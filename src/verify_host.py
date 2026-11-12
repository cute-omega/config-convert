"""为「改写了 SNI」的拦截规则补 verifyHost。

dev-sidecar 自 2.3.4（#745）起，`sni` 只改握手，不再隐式关闭证书校验：
上游返回的证书必须与真实域名匹配，否则报 `ERR_TLS_CERT_ALTNAME_INVALID`。
而本转换器的上游（Sheas Cealer 等）给被墙站点配的 SNI 往往是诱饵
（`baidu.com` / `g.cn` / `none`），边缘会返回自己的默认证书，按真实域名校验必然失败。

这里在生成配置时实测一遍：用规则里的 SNI 连目标 IP，读回证书，
若真实域名不在证书里，就从证书 SAN 里挑一个能通过校验、且与真实域名关系最近的名字写进
`verifyHost`。这样证书链仍然校验，只是比对对象换成上游实际签发的那张证书。

探测只在干净网络下可信（CI）。本地跑时大量目标不可达，失败的条目会保持原样并计入日志，
不会写入未经证实的 verifyHost。
"""

import asyncio
import ipaddress
import os
import re
import socket
import ssl
import tempfile
from collections.abc import Iterable, Mapping, MutableMapping
from logging import getLogger

from ExtendedDict import ExtendedDict
from header import verify_host_probe_concurrency, verify_host_probe_timeout

__all__ = ["probe_and_fill_verify_host"]

logger = getLogger(__name__)

# 只对「本身就是主机名」的拦截键做探测；glob（*github.com）与正则键无法确定具体主机
_HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$"
)


def _probe_host_for_key(key: str) -> str | None:
    """把拦截键映射成可用于探测的具体主机名。

    - 普通主机名：原样返回；
    - 单层通配键（`*github.com` / `*.github.com`）：用 `probe.<base>` 代探。
      诱饵 SNI 下边缘返回的是默认证书，与该用哪个子域无关；用不存在的子域代探，
      命中说明证书是通配的（所有子域都覆盖），不命中则挑出的名字对整个 glob 都成立。
    - 其它（正则、`*google*` 这类中间通配）：无法确定主机，返回 None。
    """
    if _HOSTNAME_RE.match(key):
        return key
    if key.startswith("*"):
        base = key.lstrip("*").lstrip(".")
        if base and "*" not in base and _HOSTNAME_RE.match(base):
            return f"probe.{base}"
    return None


def _iter_pending_rules(config: ExtendedDict) -> Iterable[tuple[str, str, str, MutableMapping]]:
    """挑出需要补 verifyHost 的规则：有 sni、没有 verifyHost/unVerifySsl、也不改写目标。

    yield (拦截键, 用于比对证书的主机名, 用于取 IP 的主机名, 规则)。
    """
    intercepts = config.get("server", {}).get("intercepts", {})
    if not isinstance(intercepts, Mapping):
        return
    for key, rules in intercepts.items():
        if not isinstance(rules, Mapping):
            continue
        probe_host = _probe_host_for_key(key)
        if probe_host is None:
            continue
        base_host = key.lstrip("*").lstrip(".") if key.startswith("*") else key
        for rule in rules.values():
            if not isinstance(rule, MutableMapping):
                continue
            if rule.get("sni") is None:
                continue
            if rule.get("verifyHost") or rule.get("unVerifySsl") is True:
                continue
            if rule.get("ssl") is False:
                continue
            # proxy 会把连接改到另一个目标，sni/verifyHost 的语义不同，不在这里处理
            if rule.get("proxy") or rule.get("abort") or rule.get("success"):
                continue
            yield key, probe_host, base_host, rule


def _preset_ips(config: ExtendedDict, host: str) -> list[str]:
    """取 preSetIpList 里该域名已有的 IP（优先 IPv4），并做合法性过滤。"""
    preset = config.get("server", {}).get("preSetIpList", {})
    if not isinstance(preset, Mapping):
        return []
    entries = preset.get(host)
    if not isinstance(entries, Mapping):
        return []

    def clean(value: str) -> str:
        value = value.strip("[]")
        return value

    ips = [clean(str(ip)) for ip in entries]
    valid = [ip for ip in ips if _is_ip(ip)]
    valid.sort(key=lambda ip: ":" in ip)  # IPv4 优先
    return valid


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _resolve_ips(host: str, timeout: float) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, 443, type=socket.AF_INET), timeout
        )
    except Exception:
        return []
    ips: list[str] = []
    for info in infos:
        ip = str(info[4][0])
        if ip not in ips:
            ips.append(ip)
    return ips


async def _fetch_der(ip: str, sni: str, timeout: float) -> bytes | None:
    """用指定 SNI 连 IP，返回证书 DER。要求证书链可校验（拒绝被劫持/自签的证书）。"""
    # create_default_context() 会加载系统 CA；直接构造 SSLContext 不带任何根证书
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=sni), timeout
        )
    except Exception:
        return None
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        return der or None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _decode_sans(der: bytes) -> list[str]:
    """从证书 DER 里取出 DNS 类型的 subjectAltName。

    用 stdlib 的 `ssl._ssl._test_decode_cert`（需要 PEM 文件路径）。
    它属于 CPython 的私有接口，但跨版本一直存在；失败时返回空列表，调用方跳过该条。
    """
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as file:
            file.write(pem)
        info = ssl._ssl._test_decode_cert(path)  # pyright: ignore[reportAttributeAccessIssue]
    except Exception:
        return []
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return [value for key, value in info.get("subjectAltName", ()) if key == "DNS"]


def _match_name(name: str, pattern: str) -> bool:
    """RFC 6125 简化版：支持单层通配符 `*.example.com`，大小写不敏感。"""
    name = name.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        remainder = pattern[2:]
        label, dot, rest = name.partition(".")
        return bool(label) and bool(dot) and rest == remainder
    return name == pattern


def _pick_verify_host(host: str, sans: list[str]) -> str | None:
    """真实域名不在证书里时，挑一个能通过校验的名字。

    优先选与真实域名同后缀（如 gist.github.com → github.com），其次任一精确 SAN；
    只有通配符时不猜（生成的名字没有语义，宁可不写）。
    """
    if any(_match_name(host, san) for san in sans):
        return None

    exact = [san for san in sans if "*" not in san]
    related = [san for san in exact if host.endswith(f".{san}")]
    if related:
        return max(related, key=len)
    if exact:
        return exact[0]
    return None


async def _probe_one(
    key: str,
    probe_host: str,
    base_host: str,
    rule: MutableMapping,
    config: ExtendedDict,
    timeout: float,
) -> tuple[str | None, str]:
    """返回 (verifyHost|None, 状态)。状态：ok / unreachable / no-probe / mismatch。"""
    sni = str(rule.get("sni"))
    ips = _preset_ips(config, key) or _preset_ips(config, base_host)
    if not ips:
        ips = await _resolve_ips(base_host, timeout)
    if not ips:
        return None, "unreachable"

    for ip in ips[:3]:
        der = await _fetch_der(ip, sni, timeout)
        if der is None:
            continue
        sans = _decode_sans(der)
        if not sans:
            return None, "no-probe"
        verify_host = _pick_verify_host(probe_host, sans)
        if verify_host is None:
            return None, "ok"
        return verify_host, "mismatch"
    return None, "unreachable"


async def probe_and_fill_verify_host(
    config: ExtendedDict,
    timeout: float = verify_host_probe_timeout,
    concurrency: int = verify_host_probe_concurrency,
) -> tuple[int, int, int, int]:
    """探测所有「有 sni、没校验策略」的规则并补 verifyHost（就地修改）。

    Returns:
        (探测数, 补写数, 无需补写数, 失败数)
    """
    pending: list[tuple[str, str, str, MutableMapping]] = list(_iter_pending_rules(config))
    if not pending:
        return 0, 0, 0, 0

    semaphore = asyncio.Semaphore(concurrency)

    async def run(key: str, probe_host: str, base_host: str, rule: MutableMapping):
        async with semaphore:
            return await _probe_one(key, probe_host, base_host, rule, config, timeout)

    results = await asyncio.gather(
        *(run(key, probe_host, base_host, rule) for key, probe_host, base_host, rule in pending)
    )

    probed = added = ok = failed = 0
    for (key, _probe_host, _base_host, rule), (verify_host, status) in zip(
        pending, results
    ):
        probed += 1
        if status == "mismatch" and verify_host:
            rule["verifyHost"] = verify_host
            logger.info(f"{key}: 证书不含真实域名，补 verifyHost={verify_host}")
            added += 1
        elif status == "ok":
            ok += 1
        else:
            failed += 1

    if failed:
        logger.warning(
            f"verifyHost 探测：{failed}/{probed} 条未能确认（不可达或证书异常），保持原样"
        )
    return probed, added, ok, failed



