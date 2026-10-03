import asyncio
import re
import ssl
from collections.abc import Mapping, Sequence
from fnmatch import fnmatchcase
from ipaddress import ip_address
from logging import Logger
from urllib.parse import urlparse

import aiohttp
import dns.asyncresolver
import dns.exception
import dns.message
import dns.rdatatype

from ExtendedDict import ExtendedDict
from header import JSON5Object, JSONValue, dns_query_timeout, skip_IPv6

__all__ = [
    "collect_resolvable_domains",
    "is_ipv6_address",
    "query_dns_records_async",
    "resolve_pre_set_ip_list",
    "show_raw_text_for_debugging",
    "sort_json_object",
]


def is_ipv6_address(target: str) -> bool:
    # 处理形如 [240e::] 的格式
    if target.startswith("[") and target.endswith("]"):
        addr = target.strip("[]")
        try:
            return ip_address(addr).version == 6
        except ValueError:
            return False
    return False


def show_raw_text_for_debugging(name: str, msg: str, logger: Logger):
    logger.debug(f"{name} raw config text (truncated to 500 chars):")
    logger.debug(f"{msg[:500]}{'...(truncated)' if len(msg) > 500 else ''}")


async def query_dns_records_async(
    domain: str,
    record_type: str,
    nameserver: str,
    port: int | None = None,
    timeout: float = 5.0,
) -> list[str]:
    """使用指定 DNS 服务器异步查询指定类型的所有记录。"""

    record_rdatatype = dns.rdatatype.from_text(record_type)

    # 解析 nameserver（支持 URL 或 host[:port]），并根据协议前缀自动识别传输类型。
    parsed = urlparse(nameserver) if "://" in nameserver else None

    parsed_port = None
    host_for_connect = nameserver
    if parsed and parsed.scheme:
        if parsed.hostname:
            host_for_connect = parsed.hostname
        parsed_port = parsed.port
        scheme = parsed.scheme.lower()
    else:
        scheme = ""
        # 处理 host:port 和 [ipv6]:port
        h = nameserver
        if h.startswith("["):
            # [ipv6]:port or [ipv6]
            if "]" in h:
                end = h.find("]")
                host_for_connect = h[: end + 1]
                rest = h[end + 1 :]
                if rest.startswith(":"):
                    try:
                        parsed_port = int(rest[1:])
                    except Exception:
                        parsed_port = None
        else:
            if ":" in h and h.count(":") == 1:
                # host:port
                try:
                    host_part, port_part = h.rsplit(":", 1)
                    parsed_port = int(port_part)
                    host_for_connect = host_part
                except Exception:
                    host_for_connect = nameserver

    # 根据 nameserver 的协议前缀判断：
    # - https/http -> DoH（端口默认 443）
    # - tls -> DoT（端口默认 853）
    # - tcp -> 使用 TCP（端口默认 53）
    # - 无协议前缀 -> 默认 UDP（端口默认 53）
    if scheme in ("https", "http"):
        default_port = 443
        mode = "doh"
    elif scheme == "tls":
        default_port = 853
        mode = "dot"
    elif scheme == "tcp":
        default_port = 53
        mode = "tcp"
    else:
        default_port = 53
        mode = "udp"

    final_port = (
        port
        if port is not None
        else (parsed_port if parsed_port is not None else default_port)
    )

    # DoH 条件：显式 https/http URL
    if scheme in ("https", "http"):
        # DNS over HTTPS (DoH) - nameserver must be a full URL
        try:
            query = dns.message.make_query(domain, record_type)
            data = query.to_wire()
            headers = {"content-type": "application/dns-message"}
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with (
                aiohttp.ClientSession(timeout=timeout_obj) as sess,
                sess.post(nameserver, data=data, headers=headers) as resp,
            ):
                if resp.status != 200:
                    raise RuntimeError(
                        f"DoH request failed: {resp.status} {resp.reason}"
                    )
                resp_bytes = await resp.read()
            msg = dns.message.from_wire(resp_bytes)
        except aiohttp.ClientError as exc:
            raise RuntimeError(f"DoH request error: {exc}") from exc

    elif scheme == "tls" or final_port == 853:
        # DNS over TLS (DoT)
        host = host_for_connect
        ssl_ctx = ssl.create_default_context()

        # 建立 TLS 连接并发送 length-prefixed DNS over TCP
        reader, writer = await asyncio.open_connection(host, final_port, ssl=ssl_ctx)
        try:
            query = dns.message.make_query(domain, record_type)
            wire = query.to_wire()
            writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()

            # 读取两字节长度
            len_bytes = await reader.readexactly(2)
            resp_len = int.from_bytes(len_bytes, "big")
            resp_bytes = await reader.readexactly(resp_len)
            msg = dns.message.from_wire(resp_bytes)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    else:
        # 默认使用系统 UDP/TCP 解析（通过 dnspython 的 asyncresolver）
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = [host_for_connect]
        resolver.port = final_port
        resolver.timeout = timeout
        resolver.lifetime = timeout
        use_tcp = mode == "tcp"
        try:
            answer = await resolver.resolve(
                domain,
                record_type,
                tcp=use_tcp,
                lifetime=timeout,
            )
        except dns.exception.Timeout as exc:
            raise TimeoutError(
                f"DNS query timed out for {domain} {record_type} via {host_for_connect}:{final_port}"
            ) from exc

        return [r.to_text() for r in answer]

    # 从 dns.message 中抽取记录文本
    results: list[str] = []
    for rrset in getattr(msg, "answer", []):
        if rrset.rdtype == record_rdatatype:
            for rr in rrset:
                results.append(rr.to_text())
    return results


# 可作为 DNS 查询目标的主机名（排除通配符、正则规则等非域名键）
_HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$"
)


def collect_resolvable_domains(config: ExtendedDict) -> list[str]:
    """挑出 server.intercepts 里能直接做 DNS 查询的域名键。

    跳过通配符（*.x.com）与正则规则（^/Homebrew/.*$、^.*(a|b)$）等非主机名键。
    """
    intercepts = config.get("server", {}).get("intercepts", {})
    return sorted(key for key in intercepts if _HOSTNAME_RE.match(key))


def _matches_pattern(domain: str, pattern: str) -> bool:
    """判断域名是否被某个 preSetIpList 键覆盖。

    上游配置里的键写法不统一：既有合法正则（^.*(youtube.com|...)$），
    也有 glob（*facebook.com、*.w.wiki —— 这些用 re 编译会抛错）。所以两种都试。
    """
    try:
        if re.search(pattern, domain):
            return True
    except re.error:
        pass
    return fnmatchcase(domain, pattern)


async def resolve_pre_set_ip_list(
    config: ExtendedDict,
    nameservers: Sequence[str],
    timeout: float = dns_query_timeout,
) -> tuple[int, int]:
    """用可信 DNS 并发解析 config 中 server.intercepts 的域名，把 IP 补进 server.preSetIpList。

    - 只补缺：preSetIpList 中**已被现有键覆盖**的域名一律不动。覆盖判定同时支持正则与 glob
      两种写法（上游两种混用），因此不会和已有的正则规则打架。
    - skip_IPv6 为真时只查 A 记录，否则同时查 A 与 AAAA。
    - 各可信 DNS 的查询结果取并集去重；单个查询失败只跳过该条，不影响其它域名。
      可信 DNS 选的是国外大厂，在 GitHub Actions 节点上不存在污染。

    Returns:
        tuple[int, int]: (尝试解析的域名数, 实际写入 preSetIpList 的域名数)
    """
    domains = collect_resolvable_domains(config)
    if not domains or not nameservers:
        return len(domains), 0

    record_types = ["A"] if skip_IPv6 else ["A", "AAAA"]

    async def query(domain: str, record_type: str, nameserver: str) -> tuple[str, list[str]]:
        try:
            records = await query_dns_records_async(
                domain, record_type, nameserver, timeout=timeout
            )
        except Exception:  # 单个 DNS 不可用不应中断整体
            records = []
        return domain, records

    results = await asyncio.gather(
        *(
            query(domain, record_type, nameserver)
            for domain in domains
            for record_type in record_types
            for nameserver in nameservers
        )
    )

    resolved: dict[str, list[str]] = {}
    for domain, records in results:
        bucket = resolved.setdefault(domain, [])
        for ip in records:
            if ip not in bucket:
                bucket.append(ip)

    pre_set_ip_list = config.setdefault("server", {}).setdefault("preSetIpList", {})
    existing_keys = list(pre_set_ip_list)  # 快照：新增的键不参与后续判定
    added = 0
    for domain, ips in resolved.items():
        if not ips:
            continue
        if any(_matches_pattern(domain, key) for key in existing_keys):
            continue  # 只补缺：已被现有键（含正则/glob）覆盖
        pre_set_ip_list[domain] = dict.fromkeys(ips, True)
        added += 1
    return len(domains), added


def sort_json_object(obj: JSON5Object) -> JSONValue:
    """递归排序 Mapping 的键：按 key 长度降序，长度相同按字典序升序。

    接受 ExtendedDict / dict / list / 标量；返回值类型为 JSONValue，即
    纯 JSON 容器（dict / list / 标量），不含 ExtendedDict，可直接交给 json.dump 序列化。
    """

    if isinstance(obj, Mapping):

        def sort_key(item):
            k = item[0]
            k_str = k if isinstance(k, str) else str(k)
            return (-len(k_str), k_str)

        sorted_items = sorted(obj.items(), key=sort_key)
        return {k: sort_json_object(v) for k, v in sorted_items}

    if isinstance(obj, list):
        return [sort_json_object(item) for item in obj]

    return obj
