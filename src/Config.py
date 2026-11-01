from dataclasses import InitVar, dataclass, field
from logging import Logger, getLogger

from json5 import dump, loads
from requests import get

from ExtendedDict import ExtendedDict
from header import (
    GITHUB_MIRRORS,
    JSON5Object,
    RawSheasCealerConfig,
    USER_AGENT,
    skip_IPv6,
)
from utils import (
    fix_json5_invalid_escapes,
    is_ipv6_address,
    show_raw_text_for_debugging,
    sort_json_object,
)

__all__ = [
    "GithubConfig",
    "LocalConfig",
    "MemoryConfig",
    "RemoteConfig",
    "SheasCealerConfig",
]


logger = getLogger(__name__)


def _log_json5_fixes(name: str, fixes: list[tuple[int, str]], logger: Logger):
    """把修复 JSON5 非法转义的位置写进日志，提示配置作者改用双反斜杠。"""
    for line_no, ch in fixes[:20]:
        logger.warning(
            f"{name} 配置第 {line_no} 行出现 JSON5 非法转义 '\\{ch}'"
            f"（JSON5 会吞掉反斜杠），已按字面反斜杠修复；"
            f"建议在源配置里写成 '\\\\{ch}'"
        )
    if len(fixes) > 20:
        logger.warning(f"{name} 配置另有 {len(fixes) - 20} 处同类非法转义，已一并修复")


@dataclass
class Config:
    """dev-sidecar配置类，在初始化时即尝试加载。

    Args:
        path (str): 配置路径，可以是本地路径、GitHub路径（省略协议和域名）或完整的远程URL
        name (str): 配置名称，用于日志记录

    Attributes:
        raw_config (JSON5Object, initialized during object construction): 仅序列化的原始配置数据
        config (ExtendedDict, initialized during object construction): 解析后的Dev-Sidecar配置
    """

    path: str
    name: str
    raw_config: JSON5Object = field(init=False)
    config: ExtendedDict = field(init=False)

    def __post_init__(self):
        """
        子类应重写本函数以实现加载配置，并在加载完成后调用 super().__post_init__() 以记录日志。
        Subclasses should override this method to implement configuration loading,
        and call super().__post_init__() at the end to log the loading event.
        """
        logger.info(f"Finish loading {self.name} config from {self.path}")

    def save(self, fn: str):
        sorted_config = sort_json_object(self.config)
        # 统一用 json5 序列化（JSON5 是 JSON 超集，dev-sidecar 按 JSON5 解析）。
        # 显式指定 utf-8：否则会跟随 Windows 区域编码（cp936）把中文写坏。
        with open(fn, "w", encoding="utf-8") as f:
            dump(sorted_config, f, ensure_ascii=False, indent=2)
        logger.info(f"Finish saving {self.name} config to {fn}")

    def download(self, mirrors: list[str] | None = None) -> JSON5Object:
        """从远程下载配置并反序列化为JSON5对象，会尝试所有配置的镜像

        Args:
            mirrors (list[str] | None, optional): 下载时指定的镜像域名列表，可以为空列表. Defaults to None.

        Raises:
            RuntimeError: 所有镜像下载全部失败，或内容全部不可反序列化

        Returns:
            JSON5Object: 反序列化后的JSON5对象
        """
        if mirrors is None:
            mirrors = [""]
        for mirror in mirrors:
            if mirror:
                url = f"https://{mirror}/{self.path}"
            else:
                if self.path.startswith("http"):
                    url = self.path
                else:
                    url = f"https://{self.path}"

            r = None
            try:
                logger.info(f"Trying to download {self.name} config from {url} ...")
                # 带明确 UA（裸 requests UA 可能被 CDN/WAF 拦），并区分连接/读取超时：
                # 单个 10s 对"连得上但很慢"的镜像偏紧。
                r = get(
                    url,
                    timeout=(10, 30),
                    allow_redirects=True,
                    headers={"User-Agent": USER_AGENT},
                )
                if r.status_code != 200:
                    raise ValueError(f"HTTP {r.status_code} {r.reason} for {url}")
            except Exception as e:
                logger.warning(f"Failed to download {self.name} config from {url}: {e}")
                if r is None:
                    logger.debug("Failed to receive any response.")
                else:
                    logger.debug(f"Request status: {r.status_code} {r.reason}")
                    show_raw_text_for_debugging(self.name, r.text, logger)
                continue
            else:
                config_text, fixes = fix_json5_invalid_escapes(r.text)
                _log_json5_fixes(self.name, fixes, logger)
                try:
                    result: JSON5Object = loads(config_text)
                except Exception as e:
                    logger.warning(
                        f"Failed to parse downloaded {self.name} config from {url} as JSON5: {e}"
                    )
                    show_raw_text_for_debugging(self.name, config_text, logger)
                    continue
                else:
                    logger.info(
                        f"Finish downloading latest {self.name} config from {url}"
                    )
                    return result
        raise RuntimeError(
            f"Failed to download a valid {self.name} config from all mirrors: {mirrors}"
        )  # fast fail


class SheasCealerConfig(Config):
    """
    Sheas Cealer配置，反序列化之后会自动转换。

    raw_config是原始的Sheas Cealer配置list
    """

    def __post_init__(self):
        self.raw_config: RawSheasCealerConfig = self.download(  # type: ignore  # pyright: ignore[reportIncompatibleVariableOverride, reportAttributeAccessIssue]
            GITHUB_MIRRORS
        )

        # 解析 raw_config
        self.config = self.__convert()
        logger.info("Finish converting Sheas Cealer config to Dev-Sidecar config")
        super().__post_init__()

    def __convert(self) -> ExtendedDict:
        """
        Convert the raw Sheas Cealer configuration to Dev-Sidecar format.

        Iterates over each entry in self.raw_config, extracting domain rules, SNI, and target IPs.
        - Domains are cleaned and combined into a single rule string.
        - SNI values are set for each domain rule.
        - Target IPs are added to the preSetIpList if they are not IPv6 (when skip_IPv6 is enabled).

        Returns:
            ExtendedDict: The configuration in Dev-Sidecar format, with 'server', 'intercepts', and 'preSetIpList' sections populated.
        """
        ds_config = ExtendedDict({"server": {"intercepts": {}, "preSetIpList": {}}})

        for item in self.raw_config:
            # 上游第二个字段是「SNI 覆盖」：非空时用该值，空字符串表示不发送 SNI。
            #
            # 这里刻意改写成无害字面量 "none"，而不是 Dev-Sidecar 的空字符串写法：
            # 实测发空 SNI 会让 Fastly 一类边缘返回 default.ssl.fastly.net 的默认证书，
            # 而 sni.js 的空串分支在切换到 unVerifySsl agent 之前就 return 了，
            # 于是证书校验失败（www.reddit.com 稳定 500）；写成 "none" 走常规分支，
            # 会顺带切到 unVerifySsl agent，访问正常。给规则额外加 unVerifySsl: true
            # 也无法补救。
            sni: str | None = item[1]
            if sni is None:
                continue
            elif sni == "":
                sni = "none"

            target: str = item[2]
            if target == "":
                target = "127.0.0.1"

            is_IPv6 = is_ipv6_address(target)

            raw_domains: list[str] = item[0]
            domains = [
                raw_domain.lstrip("$#")
                for raw_domain in raw_domains
                if "^" not in raw_domain
            ]

            for domain in domains:
                intercepts = ds_config["server"].setdefault("intercepts", {})
                domain_dict = intercepts.setdefault(domain, {})
                sni_dict = domain_dict.setdefault(".*", {})
                sni_dict["sni"] = sni

                if skip_IPv6 and not is_IPv6:
                    pre_set_ip_list = ds_config["server"].setdefault("preSetIpList", {})
                    pre_set_domain_dict = pre_set_ip_list.setdefault(domain, {})
                    pre_set_domain_dict[target] = True

        return ds_config


class LocalConfig(Config):
    """
    本地配置

    path应指定为本地文件路径。
    """

    def __post_init__(self):
        with open(self.path, encoding="utf-8") as f:
            text, fixes = fix_json5_invalid_escapes(f.read())
        _log_json5_fixes(self.name, fixes, logger)
        self.raw_config = loads(text)
        self.config = ExtendedDict(self.raw_config)
        super().__post_init__()


class GithubConfig(Config):
    """
    GitHub配置，下载时会自动尝试内置的GitHub镜像。

    path应为省略协议和域名的GitHub URL，如"user/repo/raw/branch/path/to/config.json5"
    """

    def __post_init__(self):
        self.raw_config: JSON5Object = self.download(GITHUB_MIRRORS)
        self.config = ExtendedDict(self.raw_config)
        super().__post_init__()


class RemoteConfig(Config):
    """普通的远程配置

    path应为完整的远程URL。
    """

    def __post_init__(self):
        self.raw_config: JSON5Object = self.download()
        self.config = ExtendedDict(self.raw_config)
        super().__post_init__()


@dataclass
class MemoryConfig(Config):
    """内存配置，直接使用传入的JSON5对象作为配置内容。

    path参数仍然保留为字符串标识；真正的配置内容通过初始化时的 raw_config 传入。
    """

    config_data: InitVar[JSON5Object]

    def __post_init__(self, config_data: JSON5Object):
        self.raw_config = config_data
        self.config = ExtendedDict(self.raw_config)
        super().__post_init__()
