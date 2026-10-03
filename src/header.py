from os.path import abspath, dirname, join

from ExtendedDict import ExtendedDict

__all__ = [
    "GITHUB_MIRRORS",
    "GITHUB_USER_CONTENT_MIRRORS",
    "JSON5Object",
    "JSONValue",
    "RawSheasCealerConfig",
    "TRUSTED_DNS_SERVERS",
    "dns_config_id",
    "dns_query_timeout",
    "excluded_domains_path",
    "final_config_dns_path",
    "final_config_path",
    "manual_path",
    "skip_IPv6",
    "xget_config_path",
]

# RawSheasCealerConfig is a list of tuples, where each tuple contains:
#   - list[str]: A list of domain names or patterns to match.
#   - str | None: An optional string representing a redirect target or configuration value (can be None).
#   - str: A string representing a comment, description, or additional metadata.
type RawSheasCealerConfig = list[tuple[list[str], str | None, str]]
# 纯 JSON 值：只含 dict / list / 标量，可被 json.dump 直接序列化
type JSONValue = (
    dict[str, JSONValue] | list[JSONValue] | str | int | float | bool | None
)
# JSON5 解析结果：纯 JSON 值，或项目自定义的 ExtendedDict（UserDict 子类，不可直接序列化）
type JSON5Object = JSONValue | ExtendedDict

GITHUB_MIRRORS = [
    "github.com",
    "ghfast.top/https://github.com",
    "xget.xi-xu.me/gh",
]

# 在重定向不可用时备用
GITHUB_USER_CONTENT_MIRRORS = [
    "raw.githubusercontent.com",
    "ghproxy.net/https://raw.githubusercontent.com",
]

# Flag to control whether IPv6 addresses should be skipped during network operations.
# Set to True to avoid using IPv6 (e.g., if IPv6 connectivity is unreliable or undesired).
# Set to False to allow both IPv4 and IPv6 addresses.
skip_IPv6 = True

# 可信 DNS 服务器，用于解析 preSetIpList 的真实 IP。
# 选国外大厂：GitHub Actions 节点上不存在污染，本地跑不通时会自动降级（见 main.py）。
# 支持 query_dns_records_async 的全部写法："host"、"host:port"、"tls://host"、"https://host/path"。
TRUSTED_DNS_SERVERS = [
    "1.1.1.1",  # Cloudflare
    "8.8.8.8",  # Google
    "9.9.9.9",  # Quad9
    "https://cloudflare-dns.com/dns-query",  # DoH 兜底
    "https://dns.google/dns-query",  # DoH 兜底
]

# 单次 DNS 查询超时（秒）
dns_query_timeout = 5.0

# DNS 版产物的 metaInfo.id。必须与标准版（assets/manual_config.json5 里的 io.github.cute-omega）
# 不同，否则 dev-sidecar 会把两份配置当成同一个而互相覆盖。
dns_config_id = "io.github.cute-omega.dns"

excluded_domains_path = abspath(
    join(dirname(__file__), "..", "assets", "excluded_domains.json5")
)

manual_path = abspath(join(dirname(__file__), "..", "assets", "manual_config.json5"))

final_config_path = abspath(
    join(dirname(__file__), "..", "assets", "final_config.json")
)

# 第二份产物：额外并入「通过可信 DNS 解析得到的 IP」（preSetIpList），供用户自行选择是否使用。
final_config_dns_path = abspath(
    join(dirname(__file__), "..", "assets", "final_config_dns.json")
)

# Xget 全平台加速规则（独立文件）。默认不参与构建，仅在 main.py 传入 --xget 时合并。
xget_config_path = abspath(join(dirname(__file__), "..", "assets", "xget_config.json5"))
