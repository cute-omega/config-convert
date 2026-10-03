import argparse
import asyncio
import logging
from copy import deepcopy
from datetime import datetime, timedelta, timezone

from json5 import load

from Config import (
    GithubConfig,
    LocalConfig,
    MemoryConfig,
    RemoteConfig,
    SheasCealerConfig,
)
from header import (
    TRUSTED_DNS_SERVERS,
    dns_config_id,
    excluded_domains_path,
    final_config_dns_path,
    final_config_path,
    manual_path,
    xget_config_path,
)
from utils import resolve_pre_set_ip_list

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--xget",
        action="store_true",
        help="同时合并 assets/xget_config.json5 的 Xget 全平台加速规则（默认不启用）",
    )
    parser.add_argument(
        "--dns",
        action="store_true",
        help="额外生成含可信 DNS 解析 IP 的第二份配置（基础配置始终生成；默认不生成第二份）",
    )
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] File %(filename)s, line %(lineno)s, in %(module)s.%(funcName)s\n\t%(message)s",
    )

    # 读取 Excluded domains (Domains that should not be proxied now)
    with open(excluded_domains_path) as f:
        excluded_domains: list[str] = load(f)
    logger.info(f"Finish loading excluded_domains from {excluded_domains_path}")

    try:
        # 获取 Dev-Sidecar 内置默认远程配置
        official = RemoteConfig(
            "https://ds-official-config.bestar.de5.net/remote_config.json5",
            "Official",
        )
    except RuntimeError as e:
        logger.error(e)
        logger.warning(
            "Failed to get official config, assume it has not changed and fallback to only update my last result."
        )
        try:
            official = RemoteConfig(
                "https://cute-omega.github.io/other-assets/ds-config.json",
                "Fallback Last Result",
            )
        except RuntimeError as e:
            logger.error(e)
            logger.warning(
                "Failed to get fallback config, assume it has not changed and fallback to local file."
            )
            official = LocalConfig(final_config_path, "Local Last Result")

    # 获取 Sheas Cealer 配置，默认为空列表
    sheas_cealer = SheasCealerConfig(
        "SpaceTimee/Cealing-Host/raw/main/Cealing-Host.json", "Sheas Cealer"
    )

    # 读取 8odream 配置
    _8odream = GithubConfig(
        "8odream/Devsidecar-8odream-config/raw/main/config.json", "8odream"
    )

    # 读取 手动配置
    manual = LocalConfig(manual_path, "Manual")
    # 配置版本应是“GMT+8的开始编辑时间，固定位数为年月日+时分”（年四位，月份两位，日期两位，小时两位，分钟两位），并且是JSON意义上的number类型
    config_version = int(
        datetime.now(tz=timezone(timedelta(hours=8))).strftime("%Y%m%d%H%M")
    )
    manual.config["app"]["metaInfo"]["version"] = config_version

    # 合并配置
    final_config = (
        manual.config + sheas_cealer.config + _8odream.config + official.config
    )

    # 可选：并入 Xget 全平台加速规则（独立文件，默认不启用）
    if args.xget:
        final_config = final_config + LocalConfig(xget_config_path, "Xget").config

    # 排除域名最后处理，确保对全部来源生效
    final_config = final_config - excluded_domains
    logger.info("Finish merging all configs and clearing excluded domain rules")

    # 保存 Dev-Sidecar 配置（save() 内部会调用 sort_json_object 排序）
    MemoryConfig("Memory", "Final Sorted", final_config).save(final_config_path)

    # 第二份产物：额外并入可信 DNS 解析出的 IP。默认不生成，需显式传 --dns。
    # 之所以默认关闭：被墙域名在受污染的网络上会被解析到随机假 IP，
    # 只有无污染环境（如 GitHub Actions）才应生成这份产物。
    if not args.dns:
        logger.info("Trusted-DNS resolution disabled; only the standard config was written")
        return

    dns_config = deepcopy(final_config)
    # 两份配置必须有不同的 metaInfo.id，否则 dev-sidecar 会当成同一个配置互相覆盖
    dns_config["app"]["metaInfo"]["id"] = dns_config_id
    try:
        total, added = asyncio.run(
            resolve_pre_set_ip_list(dns_config, TRUSTED_DNS_SERVERS)
        )
        logger.info(
            f"Finish resolving {total} domains via trusted DNS, "
            f"added {added} entries to preSetIpList"
        )
    except Exception as e:
        # DNS 整体不可用时不中断构建：第二份产物退化为与第一份相同的内容
        logger.warning(f"Trusted-DNS resolution failed, DNS variant falls back: {e}")

    MemoryConfig("Memory", "Final Sorted (DNS)", dns_config).save(final_config_dns_path)


if __name__ == "__main__":
    main()
