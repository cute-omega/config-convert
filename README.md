# Sheas Cealer 转 Dev-Sidecar 的配置转换器

把Sheas Cealer的配置文件转换成Dev-Sidecar的配置文件，并支持与其他Dev-Sidecar配置合并。目前由GitHub Actions自动执行，当前每8小时更新一次配置。配置id为`io.github.cute-omega`。

## 用法

本仓库产出**两份配置**，按需选择其一填入dev-sidecar的个人远程配置，然后点击“更新远程配置”以立即生效。之后dev-sidecar会在每次启动时自动更新配置。

| 配置 | 地址 | 说明 |
| --- | --- | --- |
| 标准版 | <https://cute-omega.github.io/other-assets/ds-config.json> | 只使用上游配置提供的 IP |
| DNS 版 | <https://cute-omega.github.io/other-assets/ds-config-dns.json> | 额外把 `server.intercepts` 中域名经**可信 DNS** 解析得到的 IP 补进 `server.preSetIpList` |

两份配置**只有 `server.preSetIpList` 不同**，其余内容完全一致。DNS 版只**补充**缺失的条目，不会覆盖上游已提供的 IP。

> ⚠️ DNS 版必须依赖**无 DNS 污染的环境**解析，因此**默认不生成**，只在 CI 上显式传 `--dns` 时才产出。
> 被墙域名在受污染的网络上会被解析到随机假 IP，所以本地运行**不要**加 `--dns`，也不要用中国大陆网络自行重建该文件。

**注意**：即使是可信节点获取的IP，也可能被封锁，无法保证所有IP在本地都可用，使用这些IP可能增加本地验证IP可用性的访问延迟。

## 脚本当前工作流

`(manual.config + sheas_cealer.config + 8odream.config + official.config) - excluded_domains`

`manual.config`是[本仓库手动配置的收尾设置文件](https://github.com/cute-omega/config_convert/blob/main/assets/manual_config.json5)，包含一些额外的配置调整。

`sheas_cealer.config`转换自[SpaceTimee/Cealing-Host](https://github.com/SpaceTimee/Cealing-Host)

`8odream.config`来自[8odream/Dev-sidecar-8odream-config](https://github.com/8odream/Dev-sidecar-8odream-config)

`official.config`来自[Dev-Sidecar内置的默认远程配置地址](https://gitee.com/wangliang181230/dev-sidecar-config)

**注意**：示范中的加法不满足交换律，从左向右结合。左边的配置效力高于右边的。

传 `--dns` 时，脚本**在标准版之外再**产出一份 **DNS 版**：把结果深拷贝一份，用可信 DNS（`header.TRUSTED_DNS_SERVERS`，
默认 Cloudflare / Google / Quad9 及两个 DoH）并发解析 `server.intercepts` 中可解析的域名
（跳过 `*.x.com`、`^/Homebrew/.*$` 这类通配符与正则键），把得到的 IP 补进 `server.preSetIpList`。
已有的 `preSetIpList` 键**同时按正则与 glob 两种写法**参与覆盖判定，已被覆盖的域名不会重复添加。
DNS 整体不可用时只记一条警告，该份产物退化为与标准版相同的内容，不会中断构建。

标准版**始终**生成；DNS 版默认不生成 —— 只有无污染环境（CI，见「用法」中的两个地址）才应传 `--dns`。

代码已经得到优化，更方便的支持扩展其他所需合并的配置文件。

## 本地运行

尽管这看起来是显而易见的，我们仍然给出运行脚本的步骤。

```bash
git clone https://github.com/cute-omega/config_convert.git
cd config_convert
pip3 install -r requirements.txt
python3 src/main.py
```

最好用`uv sync`同步环境，`requirements.txt`未必及时更新。

### 命令行参数

| 参数 | 说明 |
| --- | --- |
| `--debug` | 输出调试日志 |
| `--xget` | 额外合并 `assets/xget_config.json5` 的 Xget 全平台加速规则（默认不启用） |
| `--dns` | **额外**生成含可信 DNS 解析 IP 的第二份配置（基础配置始终生成；仅应在无污染环境使用，见上文「用法」中的说明） |

### 类型检查

仓库自带 `pyrightconfig.json`（已指向 `.venv`，`pythonVersion` 为 3.14），在项目根目录直接运行即可，无需额外参数：

```bash
pyright         # 未全局安装可用 npx pyright；Pylance/VSCode 会自动读取该配置
```

## 开发

请Fork dev分支，更新也请向dev分支发PR。

推送PR前请在本地测试无bug后进行。

main分支仅用于生产用途。

## GitHub Actions 配置

本仓库使用GitHub Actions自动运行配置转换并推送到main分支。由于main分支有分支保护规则，工作流使用Personal Access Token (PAT)来绕过这些规则。

### 所需的Secrets配置

- `PAT`: 具有repo权限的Personal Access Token，用于向main分支推送更改
