# secretscan 🔑

密钥格式识别与轮换治理 CLI —— **仓库里的密钥一眼认出是哪个服务的，还告诉你要不要轮换。**

扫描项目/仓库/环境变量/git 历史中的 20+ 云与服务密钥（AWS / Azure / GCP / OpenAI / GitHub / Slack / Stripe / Twilio / SendGrid / Telegram / Discord…），
识别格式与平台、判断格式合法性与误报、按类型与年龄做风险评分，最后输出**待轮换清单**（CSV）与 **HTML 看板**，配合 secretguard 类工具做治理闭环。

## 为什么做

- 各类服务密钥格式各不相同（前缀 / 长度 / 字符集 / 校验位），人工分辨费劲，轮换管理混乱。
- gitleaks / trufflehog 聚焦"扫描泄漏"，不聚焦"格式识别 + 轮换治理"。
- 需求真实（安全 / 治理 / 合规），格式库 + 校验 + 报告即可落地。

## 能力总览

| 模块 | 说明 |
|---|---|
| 识别库 | 内置 **31 种**服务密钥格式（前缀/长度/字符集/上下文锚定），支持 TOML 自定义格式 |
| 扫描 | 文件（递归、.gitignore 感知、二进制/超大文件跳过）/ 环境变量 / git 历史 |
| 校验 | 格式内核对齐 + 误报过滤（占位符、文档示例、白名单正则、忽略路径） |
| 风险 | 按类型（支付/云/AI/IM…）权重 + 年龄（文件 mtime / git 提交日期，未知标"未知"）+ 位置敏感度评分 0-10 |
| 轮换 | 建议动作：立即轮换 / 计划轮换 / 校验确认 / 历史清理，附每家服务官方轮换入口 |
| 报告 | CLI 彩色表格 + JSON + CSV（Excel 友好，含 BOM）+ 独立 HTML 看板（可搜索/筛选） |

## 快速开始

```bash
cargo build --release

# 扫描当前目录
./target/release/secretscan .

# 扫描并生成全部报告（JSON + CSV + HTML 看板）到 report/
./target/release/secretscan --format all -o report .

# 扫文件 + 环境变量 + git 历史，超详细输出
./target/release/secretscan --env --git -v .

# 只列出内置识别格式
./target/release/secretscan --list-formats
```

> 扫描到**严重/高危**密钥时退出码为 `1`（可加 `--exit-zero` 关闭），可直接挂进 CI 做密钥门禁。

## 演示

演示夹具（随机伪造的密钥）由脚本在本地生成，**不入库**——避免任何"长得像真密钥"的内容进入版本库：

```bash
bash scripts/make-demo.sh        # Windows: pwsh scripts/make-demo.ps1
./target/release/secretscan --format all -o secretscan-report demo
```

产出：
- `secretscan-report/dashboard.html` — 独立看板，打开即用
- `secretscan-report/rotation-plan.csv` — 给团队/工单系统的轮换清单
- `secretscan-report/secretscan-report.json` — 机器可读

## 内置格式（31 种）

云厂商：AWS Access Key / AWS Secret Key / AWS MWS Token、Google API Key / GCP OAuth Client ID / Google 服务账号私钥、
Azure 存储密钥 / Azure AD Client Secret、阿里云 AccessKey、腾讯云 SecretId、DigitalOcean PAT

AI：OpenAI API Key（sk-proj / 旧格式）、Anthropic API Key

代码/CICD：GitHub PAT（经典 + 细粒度）、npm token、PyPI token

IM/通讯：Slack xox token / Slack Webhook、Telegram Bot Token、Discord Bot Token、Facebook Access Token、Twilio SID / API Key

邮件：SendGrid、Mailchimp

支付：Stripe Secret / Restricted / Webhook Secret、Square、PayPal、Shopify

## 自定义格式

```bash
./target/release/secretscan --config secretscan.example.toml .
```

```toml
[settings]
allowlist = ["^AKIAIOSFODNN7EXAMPLE$"]
ignore_paths = ["vendor/"]

[[custom_formats]]
id = "internal_platform_token"
name = "内部平台 Token"
category = "cloud"            # cloud | ai | im | email | payment | cicd | other
pattern = "(?i)(?:internal_platform_token)\\s*[=:]\\s*(?P<value>[A-Za-z0-9]{20,})"
weight = 7
rotate_hint = "联系 SRE 平台组轮换"
```

正则可用 `(?P<value>...)` 命名捕获组精确提取密钥值（推荐），不写则取整个匹配。

## 误报过滤策略

1. 值含 `example / xxxx / your_ / changeme / 全同字符` → 判占位符
2. 文档/示例路径（`.md`、`docs/`、`sample/`…）且上下文或值带示例特征 → 判演示密钥
3. 格式内核对齐（AWS 20 位、Telegram bot-id 位数、Discord 三段点号…）
4. `--allow` 白名单正则 / `--ignore-path` 忽略路径
5. `-v` 可查看每条被过滤记录的原因

## 风险评分模型（0-10）

| 因素 | 调整 |
|---|---|
| 基础权重 | 支付 10 · 云厂商 9 · AI 8 · CICD 7 · IM/邮件 6 |
| 位于 `.env` / `.log` | +2 |
| 位于文档/示例路径 | −3 |
| git 历史中 | +1（建议清理历史） |
| 存在 ≥180 天 / ≥90 天 | +2 / +1（未知标"未知"） |

**等级**：严重 8-10（立即轮换）· 高 6-7（尽快轮换）· 中 4-5（计划轮换）· 低 0-3（校验确认）

## 目录结构

```
secretscan/
├─ src/
│  ├─ main.rs          # CLI 入口 / 编排 / 配置加载
│  ├─ lib.rs           # 库入口
│  ├─ formats.rs       # 识别库（31 内置 + 自定义解析）
│  ├─ scan.rs          # 文件 / env / git 历史扫描
│  ├─ validate.rs      # 校验 + 误报过滤
│  ├─ risk.rs          # 类型 / 年龄评分
│  ├─ rotate.rs        # 轮换清单 + CSV
│  └─ report.rs        # CLI 表格 + HTML 看板 + JSON
├─ tests/              # 集成 + 端到端测试
├─ scripts/            # make-demo 演示夹具生成脚本
├─ secretscan.example.toml
└─ Cargo.toml
```

## Roadmap

- [x] M1 识别库(31 种) + 扫描 + 校验 + CLI
- [x] M2 风险 / 轮换清单 + 自定义格式
- [x] M3 HTML 看板 + JSON 报告
- [ ] 密钥年龄推断（git blame / 文件内容时间戳）
- [ ] 误报率统计与 `secretscanignore` 全局忽略文件
- [ ] 对接 secretguard(74) 治理闭环

## 与竞品对比

| 工具 | 定位 | secretscan 差异 |
|---|---|---|
| gitleaks | 泄漏扫描 | 格式识别 + 轮换治理 + 看板 |
| trufflehog | 历史扫描 | 治理清单 + 风险评分 |
| secretguard(74) | 通用扫描 | 类型识别 + 轮换建议 |

## 开发

```bash
cargo test          # 单元 + 集成 + e2e 测试
cargo clippy        # lint
cargo build --release
```

## License

MIT
