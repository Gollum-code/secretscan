//! 识别库：内置 20+ 云/服务密钥格式，支持自定义格式扩展。
//!
//! 每个格式统一定义：id / 名称 / 分类 / 正则 / 示例 / 权重 / 轮换提示。
//! 正则中可使用命名捕获组 `(?P<value>...)` 精确提取密钥值（不含上下文），
//! 未定义时默认取整个匹配。

use regex::Regex;
use serde::Deserialize;

/// 平台分类，决定基础风险权重。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// 云厂商凭证/密钥
    Cloud,
    /// AI 服务（OpenAI / Anthropic / Google AI）
    Ai,
    /// 即时通讯（Slack / Telegram / Discord / Twilio）
    Im,
    /// 邮件服务（SendGrid / Mailchimp）
    Email,
    /// 支付（Stripe / Square / PayPal / Shopify）
    Payment,
    /// 代码托管与 CICD（GitHub / npm / PyPI）
    Cicd,
    /// 其它
    Other,
}

impl Category {
    pub fn label(&self) -> &'static str {
        match self {
            Category::Cloud => "云厂商",
            Category::Ai => "AI服务",
            Category::Im => "IM/通讯",
            Category::Email => "邮件",
            Category::Payment => "支付",
            Category::Cicd => "代码/CICD",
            Category::Other => "其它",
        }
    }

    /// 未显式指定权重时的缺省权重（0-10）
    pub fn default_weight(&self) -> u8 {
        match self {
            Category::Payment => 9,
            Category::Cloud => 8,
            Category::Ai => 7,
            Category::Cicd => 6,
            Category::Email => 5,
            Category::Im => 5,
            Category::Other => 3,
        }
    }
}

/// 源码内置用的格式定义（静态字符串，构建时克隆为所有权形式）
struct FormatDef {
    id: &'static str,
    name: &'static str,
    category: Category,
    pattern: &'static str,
    example: &'static str,
    rotate_hint: &'static str,
    weight: u8,
}

/// 运行时格式：所有权形式
#[derive(Debug, Clone)]
pub struct Format {
    pub id: String,
    pub name: String,
    pub category: Category,
    pub pattern: String,
    pub example: String,
    pub rotate_hint: String,
    pub weight: u8,
}

/// 配置文件中的自定义格式
#[derive(Debug, Clone, Deserialize)]
pub struct CustomFormat {
    pub id: String,
    pub name: Option<String>,
    pub category: Option<Category>,
    pub pattern: String,
    pub example: Option<String>,
    pub rotate_hint: Option<String>,
    pub weight: Option<u8>,
}

impl Format {
    pub fn from_custom(c: &CustomFormat) -> Result<Format, String> {
        // 先校验正则合法
        Regex::new(&c.pattern)
            .map_err(|e| format!("自定义格式 '{}' 的正则无效: {}", c.id, e))?;
        let category = c.category.unwrap_or(Category::Other);
        Ok(Format {
            id: c.id.clone(),
            name: c.name.clone().unwrap_or_else(|| c.id.clone()),
            category,
            pattern: c.pattern.clone(),
            example: c.example.clone().unwrap_or_default(),
            rotate_hint: c.rotate_hint.clone().unwrap_or_default(),
            weight: c.weight.unwrap_or_else(|| category.default_weight()),
        })
    }
}

use std::sync::OnceLock;
static BUILTIN: OnceLock<Vec<Format>> = OnceLock::new();

/// 内置格式库（31 种，覆盖云厂商 / AI / IM / 支付 / 邮件 / CICD）
pub fn builtin_formats() -> &'static Vec<Format> {
    BUILTIN.get_or_init(|| {
        let defs: Vec<FormatDef> = vec![
            // ============ 云厂商 ============
            FormatDef {
                id: "aws_access_key_id",
                name: "AWS Access Key ID",
                category: Category::Cloud,
                pattern: r"\b(?P<value>(A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Za-z0-9]{16})\b",
                example: "AKIAIOSFODNN7EXAMPLE",
                rotate_hint: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html (IAM → 安全凭证 → 创建访问密钥)",
                weight: 9,
            },
            FormatDef {
                id: "aws_secret_access_key",
                name: "AWS Secret Access Key",
                category: Category::Cloud,
                pattern: r"(?i)\b(aws_?secret_?access_?key)\s*[=:]\s*(?P<value>[A-Za-z0-9/+=]{40})\b",
                example: "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                rotate_hint: "同上：轮换后同时对 IAM 下所有使用该密钥的服务同步更新",
                weight: 9,
            },
            FormatDef {
                id: "aws_mws_token",
                name: "AWS MWS 授权 Token",
                category: Category::Cloud,
                pattern: r"\b(?P<value>amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
                example: "amzn.mws.00000000-0000-0000-0000-000000000000",
                rotate_hint: "卖家中心 → 设置 → 授权 → 删除旧 Token 后重新授权",
                weight: 8,
            },
            FormatDef {
                id: "gcp_api_key",
                name: "Google API Key",
                category: Category::Cloud,
                pattern: r"\b(?P<value>AIza[0-9A-Za-z\-_]{35})\b",
                example: concat!("AIza", "SyA1234567890abcdefghijklmnopqrstuv"),
                rotate_hint: "https://console.cloud.google.com/apis/credentials → 限制/轮换该 Key",
                weight: 8,
            },
            FormatDef {
                id: "gcp_oauth_client_id",
                name: "GCP OAuth Client ID",
                category: Category::Cloud,
                pattern: r"\b(?P<value>[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b",
                example: concat!("1234567890-", "abcdefghijklmnopqrstuvwxyzABCDEF.apps.googleusercontent.com"),
                rotate_hint: "https://console.cloud.google.com/apis/credentials → OAuth 客户端",
                weight: 7,
            },
            FormatDef {
                id: "gcp_service_account_key",
                name: "Google 服务账号私钥 (JSON)",
                category: Category::Cloud,
                pattern: r"(?s)(?P<value>-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)",
                example: "-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----",
                rotate_hint: "https://console.cloud.google.com/iam-admin/serviceaccounts → 密钥 → 删除后重建",
                weight: 9,
            },
            FormatDef {
                id: "azure_storage_account_key",
                name: "Azure 存储账号密钥",
                category: Category::Cloud,
                pattern: r"(?i)(?:accountkey|storageaccount)[^\r\n]{0,60}[=:]\s*(?P<value>[A-Za-z0-9+/=]{70,110})",
                example: concat!("AccountKey=", "eW8xK3BvSlJ6dU5xZmVDSQABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=="),
                rotate_hint: "https://portal.azure.com → 存储账户 → 访问密钥（主/次轮流换）",
                weight: 9,
            },
            FormatDef {
                id: "azure_client_secret",
                name: "Azure AD 客户端密钥",
                category: Category::Cloud,
                pattern: r"(?i)(?:azure_?client_?secret|client_?secret)[^\r\n]{0,60}[=:]\s*(?P<value>[A-Za-z0-9_~\.\-]{34,80})",
                example: concat!("AZURE_CLIENT_SECRET=", "q7z~AdM4sKpX9vAbCdEfGhIjKlMnOpQrStUvWxYz12"),
                rotate_hint: "https://portal.azure.com → Microsoft Entra ID → 应用注册 → 证书与密码 → 新建客户端密码",
                weight: 9,
            },
            FormatDef {
                id: "aliyun_access_key_id",
                name: "阿里云 AccessKey ID",
                category: Category::Cloud,
                pattern: r"\b(?P<value>LTAI[0-9A-Za-z]{20})\b",
                example: concat!("LTAI", "0123456789abcdefghij"),
                rotate_hint: "https://ram.console.aliyun.com/manage/ak → 禁用/删除后重建",
                weight: 9,
            },
            FormatDef {
                id: "tencent_secret_id",
                name: "腾讯云 SecretId",
                category: Category::Cloud,
                pattern: r"\b(?P<value>AKID[0-9A-Za-z]{11,20})\b",
                example: "AKIDxxxxxxxxxxxxxxxxxxxx",
                rotate_hint: "https://console.cloud.tencent.com/cam/capi → API 密钥管理 → 轮换",
                weight: 9,
            },
            FormatDef {
                id: "digitalocean_pat",
                name: "DigitalOcean PAT",
                category: Category::Cloud,
                pattern: r"\b(?P<value>dop_v1_[0-9a-f]{64})\b",
                example: concat!("dop_v1_", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
                rotate_hint: "https://cloud.digitalocean.com/account/api/tokens → 删除后重建",
                weight: 8,
            },
            // ============ AI 服务 ============
            FormatDef {
                id: "openai_api_key",
                name: "OpenAI API Key",
                category: Category::Ai,
                pattern: r"\b(?P<value>sk-proj-[0-9A-Za-z\-_]{20,200}|sk-[0-9A-Za-z]{20}T3BlbkFJ[0-9A-Za-z]{20}|sk-[0-9A-Za-z]{32,48})\b",
                example: concat!("sk-proj-", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"),
                rotate_hint: "https://platform.openai.com/api-keys → 撤销后重建（sk-proj 后缀 '…-xxx' 为项目关联）",
                weight: 8,
            },
            FormatDef {
                id: "anthropic_api_key",
                name: "Anthropic API Key",
                category: Category::Ai,
                pattern: r"\b(?P<value>sk-ant-(?:api[0-9]{2}|apik)-[0-9A-Za-z\-_]{40,130})\b",
                example: concat!("sk-ant-api03-", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST"),
                rotate_hint: "https://console.anthropic.com/settings/keys → 创建/撤销",
                weight: 8,
            },
            // ============ 代码/CICD ============
            FormatDef {
                id: "github_pat",
                name: "GitHub Token/PAT",
                category: Category::Cicd,
                pattern: r"\b(?P<value>github_pat_[0-9A-Za-z_]{22}_[0-9A-Za-z_]{59}|ghp_[0-9A-Za-z]{36}|gho_[0-9A-Za-z]{36}|ghu_[0-9A-Za-z]{36}|ghs_[0-9A-Za-z]{36}|ghr_[0-9A-Za-z]{36})\b",
                example: concat!("ghp_", "abcdefghijklmnopqrstuvwxyzABCDEFGH12"),
                rotate_hint: "https://github.com/settings/tokens → 吊销后重建（了解权限最小化授权）",
                weight: 8,
            },
            FormatDef {
                id: "npm_token",
                name: "npm 访问令牌",
                category: Category::Cicd,
                pattern: r"\b(?P<value>npm_[0-9A-Za-z]{36})\b",
                example: concat!("npm_", "abcdEFGHijklMNOPqrstUVWXyz1234567890"),
                rotate_hint: "https://www.npmjs.com/settings/<user>/tokens → 删除后重建",
                weight: 7,
            },
            FormatDef {
                id: "pypi_token",
                name: "PyPI API Token",
                category: Category::Cicd,
                pattern: r"\b(?P<value>pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_\-]{30,})\b",
                example: concat!("pypi-AgEIcHlwaS5vcmc", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"),
                rotate_hint: "https://pypi.org/manage/account/token/ → 删除后重建",
                weight: 7,
            },
            // ============ IM / 通讯 ============
            FormatDef {
                id: "slack_bot_token",
                name: "Slack Token (xox)",
                category: Category::Im,
                pattern: r"\b(?P<value>xox[baprs]-[0-9A-Za-z\-]{10,80})\b",
                example: concat!("xoxb-", "123456789012-1234567890123-abcdefghijklmnopqrstuvwx"),
                rotate_hint: "https://api.slack.com/apps → 你创建的 App → OAuth & Permissions → 重新生成",
                weight: 6,
            },
            FormatDef {
                id: "slack_webhook_url",
                name: "Slack 传入 Webhook",
                category: Category::Im,
                pattern: r"https://hooks\.slack\.com/services/T[0-9A-Z]{4,12}/B[0-9A-Z]{4,12}/[0-9A-Za-z\-]{20,60}",
                example: "https://hooks.slack.com/services/T000000/B000000/XXXXXXXXXXXXXXXXXXXXXXXX",
                rotate_hint: "https://api.slack.com/apps → Incoming Webhooks → 撤销该 Webhook URL",
                weight: 6,
            },
            FormatDef {
                id: "telegram_bot_token",
                name: "Telegram Bot Token",
                category: Category::Im,
                pattern: r"\b(?P<value>[0-9]{8,10}:[0-9A-Za-z_-]{35})\b",
                example: concat!("9876543210:", "abcdefghijklmnopqrstuvwxyz123456789"),
                rotate_hint: "@BotFather → /revoke → 生成新 Token",
                weight: 6,
            },
            FormatDef {
                id: "discord_bot_token",
                name: "Discord Bot Token",
                category: Category::Im,
                pattern: r"\b(?P<value>[MNO][a-zA-Z0-9_\-]{23,25}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27,38})\b",
                example: concat!("M", "aaaaaaaaaaaaaaaaaaaaaaa.bbbbbb.cccccccccccccccccccccccccccccccccc"),
                rotate_hint: "https://discord.com/developers/applications → Bot → Reset Token（旧 token 立即失效）",
                weight: 6,
            },
            FormatDef {
                id: "facebook_access_token",
                name: "Facebook Access Token",
                category: Category::Im,
                pattern: r"\b(?P<value>EAACEdEose0cBA[0-9A-Za-z]+|EAAGm0PX[0-9A-Za-z]+)\b",
                example: concat!("EAACEdEose0cBA", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"),
                rotate_hint: "https://developers.facebook.com/tools/accesstoken/ → 删除后重新授权",
                weight: 6,
            },
            FormatDef {
                id: "twilio_sid",
                name: "Twilio Account SID",
                category: Category::Im,
                pattern: r"\b(?P<value>AC[0-9a-f]{32})\b",
                example: concat!("AC", "abcdef0123456789abcdef0123456789"),
                rotate_hint: "https://console.twilio.com → 设置 → 凭证（与 Auth Token 成对轮换）",
                weight: 7,
            },
            FormatDef {
                id: "twilio_api_key",
                name: "Twilio API Key (SK)",
                category: Category::Im,
                pattern: r"\b(?P<value>SK[0-9a-f]{32})\b",
                example: concat!("SK", "abcdef0123456789abcdef0123456789"),
                rotate_hint: "https://console.twilio.com/iam/keys → API 密钥 → 停用后重建",
                weight: 7,
            },
            // ============ 邮件 ============
            FormatDef {
                id: "sendgrid_api_key",
                name: "SendGrid API Key",
                category: Category::Email,
                pattern: r"\b(?P<value>SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})\b",
                example: concat!("SG.", "0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyz0123456"),
                rotate_hint: "https://app.sendgrid.com/settings/api_keys → 删除后重建",
                weight: 7,
            },
            FormatDef {
                id: "mailchimp_api_key",
                name: "Mailchimp API Key",
                category: Category::Email,
                pattern: r"\b(?P<value>[0-9a-f]{32}-us[0-9]{1,2})\b",
                example: concat!("abcdef0123456789", "abcdef0123456789-us20"),
                rotate_hint: "https://us<NN>.admin.mailchimp.com/account/api-key/ → 丢弃旧 Key",
                weight: 6,
            },
            // ============ 支付 ============
            FormatDef {
                id: "stripe_secret_key",
                name: "Stripe Secret Key",
                category: Category::Payment,
                pattern: r"\b(?P<value>sk_live_[0-9A-Za-z]{24})\b",
                example: concat!("sk_live_", "0123456789abcdefghijklmn"),
                rotate_hint: "https://dashboard.stripe.com/apikeys → 轮换（先切环境再撤旧的）",
                weight: 10,
            },
            FormatDef {
                id: "stripe_restricted_key",
                name: "Stripe Restricted Key",
                category: Category::Payment,
                pattern: r"\b(?P<value>rk_live_[0-9A-Za-z]{24})\b",
                example: concat!("rk_live_", "0123456789abcdefghijklmn"),
                rotate_hint: "https://dashboard.stripe.com/apikeys → 受限密钥，收紧权限或删除",
                weight: 9,
            },
            FormatDef {
                id: "stripe_webhook_secret",
                name: "Stripe Webhook Secret",
                category: Category::Payment,
                pattern: r"\b(?P<value>whsec_[0-9A-Za-z]{16,40})\b",
                example: concat!("whsec_", "0123456789abcdefghijklmnopqrstuvwx"),
                rotate_hint: "https://dashboard.stripe.com/webhooks → 轮换签名密钥",
                weight: 8,
            },
            FormatDef {
                id: "square_access_token",
                name: "Square 访问令牌",
                category: Category::Payment,
                pattern: r"\b(?P<value>sq0atp-[0-9A-Za-z\-_]{22}|sq0csp-[0-9A-Za-z\-_]{43})\b",
                example: concat!("sq0atp-", "0123456789abcdefghijkl"),
                rotate_hint: "https://developer.squareup.com/apps → OAuth → 改写 Access Token",
                weight: 9,
            },
            FormatDef {
                id: "paypal_access_token",
                name: "PayPal OAuth Token",
                category: Category::Payment,
                pattern: r"(?i)\b(?P<value>access_token\$production\$[0-9a-z]{16}_[0-9a-z]{32})\b",
                example: concat!("access_token$production$", "1234567890abcdef_ABCDEF0123456789abcdef0123456789"),
                rotate_hint: "https://developer.paypal.com → 应用 → API 凭证 → 轮换 CLIENT_SECRET",
                weight: 9,
            },
            FormatDef {
                id: "shopify_access_token",
                name: "Shopify Access Token",
                category: Category::Payment,
                pattern: r"\b(?P<value>shp(?:pa|at|ss|ca)_[0-9a-fA-F]{32})\b",
                example: concat!("shpat_", "0123456789abcdef0123456789abcdef"),
                rotate_hint: "店铺后台 → 设置 → 应用 → 管理 API 访问令牌（重装 App 后重建）",
                weight: 9,
            },
        ];
        defs.iter()
            .map(|d| Format {
                id: d.id.to_string(),
                name: d.name.to_string(),
                category: d.category,
                pattern: d.pattern.to_string(),
                example: d.example.to_string(),
                rotate_hint: d.rotate_hint.to_string(),
                weight: d.weight,
            })
            .collect()
    })
}

/// 原始命中（扫描得到，尚未校验/评分）
#[derive(Debug, Clone)]
pub struct RawHit {
    /// 命中的格式在 finder.formats 中的下标
    pub format_idx: usize,
    /// 密钥值（仅值部分，不含上下文）
    pub value: String,
    /// 在原文中的字节偏移（用于定位行号/列号）
    pub start: usize,
    /// 密钥值在原文中的字节长度
    pub len: usize,
}

/// 编译后的查找器：内置格式 + 用户自定义格式
pub struct Finder {
    pub formats: Vec<Format>,
    regexes: Vec<Regex>,
}

impl Finder {
    /// 用内置格式 + 额外自定义格式构造查找器；自定义格式正则非法会返回 Err
    pub fn new(extra: &[CustomFormat]) -> Result<Finder, String> {
        let mut formats: Vec<Format> = builtin_formats().clone();
        for c in extra {
            formats.push(Format::from_custom(c)?);
        }
        let mut regexes = Vec::with_capacity(formats.len());
        for f in &formats {
            let re = Regex::new(&f.pattern)
                .map_err(|e| format!("格式 '{}' 正则编译失败: {}", f.id, e))?;
            regexes.push(re);
        }
        Ok(Finder { formats, regexes })
    }

    /// 仅内置格式的构造器（测试便捷方法）
    #[cfg(test)]
    pub fn builder() -> Result<Finder, String> {
        Finder::new(&[])
    }

    /// 在整段内容中查找所有命中（支持多行正则）
    pub fn find_all(&self, content: &str) -> Vec<RawHit> {
        let mut hits = Vec::new();
        for (idx, re) in self.regexes.iter().enumerate() {
            for caps in re.captures_iter(content) {
                let (value, span) = match caps.name("value") {
                    Some(v) => (v.as_str().to_string(), v.range()),
                    None => {
                        let m = caps.get(0).unwrap();
                        (m.as_str().to_string(), m.range())
                    }
                };
                if value.is_empty() {
                    continue;
                }
                hits.push(RawHit {
                    format_idx: idx,
                    value,
                    start: span.start,
                    len: span.len(),
                });
            }
        }
        // 去重：不同格式命中同一位置时，保留更长/更具体的那个
        hits.sort_by(|a, b| a.start.cmp(&b.start).then(b.len.cmp(&a.len)));
        let mut deduped: Vec<RawHit> = Vec::with_capacity(hits.len());
        for h in hits {
            if let Some(last) = deduped.last() {
                if h.start < last.start + last.len {
                    // 重叠：保留已保留的更长的那个（排序保证 len 降序）
                    continue;
                }
            }
            deduped.push(h);
        }
        deduped
    }
}