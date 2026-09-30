//! 校验：格式合法性复核 + 常见误报过滤（占位符 / 示例 / 上下文 / 白名单）。

use crate::formats::Finder;
use crate::scan::{LocatedHit, Source};
use regex::Regex;

/// 一批误报过滤规则
#[derive(Debug, Clone, Default)]
pub struct FilterRules {
    /// 白名单：值命中任一正则即视为合法/跳过
    pub allowlist: Vec<Regex>,
    /// 静默忽略的路径子串（如 `vendor/`, `test-data/`）
    pub ignore_paths: Vec<String>,
}

impl FilterRules {
    pub fn build(
        allow_patterns: &[String],
        ignore_paths: &[String],
    ) -> Result<FilterRules, String> {
        let mut allowlist = Vec::with_capacity(allow_patterns.len());
        for p in allow_patterns {
            allowlist.push(
                Regex::new(p).map_err(|e| format!("白名单正则无效: {} ({})", p, e))?,
            );
        }
        Ok(FilterRules {
            allowlist,
            ignore_paths: ignore_paths.to_vec(),
        })
    }
}

/// 对单个命中执行校验与误报过滤。
/// 返回 `Ok(true)` 保留、`Ok(false)` 过滤掉（verbose 时说明原因）。
pub fn validate(
    finder: &Finder,
    hit: &LocatedHit,
    rules: &FilterRules,
    verbose: bool,
) -> Result<bool, String> {
    let format = &finder.formats[hit.format_idx];
    let value = &hit.value;
    let lower = value.to_lowercase();

    // 0) 白名单路径
    for p in &rules.ignore_paths {
        let loc = hit.source.location();
        if loc.contains(p) {
            if verbose {
                eprintln!("[skip] 路径匹配忽略规则 '{}': {}", p, loc);
            }
            return Ok(false);
        }
    }

    // 1) 白名单正则：值命中则跳过
    for re in &rules.allowlist {
        if re.is_match(value) {
            if verbose {
                eprintln!(
                    "[skip] 值命中白名单 '{}': {} ({})",
                    re.as_str(),
                    hit.source.location(),
                    crate::scan::mask_value(value)
                );
            }
            return Ok(false);
        }
    }

    // 2) 占位符 / 示例值检测
    if is_placeholder(value) {
        if verbose {
            eprintln!(
                "[skip] 疑似占位符: {} ({})",
                hit.source.location(),
                crate::scan::mask_value(value)
            );
        }
        return Ok(false);
    }

    // 3) 上下文示例检测（行内容 / 路径出现示例性词汇）
    let ctx = hit.context.to_lowercase();
    let example_words = [
        "example",
        "placeholder",
        "sample",
        "demo",
        "dummy",
        "fake",
        "mock",
        "xxxx",
        "changeme",
        "your-",
        "your_key",
        "replace",
        "<token>",
        // 中文示例性词汇
        "示例",
        "演示",
        "样例",
        "假值",
    ];
    let path_ctx = match &hit.source {
        Source::File { path, .. } => path.to_lowercase(),
        _ => String::new(),
    };
    let ctx_says_example = example_words.iter().any(|w| ctx.contains(w));
    // 文档/示例类路径（README、docs 目录、sample、fixture 等）
    let path_is_docs = path_ctx.ends_with(".md")
        || path_ctx.ends_with(".mdx")
        || path_ctx.ends_with(".rst")
        || path_ctx.ends_with(".txt")
        || path_ctx.contains("docs/")
        || path_ctx.contains("doc/")
        || path_ctx.contains("example")
        || path_ctx.contains("sample")
        || path_ctx.contains("fixture");
    let looks_like_example = ctx_says_example || path_is_docs;

    // 4) 格式内核对齐（长度 / 校验位）
    let format_ok = check_format_alignment(format.id.as_str(), value);

    let is_example_val = lower.contains("example")
        || lower.contains("xxxx")
        || lower.contains("test-")
        || lower.contains("fake")
        || lower.contains("123456")
        || has_long_repeat_run(value);

    // 出现在文档/示例路径，且上下文或值带示例特征 → 判为演示密钥
    if looks_like_example && (ctx_says_example || is_example_val) {
        if verbose {
            eprintln!(
                "[skip] 疑似示例/文档中的演示密钥: {} ({})",
                hit.source.location(),
                crate::scan::mask_value(value)
            );
        }
        return Ok(false);
    }
    // 同一行出现多个示例性关键词（如 "example"/"示例"）也判为演示
    if ctx_says_example && ctx.matches("example").count() + ctx.matches("示例").count() >= 2 {
        if verbose {
            eprintln!(
                "[skip] 同行多处示例标记: {} ({})",
                hit.source.location(),
                crate::scan::mask_value(value)
            );
        }
        return Ok(false);
    }

    // 5) 格式内核对齐失败 → 视为误匹配，除非是上下文型格式
    if let Some(reason) = format_ok {
        if reason != "ok" {
            if verbose {
                eprintln!(
                    "[skip] 格式内核对齐失败 {}: {} ({})",
                    reason,
                    hit.source.location(),
                    crate::scan::mask_value(value)
                );
            }
            return Ok(false);
        }
    }

    Ok(true)
}

/// 对部分格式做内核对齐：返回 Some("ok") / Some(原因) / None（无需内核对齐）
fn check_format_alignment(fmt_id: &str, value: &str) -> Option<String> {
    match fmt_id {
        "aws_access_key_id" => {
            // AKIA 等前缀 + 16 位 base62 = 20 位
            if value.len() == 20 {
                Some("ok".into())
            } else {
                Some(format!("AWSAccessKeyID 应为 20 位，实际 {}", value.len()))
            }
        }
        "openai_api_key" => {
            if value.len() >= 32 {
                Some("ok".into())
            } else {
                Some("OpenAI key 过短".into())
            }
        }
        "telegram_bot_token" => {
            let ok = value
                .split_once(':')
                .map(|(bot_id, _)| bot_id.len() >= 8 && bot_id.len() <= 10)
                .unwrap_or(false);
            if ok {
                Some("ok".into())
            } else {
                Some("Telegram token 需要 bot id 8-10 位".into())
            }
        }
        "discord_bot_token" => {
            if value.matches('.').count() == 2 {
                Some("ok".into())
            } else {
                Some("Discord token 应含两个点".into())
            }
        }
        "mailchimp_api_key" => {
            let ok = value.starts_with("us") || {
                let parts: Vec<&str> = value.split('-').collect();
                parts.len() == 2
            };
            if ok {
                Some("ok".into())
            } else {
                Some("Mailchimp key 需要 -us<NN> 后缀".into())
            }
        }
        _ => None,
    }
}

/// 占位符 / 示例值启发式：值本身明显是模板或示例
fn is_placeholder(v: &str) -> bool {
    let lower = v.to_lowercase();
    if lower.contains("example") {
        return true;
    }
    if lower.contains("xxxx") || lower.contains("xxxxx") {
        return true;
    }
    if lower.starts_with("your_") || lower.starts_with("your-") {
        return true;
    }
    if lower == "changeme" {
        return true;
    }
    // 大量重复同一字符（aaaa... / 0000...）视为占位
    if v.len() >= 8 {
        let first = v.chars().next().unwrap();
        if v.chars().all(|c| c == first) {
            return true;
        }
    }
    false
}

/// 值中是否存在 ≥8 个连续相同字符（如 sk-0000000... 等合成占位）
fn has_long_repeat_run(v: &str) -> bool {
    let chars: Vec<char> = v.chars().collect();
    if chars.len() < 8 {
        return false;
    }
    let mut run = 1;
    for i in 1..chars.len() {
        if chars[i] == chars[i - 1] {
            run += 1;
            if run >= 8 {
                return true;
            }
        } else {
            run = 1;
        }
    }
    false
}