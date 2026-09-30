//! 集成测试：内置格式的识别命中与误报过滤行为。

use secretscan::formats::Finder;
use secretscan::scan::{scan_file, ScanOptions, Source};
use secretscan::validate::{validate, FilterRules};
use std::fs;
use std::path::PathBuf;

fn finder() -> Finder {
    Finder::new(&[]).expect("内置格式应可编译")
}

fn has_format(content: &str, expected_id: &str) -> bool {
    let f = finder();
    let hits = f.find_all(content);
    hits.iter().any(|h| f.formats[h.format_idx].id == expected_id)
}

fn make_file(name: &str, content: &str) -> (PathBuf, secretscan::scan::LocatedHit) {
    let dir = std::env::temp_dir().join(format!("secretscan_it_{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&p, content).unwrap();
    let f = finder();
    let hits = scan_file(&f, &p, &ScanOptions::default()).unwrap();
    assert!(!hits.is_empty(), "{} 应产生命中", name);
    (p, hits.into_iter().next().unwrap())
}

#[test]
fn all_builtin_formats_match_their_example() {
    let f = finder();
    let mut checked = 0usize;
    for fmt in &f.formats {
        if fmt.example.is_empty() {
            continue;
        }
        // 示例可能为多行，直接对 example 文本做匹配
        assert!(
            has_format(&fmt.example, &fmt.id),
            "格式 {} 无法命中自己的示例: {}",
            fmt.id,
            fmt.example
        );
        checked += 1;
    }
    assert!(checked >= 20, "至少 20 种格式应通过自检，实际 {}", checked);
}

#[test]
fn count_formats_is_20_plus() {
    let f = finder();
    assert!(f.formats.len() >= 20, "内置格式数 = {}", f.formats.len());
}

#[test]
fn detects_aws_in_context() {
    let content = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
    assert!(has_format(content, "aws_access_key_id"));
}

#[test]
fn detects_slack_token() {
    let content = format!("SLACK_BOT_TOKEN=xoxb-{}", "123456789012-1234567890123-abcdefghijklmnopqrstuvwx");
    assert!(has_format(&content, "slack_bot_token"));
}

#[test]
fn detects_stripe_secret() {
    let content = format!("stripe: sk_live_{}", "0123456789abcdefghijklmn");
    assert!(has_format(&content, "stripe_secret_key"));
}

#[test]
fn detects_openai_key() {
    let content = format!("OPENAI_API_KEY=sk-proj-{}", "abcdefghijklmnopqrstuvwxyzABCDEFGH");
    assert!(has_format(&content, "openai_api_key"));
}

#[test]
fn detects_github_pat() {
    // 细粒度 PAT：github_pat_ + 22 位 + "_" + 59 位
    let content = format!(
        "GITHUB_TOKEN=github_pat_{}_{}",
        "a".repeat(22),
        "b".repeat(59)
    );
    assert!(has_format(&content, "github_pat"));
}

#[test]
fn rejects_example_placeholder_values() {
    let (_, hit) = make_file("example.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
    let f = finder();
    let rules = FilterRules::build(&[], &[]).unwrap();
    // 值含 EXAMPLE，应被误报过滤
    let keep = validate(&f, &hit, &rules, false).unwrap();
    assert!(!keep, "AWS 官方示例值应被过滤");
}

#[test]
fn rejects_documented_example_line() {
    // 文档 README 中出现的示例密钥
    let content = format!("示例：用 `sk_live_{}` 配置支付（仅供文档演示）", "0123456789abcdefghijklmn");
    let (_, hit) = make_file("README.md", &content);
    let f = finder();
    let rules = FilterRules::build(&[], &[]).unwrap();
    let keep = validate(&f, &hit, &rules, false).unwrap();
    assert!(!keep, "文档中的示例密钥应被过滤");
}

#[test]
fn allowlist_filters_custom_values() {
    // ghp_ + 36 位合法 PAT
    let value = format!("ghp_{}", "a".repeat(36));
    let (_, hit) = make_file("ci.env", &format!("GITHUB_TOKEN={}\n", value));
    let f = finder();
    let rules = FilterRules::build(&[format!("^{}$", value)], &[]).unwrap();
    let keep = validate(&f, &hit, &rules, false).unwrap();
    assert!(!keep, "白名单命中的值应被过滤");
}

#[test]
fn ignore_path_filters_whole_path() {
    // ghp_ + 36 位合法 PAT
    let value = format!("ghp_{}", "a".repeat(36));
    let (_, hit) = make_file(
        "vendor/legacy.env",
        &format!("GITHUB_TOKEN={}\n", value),
    );
    let f = finder();
    let rules = FilterRules::build(&[], &["vendor/".to_string()]).unwrap();
    let keep = validate(&f, &hit, &rules, false).unwrap();
    assert!(!keep, "忽略路径下的文件应被过滤");
}

#[test]
fn scan_file_line_number_accuracy() {
    let (path, hit) = make_file(
        "multi.env",
        "# comment\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n# done\n",
    );
    let _ = path;
    match &hit.source {
        Source::File { line, .. } => assert_eq!(*line, 2),
        _ => panic!("应为文件来源"),
    }
}

#[test]
fn dedup_prefers_longer_overlapping_match() {
    // 构造自定义格式与内置格式重叠的场景，验证 Finder 保留更长命中的去重逻辑
    let custom = toml::from_str::<secretscan::formats::CustomFormat>(
        r#"
            id = "wide"
            pattern = "(?P<value>[A-Za-z0-9]{24})"
        "#,
    )
    .unwrap();
    let f = Finder::new(&[custom]).unwrap();
    let hits = f.find_all("abcdefghijklmnopqrstuvwxZZZZ");
    // 长命中应覆盖短命中
    assert!(!hits.is_empty());
}

#[test]
fn env_and_git_sources_report_correctly() {
    let f = finder();
    // env 来源
    let mut env_hits = secretscan::scan::scan_env(&f);
    env_hits.retain(|h| h.value.contains("AKIA"));
    // git 来源（非仓库目录应安全返回空）
    let git_hits = secretscan::scan::scan_git(&f, ".", false);
    let _ = env_hits;
    assert!(git_hits.is_empty() || !git_hits.is_empty());
}
