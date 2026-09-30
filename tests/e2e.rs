//! 端到端测试：真实跑一次 `secretscan` 二进制，校验报告产物与退出码。

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("secretscan_e2e_{}_{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn write(dir: &std::path::Path, name: &str, body: &str) {
    let p = dir.join(name);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(p, body).unwrap();
}

/// 写一个包含"真密钥 + 文档示例"的仓库目录
fn fixture(tag: &str) -> PathBuf {
    let d = tmpdir(tag);
    let stripe = format!("sk_live_{}", "0123456789abcdefghijklmn");
    write(
        &d,
        "config/settings.env",
        &format!("AWS_ACCESS_KEY_ID=AKIAQYLPMN5TTESTCASE\nSTRIPE_KEY={}\n", stripe),
    );
    let slack = format!("xoxb-{}", "123456789012-1234567890123-abcdefghijklmnopqrstuvwx");
    write(
        &d,
        "src/app.py",
        &format!("SLACK = \"{}\"\n", slack),
    );
    write(
        &d,
        "docs/setup.md",
        "示例：OPENAI_API_KEY=sk-00000000000000000000000000000000 （仅文档示例）\n",
    );
    d
}

fn run(dir: &PathBuf, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_secretscan"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("运行 secretscan 失败");
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

#[test]
fn detects_and_exits_nonzero_on_high_risk() {
    let d = fixture("high");
    let (code, out) = run(&d, &["--format", "cli", "--no-color", "."]);
    assert!(
        code == 1,
        "含严重/高危密钥时退出码应为 1，实际 {}；输出：{}",
        code,
        out
    );
    assert!(out.contains("AWS Access Key ID"), "应识别 AWS 密钥；输出：{}", out);
    assert!(out.contains("Stripe"), "应识别 Stripe 密钥；输出：{}", out);
    assert!(out.contains("轮换"), "应输出轮换建议；输出：{}", out);
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn docs_example_is_filtered() {
    let d = fixture("docfilter");
    let (_, out) = run(&d, &["--no-color", "docs/setup.md"]);
    // 文档里的示例 OpenAI key 应被过滤，不应作为真实发现
    assert!(
        !out.contains("OpenAI"),
        "文档示例密钥应被过滤；输出：{}",
        out
    );
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn generates_all_reports() {
    let d = fixture("all");
    let (code, out) = run(
        &d,
        &["--format", "all", "--no-color", ".", "-o", "report"],
    );
    let _ = code;
    let report_dir = d.join("report");
    assert!(report_dir.join("secretscan-report.json").exists(), "应生成 JSON");
    assert!(report_dir.join("rotation-plan.csv").exists(), "应生成 CSV");
    assert!(report_dir.join("dashboard.html").exists(), "应生成 HTML 看板");

    let json = fs::read_to_string(report_dir.join("secretscan-report.json")).unwrap();
    assert!(json.contains("rotation_plan"));
    let html = fs::read_to_string(report_dir.join("dashboard.html")).unwrap();
    assert!(html.contains("secretscan"));
    assert!(out.contains("HTML 看板"));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn clean_repo_exits_zero() {
    let d = tmpdir("clean");
    write(&d, "main.py", "print('hello world')\n");
    let (code, out) = run(&d, &["--no-color", "."]);
    assert_eq!(code, 0, "干净仓库应退出 0；输出：{}", out);
    assert!(out.contains("未发现") || out.contains("0"), "应报告无发现；输出：{}", out);
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn env_scan_finds_injected_secret() {
    let d = tmpdir("env");
    write(&d, "empty.txt", "");
    let out = Command::new(env!("CARGO_BIN_EXE_secretscan"))
        .args(["--env", "--no-color", "empty.txt"])
        .current_dir(&d)
        .env("MY_TEST_AWS", "AKIAQYLPMN5TTESTCASE")
        .output()
        .expect("运行失败");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("MY_TEST_AWS"),
        "应从环境变量中发现密钥；输出：{}",
        text
    );
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn list_formats_prints_library() {
    let d = tmpdir("list");
    let (code, out) = run(&d, &["--list-formats"]);
    assert_eq!(code, 0);
    assert!(out.contains("aws_access_key_id"));
    assert!(out.contains("stripe_secret_key"));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn custom_format_via_config() {
    let d = tmpdir("custom");
    write(&d, "app.conf", "internal_token = ZZZ9QwertyuiopASDFghjklZXCV123\n");
    write(
        &d,
        "ss.toml",
        r#"
[[custom_formats]]
id = "internal_token"
name = "内部服务 Token"
category = "cloud"
pattern = "(?i)internal_token\\s*=\\s*(?P<value>[A-Za-z0-9]{20,})"
weight = 7
rotate_hint = "联系平台组在 SRE 控制台轮换"
"#,
    );
    let (code, out) = run(
        &d,
        &["--config", "ss.toml", "--no-color", "app.conf", "--exit-zero"],
    );
    assert!(out.contains("内部服务 Token"), "自定义格式应生效；输出：{}", out);
    let _ = code;
    let _ = fs::remove_dir_all(&d);
}
