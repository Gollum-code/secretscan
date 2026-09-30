//! secretscan — 密钥格式识别与轮换治理 CLI
//!
//! 流程：扫描（文件 / 环境变量 / git 历史）→ 校验（格式 + 误报过滤）
//! → 风险评分（类型 / 年龄）→ 轮换清单（立即 / 计划 / 校验）→ 报告（CLI / JSON / CSV / HTML）。

use clap::Parser;
use secretscan::formats::{CustomFormat, Finder};
use secretscan::rotate::RotationItem;
use secretscan::scan::{LocatedHit, ScanOptions};
use secretscan::{risk, report, rotate, scan, validate};
use std::path::PathBuf;

use validate::FilterRules;

// ============================================================ CLI 定义

#[derive(Parser, Debug)]
#[command(
    name = "secretscan",
    version,
    about = "密钥格式识别与轮换治理：认出是哪个服务的密钥，判断风险，生成轮换清单",
    long_about = "secretscan 扫描项目 / 仓库 / 环境变量 / git 历史中的各类服务密钥（20+ 格式），\
判断格式合法性与误报，按类型与年龄评分，并输出可执行的轮换清单（CSV / HTML 看板）。"
)]
struct Cli {
    /// 扫描路径（文件或目录，目录递归；默认当前目录）
    #[arg(value_name = "PATHS", default_value = ".")]
    paths: Vec<String>,

    /// 扫描环境变量
    #[arg(short = 'e', long = "env")]
    scan_env: bool,

    /// 扫描 git 历史（`git log -p --all`），可指定仓库目录
    #[arg(short = 'g', long = "git", value_name = "REPO", num_args = 0..=1, default_missing_value = ".")]
    scan_git: Option<String>,

    /// 输出格式：cli / json / csv / html / all
    #[arg(short = 'f', long = "format", default_value = "cli", value_parser = ["cli", "json", "csv", "html", "all"])]
    format: String,

    /// 报告输出目录（json/csv/html 落盘位置）
    #[arg(short = 'o', long = "output-dir", default_value = "secretscan-report")]
    output_dir: PathBuf,

    /// 配置文件（自定义格式 / 白名单 / 忽略路径）
    #[arg(short = 'c', long = "config", value_name = "FILE")]
    config: Option<PathBuf>,

    /// 白名单正则：值命中的密钥直接跳过（可重复）
    #[arg(long = "allow", value_name = "REGEX")]
    allow: Vec<String>,

    /// 忽略路径子串（可重复），如 `vendor/`
    #[arg(long = "ignore-path", value_name = "SUBSTR")]
    ignore_path: Vec<String>,

    /// 不遵守 .gitignore
    #[arg(long = "no-gitignore")]
    no_gitignore: bool,

    /// 单文件最大扫描体积（MB）
    #[arg(long = "max-size", default_value_t = 5)]
    max_size: u64,

    /// 列出内置识别格式后退出
    #[arg(long = "list-formats")]
    list_formats: bool,

    /// 详细模式（打印被过滤的误报）
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// 静默模式（仅输出汇总与文件）
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// 禁用彩色输出
    #[arg(long = "no-color")]
    no_color: bool,

    /// 始终以 0 退出（默认发现严重/高危时退出码为 1，便于 CI 门禁）
    #[arg(long = "exit-zero")]
    exit_zero: bool,
}

// ============================================================ 配置

#[derive(Debug, Default, serde::Deserialize)]
struct Config {
    #[serde(default)]
    settings: Settings,
    #[serde(default, rename = "custom_formats")]
    custom_formats: Vec<CustomFormat>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct Settings {
    #[serde(default)]
    allowlist: Vec<String>,
    #[serde(default)]
    ignore_paths: Vec<String>,
}

impl Config {
    fn load(path: &PathBuf) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("读取配置文件失败 {}: {}", path.display(), e))?;
        toml::from_str(&text).map_err(|e| format!("解析配置文件失败 {}: {}", path.display(), e))
    }
}

// ============================================================ 终端着色

struct Style {
    enabled: bool,
}
impl Style {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.enabled {
            format!("\x1b[{}m{}\x1b[0m", code, s)
        } else {
            s.to_string()
        }
    }
    fn red(&self, s: &str) -> String {
        self.paint("31", s)
    }
    fn yellow(&self, s: &str) -> String {
        self.paint("33", s)
    }
    fn green(&self, s: &str) -> String {
        self.paint("32", s)
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
}

// ============================================================ CLI 输出

fn print_findings(items: &[RotationItem], st: &Style, quiet: bool) {
    if items.is_empty() {
        println!("{}", st.green("✅ 未发现需要治理的密钥（已过滤示例/占位符误报）"));
        return;
    }
    if !quiet {
        println!();
        println!("{}", st.bold("发现的密钥与轮换建议"));
        println!("{}", st.dim(&"─".repeat(100)));
        for it in items {
            let tag = match it.action.label() {
                "立即轮换" => "● 立即轮换",
                "历史清理" => "● 历史清理",
                "计划轮换" => "● 计划轮换",
                _ => "○ 校验确认",
            };
            println!(
                "{tag} [{}] {}",
                it.risk_score,
                it.format_name
            );
            println!("   {} {}", st.dim("位置:"), it.location);
            println!("   {} {}", st.dim("年龄:"), it.age);
            println!("   {} {}", st.dim("密钥:"), it.masked_value);
            println!("   {} {}", st.dim("轮换:"), it.rotate_hint);
            for f in &it.factors {
                println!("   {} {}", st.dim("·"), st.dim(f));
            }
            println!();
        }
    }
}

fn print_summary(summary: &risk::RiskSummary, scanned: usize, st: &Style) {
    println!("{}", st.bold("汇总"));
    println!("{}", st.dim(&"─".repeat(100)));
    println!("扫描命中（过滤前）: {}", scanned);
    println!(
        "待治理: {}  |  {} {}  |  {} {}  |  {} {}  |  {} {}",
        summary.total,
        st.red("严重"),
        summary.critical,
        st.yellow("高危"),
        summary.high,
        st.dim("中危"),
        summary.medium,
        st.green("低危"),
        summary.low
    );
    if !summary.by_category.is_empty() {
        let cats: Vec<String> = summary
            .by_category
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        println!("按分类: {}", cats.join("  "));
    }
}

fn list_formats(finder: &Finder) {
    println!("{}", "内置识别格式库（共 {} 种）".replacen("{}", &finder.formats.len().to_string(), 1));
    println!("{}", "─".repeat(110));
    println!(
        "{:<32} {:<8} {:<5} {:<24} 示例",
        "ID", "分类", "权重", "名称"
    );
    for f in &finder.formats {
        let ex: String = f.example.chars().take(22).collect();
        println!(
            "{:<32} {:<8} {:<5} {:<24} {}",
            f.id,
            f.category.label(),
            f.weight,
            f.name,
            ex.replace('\n', " ")
        );
    }
}

// ============================================================ 主流程

fn main() {
    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
    let cli = Cli::parse();

    // 终端着色：仅 TTY 且未 --no-color 时启用
    let use_color = !cli.no_color && std::io::IsTerminal::is_terminal(&std::io::stdout());
    let st = Style { enabled: use_color };

    // 1) 加载配置
    let cfg = match &cli.config {
        Some(p) => match Config::load(p) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[error] {}", e);
                return 2;
            }
        },
        None => Config::default(),
    };

    let mut allow_patterns = cli.allow.clone();
    allow_patterns.extend(cfg.settings.allowlist.clone());
    let mut ignore_paths = cli.ignore_path.clone();
    ignore_paths.extend(cfg.settings.ignore_paths.clone());

    // 2) 构建识别库（内置 + 自定义）
    let finder = match Finder::new(&cfg.custom_formats) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[error] {}", e);
            return 2;
        }
    };

    if cli.list_formats {
        list_formats(&finder);
        return 0;
    }

    let rules = match FilterRules::build(&allow_patterns, &ignore_paths) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[error] {}", e);
            return 2;
        }
    };

    let opts = ScanOptions {
        max_file_size: cli.max_size * 1024 * 1024,
        respect_gitignore: !cli.no_gitignore,
        verbose: cli.verbose,
    };

    // 3) 扫描
    let mut raw: Vec<LocatedHit> = Vec::new();
    raw.extend(scan::scan_paths(&finder, &cli.paths, &opts));
    if cli.scan_env {
        raw.extend(scan::scan_env(&finder));
    }
    if let Some(repo) = &cli.scan_git {
        raw.extend(scan::scan_git(&finder, repo, cli.verbose));
    }
    let scanned = raw.len();

    // 4) 校验（过滤误报）
    let mut findings: Vec<(LocatedHit, risk::RiskResult)> = Vec::new();
    for hit in raw {
        match validate::validate(&finder, &hit, &rules, cli.verbose) {
            Ok(true) => {
                let fmt = &finder.formats[hit.format_idx];
                let r = risk::score_hit(&hit, fmt.weight, fmt.category);
                findings.push((hit, r));
            }
            Ok(false) => {}
            Err(e) => eprintln!("[warn] 校验异常: {}", e),
        }
    }

    // 5) 风险汇总 + 轮换清单
    let summary = risk::summarize(&findings, &finder);
    let mut items = rotate::build_rotation_list(&findings, &finder);
    rotate::sort_rotation_list(&mut items);

    // 6) 输出
    let want_all = cli.format == "all";
    let want_html = want_all || cli.format == "html";
    let want_json = want_all || cli.format == "json";
    let want_csv = want_all || cli.format == "csv";
    let want_cli = cli.format == "cli" || (want_all && !cli.quiet);

    if want_cli {
        print_findings(&items, &st, cli.quiet);
        print_summary(&summary, scanned, &st);
    }

    if want_cli || want_json || want_csv || want_html {
        if let Err(e) = std::fs::create_dir_all(&cli.output_dir) {
            eprintln!("[warn] 无法创建输出目录: {}", e);
        }
    }

    let generated_at = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    if want_json {
        let j = report::JsonReport {
            generated_at: generated_at.clone(),
            summary: &summary,
            items: &items,
        };
        let path = cli.output_dir.join("secretscan-report.json");
        if let Err(e) = std::fs::write(&path, j.to_json()) {
            eprintln!("[warn] 写 JSON 失败: {}", e);
        } else {
            println!("JSON 报告: {}", path.display());
        }
    }
    if want_csv {
        let path = cli.output_dir.join("rotation-plan.csv");
        if let Err(e) = std::fs::write(&path, rotate::to_csv(&items)) {
            eprintln!("[warn] 写 CSV 失败: {}", e);
        } else {
            println!("轮换清单 CSV: {}", path.display());
        }
    }
    if want_html {
        let path = cli.output_dir.join("dashboard.html");
        if let Err(e) = std::fs::write(&path, report::to_html(&summary, &items, &generated_at)) {
            eprintln!("[warn] 写 HTML 失败: {}", e);
        } else {
            println!("HTML 看板: {}", path.display());
        }
    }

    // 7) 退出码：发现严重/高危返回 1（可 --exit-zero 覆盖）
    if !cli.exit_zero && (summary.critical > 0 || summary.high > 0) {
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_defaults() {
        let cli = Cli::try_parse_from(vec!["secretscan"]).unwrap();
        assert_eq!(cli.paths, vec!["."]);
        assert_eq!(cli.format, "cli");
        assert!(!cli.scan_env);
    }

    #[test]
    fn test_cli_git_default_repo() {
        let cli = Cli::try_parse_from(vec!["secretscan", "--git"]).unwrap();
        assert_eq!(cli.scan_git.as_deref(), Some("."));
    }

    #[test]
    fn test_config_defaults() {
        let c: Config = toml::from_str("").unwrap();
        assert!(c.custom_formats.is_empty());
        assert!(c.settings.allowlist.is_empty());
    }

    #[test]
    fn test_config_custom_format() {
        let toml_src = r#"
            [settings]
            allowlist = ["^TEST-"]
            ignore_paths = ["vendor/"]

            [[custom_formats]]
            id = "internal_token"
            name = "内部 Token"
            category = "cloud"
            pattern = "(?i)internal_token\\s*=\\s*(?P<value>[A-Za-z0-9]{16})"
            weight = 6
        "#;
        let c: Config = toml::from_str(toml_src).unwrap();
        assert_eq!(c.custom_formats.len(), 1);
        assert_eq!(c.settings.allowlist, vec!["^TEST-"]);
        let f = secretscan::formats::Format::from_custom(&c.custom_formats[0]).unwrap();
        assert_eq!(f.weight, 6);
    }

    #[test]
    fn test_builtin_formats_compile() {
        let f = Finder::new(&[]).unwrap();
        assert!(f.formats.len() >= 20, "至少应有 20 种内置格式");
    }

    #[test]
    fn test_source_location() {
        let s = crate::scan::Source::File {
            path: "a/b.env".into(),
            line: 12,
        };
        assert_eq!(s.location(), "a/b.env:12");
        let e = crate::scan::Source::Env { name: "KEY".into() };
        assert_eq!(e.location(), "env:KEY");
    }

    #[test]
    fn test_write_report_files() {
        // 冒烟：确保 HTML/CSV/JSON 可生成
        let summary = risk::RiskSummary {
            total: 1,
            critical: 1,
            high: 0,
            medium: 0,
            low: 0,
            by_category: vec![("云厂商".into(), 1)],
        };
        let items = vec![RotationItem {
            format_id: "aws_access_key_id".into(),
            format_name: "AWS Access Key ID".into(),
            category: "云厂商".into(),
            masked_value: "AKIA****MPLE".into(),
            location: "x.env:1".into(),
            source_kind: "file".into(),
            risk_score: 9,
            risk_level: "严重".into(),
            age: "10 天".into(),
            action: rotate::RotateAction::Immediate,
            rotate_hint: "IAM 控制台".into(),
            factors: vec!["位于敏感文件".into()],
        }];
        let html = report::to_html(&summary, &items, "2024-01-01 00:00:00");
        assert!(html.contains("secretscan"));
        let csv = rotate::to_csv(&items);
        assert!(csv.contains("aws_access_key_id"));
        let jr = report::JsonReport {
            generated_at: "2024-01-01 00:00:00".into(),
            summary: &summary,
            items: &items,
        };
        assert!(jr.to_json().contains("rotation_plan"));
    }

    #[test]
    fn test_risk_level_ordering() {
        use crate::risk::RiskLevel;
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
    }
}
