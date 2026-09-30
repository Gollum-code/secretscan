//! 风险：按类型/年龄/位置评分（0-10），年龄未知标记"未知"。

use crate::formats::Category;
use crate::scan::{LocatedHit, Source};

/// 风险等级
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn label(&self) -> &'static str {
        match self {
            RiskLevel::Low => "低",
            RiskLevel::Medium => "中",
            RiskLevel::High => "高",
            RiskLevel::Critical => "严重",
        }
    }
}

/// 年龄信息：文件 mtime 已知；env/git 未知或由 git 日期给出
#[derive(Debug, Clone)]
pub struct AgeInfo {
    pub known: bool,
    pub days: Option<u64>,
    pub label: String,
}

impl AgeInfo {
    pub fn unknown() -> AgeInfo {
        AgeInfo {
            known: false,
            days: None,
            label: "未知".into(),
        }
    }
}

/// 年龄：文件 mtime -> 距今天数
pub fn age_from_mtime(mtime: u64) -> AgeInfo {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = now.saturating_sub(mtime) / 86400;
    AgeInfo {
        known: true,
        days: Some(days),
        label: format!("{} 天", days),
    }
}

/// git 提交日期串（YYYY-MM-DD） -> 年龄
pub fn age_from_git_date(date: &str) -> AgeInfo {
    // 解析 YYYY-MM-DD
    let parts: Vec<&str> = date.split('-').collect();
    if parts.len() == 3 {
        if let (Ok(y), Ok(m), Ok(d)) = (
            parts[0].parse::<i32>(),
            parts[1].parse::<u32>(),
            parts[2].parse::<u32>(),
        ) {
            if let Some(day) = chrono::NaiveDate::from_ymd_opt(y, m, d) {
                let today = chrono::Local::now().date_naive();
                let days = (today - day).num_days().max(0) as u64;
                return AgeInfo {
                    known: true,
                    days: Some(days),
                    label: format!("{} 天", days),
                };
            }
        }
    }
    AgeInfo::unknown()
}

/// 单个命中的风险结论
#[derive(Debug, Clone)]
pub struct RiskResult {
    pub score: u8,
    pub level: RiskLevel,
    pub age: AgeInfo,
    pub factors: Vec<String>,
}

/// 按文件扩展名估计位置敏感度
fn path_sensitivity(path: &str) -> i8 {
    let lower = path.to_lowercase();
    if lower.ends_with(".env")
        || lower.ends_with(".env.local")
        || lower.contains(".env.")
        || lower.ends_with(".log")
    {
        return 2; // 密钥常驻文件
    }
    if lower.ends_with(".md")
        || lower.ends_with(".mdx")
        || lower.ends_with(".txt")
        || lower.ends_with(".rst")
        || lower.ends_with(".html")
        || lower.ends_with(".htm")
        || lower.contains("/docs/")
        || lower.starts_with("docs/")
    {
        return -3; // 文档/示例
    }
    if lower.ends_with(".json") || lower.ends_with(".toml") || lower.ends_with(".yaml")
        || lower.ends_with(".yml") || lower.ends_with(".ini") || lower.ends_with(".properties")
    {
        return 1; // 配置文件
    }
    0
}

/// 评分单个命中
pub fn score_hit(hit: &LocatedHit, base_weight: u8, category: Category) -> RiskResult {
    let mut score = base_weight as i32;
    let mut factors = Vec::new();

    // 位置因子
    match &hit.source {
        Source::File { path, line } => {
            let sens = path_sensitivity(path);
            if sens != 0 {
                score += sens as i32;
                factors.push(if sens > 0 {
                    format!("位于敏感文件 ({}:{})", path, line)
                } else {
                    "位于文档/示例路径".to_string()
                });
            }
        }
        Source::Env { name } => {
            factors.push(format!("环境变量 {}", name));
        }
        Source::Git { .. } => {
            factors.push("出现在 git 历史中（建议从历史中清理）".into());
            score += 1;
        }
    }

    // 年龄因子
    let age = match &hit.source {
        Source::File { .. } => hit
            .file_mtime
            .map(age_from_mtime)
            .unwrap_or_else(AgeInfo::unknown),
        Source::Git { date, .. } => age_from_git_date(date),
        Source::Env { .. } => AgeInfo::unknown(),
    };

    if age.known {
        if let Some(d) = age.days {
            if d >= 180 {
                score += 2;
                factors.push(format!("密钥已存在超过 180 天（{}）", age.label));
            } else if d >= 90 {
                score += 1;
                factors.push(format!("密钥已存在超过 90 天（{}）", age.label));
            }
        }
    }

    // 分类微调
    let _ = category;
    // 类型权重已通过 base_weight 计入

    let score = score.clamp(1, 10) as u8;
    let level = match score {
        8..=10 => RiskLevel::Critical,
        6..=7 => RiskLevel::High,
        4..=5 => RiskLevel::Medium,
        _ => RiskLevel::Low,
    };
    RiskResult {
        score,
        level,
        age,
        factors,
    }
}

/// 汇总风险统计
#[derive(Debug, Clone, Default)]
pub struct RiskSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub by_category: Vec<(String, usize)>,
}

pub fn summarize(
    findings: &[(LocatedHit, RiskResult)],
    formats: &crate::formats::Finder,
) -> RiskSummary {
    use std::collections::BTreeMap;
    let mut s = RiskSummary::default();
    let mut cats: BTreeMap<String, usize> = BTreeMap::new();
    for (hit, r) in findings {
        s.total += 1;
        match r.level {
            RiskLevel::Critical => s.critical += 1,
            RiskLevel::High => s.high += 1,
            RiskLevel::Medium => s.medium += 1,
            RiskLevel::Low => s.low += 1,
        }
        let cat = formats.formats[hit.format_idx]
            .category
            .label()
            .to_string();
        *cats.entry(cat).or_insert(0) += 1;
    }
    s.by_category = cats.into_iter().collect();
    s
}