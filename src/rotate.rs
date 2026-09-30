//! 轮换清单：把校验后的发现整理成"该轮换哪些、怎么换"，并导出 CSV。

use crate::formats::Finder;
use crate::risk::{RiskLevel, RiskResult};
use crate::scan::LocatedHit;

/// 建议动作
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotateAction {
    /// 立即轮换
    Immediate,
    /// 计划轮换
    Planned,
    /// 校验确认
    Verify,
    /// 从 git 历史清理
    Purge,
}

impl RotateAction {
    pub fn label(&self) -> &'static str {
        match self {
            RotateAction::Immediate => "立即轮换",
            RotateAction::Planned => "计划轮换",
            RotateAction::Verify => "校验确认",
            RotateAction::Purge => "历史清理",
        }
    }
    pub fn ascii(&self) -> &'static str {
        match self {
            RotateAction::Immediate => "IMMEDIATE",
            RotateAction::Planned => "PLANNED",
            RotateAction::Verify => "VERIFY",
            RotateAction::Purge => "PURGE",
        }
    }
    pub fn from_level_and_source(level: RiskLevel, in_git: bool) -> RotateAction {
        if in_git && level >= RiskLevel::High {
            return RotateAction::Purge;
        }
        match level {
            RiskLevel::Critical | RiskLevel::High => RotateAction::Immediate,
            RiskLevel::Medium => RotateAction::Planned,
            RiskLevel::Low => RotateAction::Verify,
        }
    }
}

/// 一条轮换记录
#[derive(Debug, Clone)]
pub struct RotationItem {
    pub format_id: String,
    pub format_name: String,
    pub category: String,
    pub masked_value: String,
    pub location: String,
    pub source_kind: String,
    pub risk_score: u8,
    pub risk_level: String,
    pub age: String,
    pub action: RotateAction,
    pub rotate_hint: String,
    pub factors: Vec<String>,
}

/// 由 (命中, 风险) 构造轮换清单
pub fn build_rotation_list(
    findings: &[(LocatedHit, RiskResult)],
    formats: &Finder,
) -> Vec<RotationItem> {
    findings
        .iter()
        .map(|(hit, risk)| {
            let f = &formats.formats[hit.format_idx];
            let in_git = hit.source.kind() == "git";
            RotationItem {
                format_id: f.id.clone(),
                format_name: f.name.clone(),
                category: f.category.label().to_string(),
                masked_value: crate::scan::mask_value(&hit.value),
                location: hit.source.location(),
                source_kind: hit.source.kind().to_string(),
                risk_score: risk.score,
                risk_level: risk.level.label().to_string(),
                age: risk.age.label.clone(),
                action: RotateAction::from_level_and_source(risk.level, in_git),
                rotate_hint: f.rotate_hint.clone(),
                factors: risk.factors.clone(),
            }
        })
        .collect()
}

/// 按动作优先级排序（立即 -> 计划 -> 校验），同级按风险分降序
pub fn sort_rotation_list(items: &mut [RotationItem]) {
    items.sort_by(|a, b| {
        let pa = match a.action {
            RotateAction::Immediate => 0,
            RotateAction::Purge => 1,
            RotateAction::Planned => 2,
            RotateAction::Verify => 3,
        };
        let pb = match b.action {
            RotateAction::Immediate => 0,
            RotateAction::Purge => 1,
            RotateAction::Planned => 2,
            RotateAction::Verify => 3,
        };
        pa.cmp(&pb)
            .then(b.risk_score.cmp(&a.risk_score))
            .then(a.format_name.cmp(&b.format_name))
            .then(a.location.cmp(&b.location))
    });
}

/// 导出 CSV（含 BOM，Excel 友好）
pub fn to_csv(items: &[RotationItem]) -> String {
    let mut csv = String::new();
    csv.push('\u{feff}'); // UTF-8 BOM
    csv.push_str("类型ID,服务,分类,掩码值,位置,来源,风险分,风险等级,年龄,建议动作,轮换提示,风险因子\n");
    for it in items {
        let factors = it.factors.join("; ");
        let row = vec![
            it.format_id.clone(),
            it.format_name.clone(),
            it.category.clone(),
            it.masked_value.clone(),
            it.location.clone(),
            it.source_kind.clone(),
            it.risk_score.to_string(),
            it.risk_level.clone(),
            it.age.clone(),
            it.action.label().to_string(),
            it.rotate_hint.clone(),
            factors,
        ];
        let escaped: Vec<String> = row.iter().map(|c| csv_escape(c)).collect();
        csv.push_str(&escaped.join(","));
        csv.push('\n');
    }
    csv
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}