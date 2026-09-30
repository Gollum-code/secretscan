//! 报告：CLI 表格 / JSON / HTML 看板。

use crate::risk::RiskSummary;
use crate::rotate::RotationItem;

/// JSON 报告数据结构
pub struct JsonReport<'a> {
    pub generated_at: String,
    pub summary: &'a RiskSummary,
    pub items: &'a [RotationItem],
}

impl<'a> JsonReport<'a> {
    pub fn to_json(&self) -> String {
        use serde_json::json;
        let items: Vec<serde_json::Value> = self
            .items
            .iter()
            .map(|it| {
                json!({
                    "format_id": it.format_id,
                    "service": it.format_name,
                    "category": it.category,
                    "masked_value": it.masked_value,
                    "location": it.location,
                    "source": it.source_kind,
                    "risk_score": it.risk_score,
                    "risk_level": it.risk_level,
                    "age": it.age,
                    "action": it.action.label(),
                    "action_ascii": it.action.ascii(),
                    "rotate_hint": it.rotate_hint,
                    "risk_factors": it.factors,
                })
            })
            .collect();
        let by_cat: serde_json::Map<String, serde_json::Value> = self
            .summary
            .by_category
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();
        let root = json!({
            "tool": "secretscan",
            "generated_at": self.generated_at,
            "summary": {
                "total": self.summary.total,
                "critical": self.summary.critical,
                "high": self.summary.high,
                "medium": self.summary.medium,
                "low": self.summary.low,
                "by_category": by_cat,
            },
            "rotation_plan": items,
        });
        serde_json::to_string_pretty(&root).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e))
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// 颜色：严重=红 高=橙 中=黄 低=绿
fn level_class(level: &str) -> &'static str {
    match level {
        "严重" => "crit",
        "高" => "high",
        "中" => "med",
        _ => "low",
    }
}

fn action_class(action: &str) -> &'static str {
    match action {
        "立即轮换" => "act-immediate",
        "历史清理" => "act-purge",
        "计划轮换" => "act-planned",
        _ => "act-verify",
    }
}

/// 生成独立 HTML 看板
pub fn to_html(summary: &RiskSummary, items: &[RotationItem], generated_at: &str) -> String {
    let mut cat_cards = String::new();
    for (cat, count) in &summary.by_category {
        cat_cards.push_str(&format!(
            r#"<div class="cat-card"><div class="cat-count">{}</div><div class="cat-name">{}</div></div>"#,
            count,
            esc(cat)
        ));
    }

    let mut rows = String::new();
    for it in items {
        let lc = level_class(&it.risk_level);
        let ac = action_class(it.action.label());
        let factors = it
            .factors
            .iter()
            .map(|f| format!("<li>{}</li>", esc(f)))
            .collect::<Vec<_>>()
            .join("");
        let factors_html = if factors.is_empty() {
            String::new()
        } else {
            format!("<details><summary>因子</summary><ul>{}</ul></details>", factors)
        };
        rows.push_str(&format!(
            r#"<tr>
  <td><span class="badge {lc}">{}</span></td>
  <td>{}<div class="sub">{}</div></td>
  <td>{}</td>
  <td class="mono">{}</td>
  <td class="mono">{}</td>
  <td>{}</td>
  <td><span class="badge {ac}">{}</span></td>
  <td>{} {}</td>
</tr>"#,
            esc(&it.risk_level),
            esc(&it.format_name),
            esc(&it.category),
            it.risk_score,
            esc(&it.masked_value),
            esc(&it.location),
            esc(&it.age),
            it.action.label(),
            esc(&it.rotate_hint),
            factors_html,
        ));
    }

    format!(
        r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>secretscan 密钥轮换看板</title>
<style>
  :root {{ --bg:#0f1117; --panel:#181b24; --text:#e6e8ee; --muted:#8b93a7; --accent:#5b8cff; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font-family:-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,'Microsoft YaHei',sans-serif;
         background:var(--bg); color:var(--text); }}
  header {{ padding:24px 32px; border-bottom:1px solid #232734; background:linear-gradient(180deg,#151823,#0f1117); }}
  h1 {{ margin:0 0 6px; font-size:22px; letter-spacing:.5px; }}
  .meta {{ color:var(--muted); font-size:13px; }}
  .wrap {{ padding:24px 32px; }}
  .cards {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:24px; }}
  .card {{ background:var(--panel); border:1px solid #232734; border-radius:12px; padding:16px 20px; min-width:150px; }}
  .card .num {{ font-size:30px; font-weight:700; }}
  .card .lbl {{ color:var(--muted); font-size:13px; margin-top:4px; }}
  .card.crit .num {{ color:#ff6b6b; }} .card.high .num {{ color:#ffa94d; }}
  .card.med .num {{ color:#ffd43b; }} .card.low .num {{ color:#69db7c; }}
  .cats {{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:20px; }}
  .cat-card {{ background:var(--panel); border:1px solid #232734; border-radius:10px; padding:10px 16px; }}
  .cat-count {{ font-size:20px; font-weight:600; color:var(--accent); }}
  .cat-name {{ color:var(--muted); font-size:12px; }}
  .toolbar {{ margin-bottom:12px; display:flex; gap:10px; flex-wrap:wrap; align-items:center; }}
  .toolbar input, .toolbar select {{ background:var(--panel); color:var(--text); border:1px solid #2b3040;
      border-radius:8px; padding:8px 10px; font-size:13px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #232734; vertical-align:top; }}
  th {{ color:var(--muted); font-weight:600; text-transform:uppercase; font-size:11px; letter-spacing:.6px;
        position:sticky; top:0; background:#141824; }}
  tr:hover td {{ background:#161a25; }}
  .mono {{ font-family:ui-monospace,'SFMono-Regular',Consolas,monospace; word-break:break-all; }}
  .sub {{ color:var(--muted); font-size:11px; margin-top:2px; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:600; }}
  .badge.crit {{ background:#3a1d1f; color:#ff8787; }} .badge.high {{ background:#3a2a1a; color:#ffc078; }}
  .badge.med {{ background:#3a361a; color:#ffe066; }} .badge.low {{ background:#1a3a24; color:#8ce99a; }}
  .act-immediate {{ background:#3a1d1f; color:#ff8787; }} .act-purge {{ background:#3a2030; color:#f783ac; }}
  .act-planned {{ background:#2a2f45; color:#a5b4fc; }} .act-verify {{ background:#23323a; color:#66d9e8; }}
  details {{ margin-top:6px; }} details summary {{ cursor:pointer; color:var(--muted); font-size:11px; }}
  details ul {{ margin:6px 0 0; padding-left:16px; color:var(--muted); font-size:11px; }}
  .empty {{ color:var(--muted); text-align:center; padding:60px 0; }}
  footer {{ color:var(--muted); font-size:12px; padding:20px 32px 40px; }}
</style>
</head>
<body>
<header>
  <h1>🔐 secretscan · 密钥轮换看板</h1>
  <div class="meta">生成时间：{gen} · 共发现 <b>{total}</b> 个待治理密钥</div>
</header>
<div class="wrap">
  <div class="cards">
    <div class="card crit"><div class="num">{crit}</div><div class="lbl">严重 · 立即轮换</div></div>
    <div class="card high"><div class="num">{high}</div><div class="lbl">高危 · 尽快轮换</div></div>
    <div class="card med"><div class="num">{med}</div><div class="lbl">中危 · 计划轮换</div></div>
    <div class="card low"><div class="num">{low}</div><div class="lbl">低危 · 校验确认</div></div>
  </div>
  <div class="cats">{cat_cards}</div>
  <div class="toolbar">
    <input id="q" placeholder="搜索服务 / 位置 / 掩码值..." />
    <select id="lvl">
      <option value="">全部风险</option>
      <option value="严重">仅严重</option>
      <option value="高">仅高</option>
      <option value="中">仅中</option>
      <option value="低">仅低</option>
    </select>
    <select id="act">
      <option value="">全部动作</option>
      <option value="立即轮换">立即轮换</option>
      <option value="历史清理">历史清理</option>
      <option value="计划轮换">计划轮换</option>
      <option value="校验确认">校验确认</option>
    </select>
  </div>
  <table id="tbl">
    <thead><tr>
      <th>风险</th><th>服务</th><th>分值</th><th>掩码值</th><th>位置</th><th>年龄</th><th>建议动作</th><th>轮换方法</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <div class="empty" id="empty" style="display:none">没有匹配的密钥 🎉</div>
</div>
<footer>由 <b>secretscan</b> 生成 · 仓库里的密钥一眼认出是哪个服务的，还告诉你要不要轮换</footer>
<script>
  const q = document.getElementById('q');
  const lvl = document.getElementById('lvl');
  const act = document.getElementById('act');
  const rows = [...document.querySelectorAll('#tbl tbody tr')];
  function apply() {{
    const t = q.value.trim().toLowerCase();
    const l = lvl.value, a = act.value;
    let shown = 0;
    rows.forEach(r => {{
      const txt = r.textContent.toLowerCase();
      const okL = !l || r.children[0].textContent.includes(l);
      const okA = !a || r.children[6].textContent.includes(a);
      const okT = !t || txt.includes(t);
      const vis = okL && okA && okT;
      r.style.display = vis ? '' : 'none';
      if (vis) shown++;
    }});
    document.getElementById('empty').style.display = shown ? 'none' : 'block';
  }}
  [q,lvl,act].forEach(el => el.addEventListener('input', apply));
</script>
</body>
</html>
"##,
        gen = esc(generated_at),
        total = summary.total,
        crit = summary.critical,
        high = summary.high,
        med = summary.medium,
        low = summary.low,
        cat_cards = cat_cards,
        rows = rows
    )
}
