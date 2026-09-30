//! 扫描：文件 / 环境变量 / git 历史（轻量），统一产出 `LocatedHit`。

use crate::formats::{Finder, RawHit};
use std::fs;
use std::path::Path;
use std::process::Command;

/// 命中位置类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// 文件路径 + 1-based 行号
    File { path: String, line: usize },
    /// 环境变量
    Env { name: String },
    /// git 历史提交
    Git { commit: String, date: String },
}

impl Source {
    pub fn kind(&self) -> &'static str {
        match self {
            Source::File { .. } => "file",
            Source::Env { .. } => "env",
            Source::Git { .. } => "git",
        }
    }

    /// 用于展示的定位串，如 `src/a.rs:12` / `env:AWS_KEY` / `git:abc1234@2024-01-01`
    pub fn location(&self) -> String {
        match self {
            Source::File { path, line } => format!("{}:{}", path, line),
            Source::Env { name } => format!("env:{}", name),
            Source::Git { commit, date } => format!("git:{}@{}", &commit[..commit.len().min(8)], date),
        }
    }
}

/// 带定位信息的命中
#[derive(Debug, Clone)]
pub struct LocatedHit {
    pub format_idx: usize,
    pub value: String,
    pub source: Source,
    /// 命中所在行内容（用于上下文判断 / 报告展示）
    pub context: String,
    /// 文件最后修改时间的 unix 秒（仅 file 来源有）
    pub file_mtime: Option<u64>,
}

/// 扫描选项
pub struct ScanOptions {
    pub max_file_size: u64,
    /// 是否遵守 .gitignore（默认 true）
    pub respect_gitignore: bool,
    pub verbose: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            max_file_size: 5 * 1024 * 1024,
            respect_gitignore: true,
            verbose: false,
        }
    }
}

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    "vendor",
    "secretscan-report",
];

/// 扫描一批路径（文件或目录，目录递归）
pub fn scan_paths(
    finder: &Finder,
    paths: &[String],
    opts: &ScanOptions,
) -> Vec<LocatedHit> {
    let mut results = Vec::new();
    for p in paths {
        let path = Path::new(p);
        if path.is_file() {
            if let Some(hits) = scan_file(finder, path, opts) {
                results.extend(hits);
            }
            continue;
        }
        if !path.is_dir() {
            if opts.verbose {
                eprintln!("[warn] 路径不存在，跳过: {}", p);
            }
            continue;
        }
        let mut builder = ignore::WalkBuilder::new(path);
        builder
            .hidden(false)
            .git_ignore(opts.respect_gitignore)
            .git_global(opts.respect_gitignore)
            .git_exclude(opts.respect_gitignore)
            .parents(opts.respect_gitignore)
            .follow_links(false)
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                let name = e.file_name().to_str().unwrap_or("");
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    let is_hidden = name.starts_with('.');
                    let is_skip = SKIP_DIRS.contains(&name);
                    return !(is_hidden || is_skip);
                }
                // 文件一律保留（包括 .env 等隐藏文件）
                true
            });
        for entry in builder.build() {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    if opts.verbose {
                        eprintln!("[warn] 遍历错误: {}", e);
                    }
                    continue;
                }
            };
            let epath = entry.path();
            if epath.is_file() {
                if let Some(hits) = scan_file(finder, epath, opts) {
                    results.extend(hits);
                }
            }
        }
    }
    results
}

/// 扫描单个文件；返回 None 表示跳过（二进制/过大等）
pub fn scan_file(finder: &Finder, path: &Path, opts: &ScanOptions) -> Option<Vec<LocatedHit>> {
    // 大小检查
    if let Ok(md) = fs::metadata(path) {
        if md.len() > opts.max_file_size {
            return None;
        }
    }
    let bytes = fs::read(path).ok()?;
    // 二进制快速判定：前 8KB 内出现 NUL 视为二进制
    let probe = &bytes[..bytes.len().min(8192)];
    if probe.contains(&0u8) {
        return None;
    }
    let content = String::from_utf8_lossy(&bytes);
    let raw_hits = finder.find_all(&content);
    if raw_hits.is_empty() {
        return None;
    }
    let mtime = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    let path_str = path.to_string_lossy().replace('\\', "/");
    Some(locate_all(
        &raw_hits,
        &content,
        Source::File { path: path_str, line: 0 },
        mtime,
    ))
}

/// 把字节偏移定位到行号/上下文，并对 Git 来源附带 commit 信息
fn locate_all(
    raw_hits: &[RawHit],
    content: &str,
    default_source: Source,
    file_mtime: Option<u64>,
) -> Vec<LocatedHit> {
    let mut out = Vec::with_capacity(raw_hits.len());
    for h in raw_hits {
        let line_no = line_number(content, h.start);
        let context = line_text(content, h.start);
        let source = match &default_source {
            Source::File { path, .. } => Source::File {
                path: path.clone(),
                line: line_no,
            },
            other => other.clone(),
        };
        out.push(LocatedHit {
            format_idx: h.format_idx,
            value: h.value.clone(),
            source,
            context,
            file_mtime,
        });
    }
    out
}

/// 偏移量 -> 1-based 行号
pub fn line_number(content: &str, offset: usize) -> usize {
    content[..offset.min(content.len())]
        .bytes()
        .filter(|b| *b == b'\n')
        .count()
        + 1
}

/// 偏移量所在行的文本（去掉换行）
pub fn line_text(content: &str, offset: usize) -> String {
    let off = offset.min(content.len());
    let start = content[..off].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let end = content[off..]
        .find('\n')
        .map(|i| off + i)
        .unwrap_or(content.len());
    content[start..end].trim().to_string()
}

/// 扫描环境变量
pub fn scan_env(finder: &Finder) -> Vec<LocatedHit> {
    let mut out = Vec::new();
    for (name, value) in std::env::vars() {
        let hits = finder.find_all(&value);
        for h in hits {
            out.push(LocatedHit {
                format_idx: h.format_idx,
                value: h.value,
                source: Source::Env {
                    name: name.clone(),
                },
                context: format!("{}={}", name, mask_value(&value)),
                file_mtime: None,
            });
        }
    }
    out
}

/// 扫描 git 历史（`git log -p --all`），命中附带 commit 与提交日期
pub fn scan_git(finder: &Finder, repo_path: &str, verbose: bool) -> Vec<LocatedHit> {
    let out = Command::new("git")
        .args(["log", "-p", "--all", "--no-color", "--full-history"])
        .current_dir(repo_path)
        .output();

    let output = match out {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            if verbose {
                eprintln!(
                    "[warn] git log 失败: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            return Vec::new();
        }
        Err(e) => {
            if verbose {
                eprintln!("[warn] 无法执行 git: {}", e);
            }
            return Vec::new();
        }
    };

    let content = String::from_utf8_lossy(&output.stdout);
    let raw_hits = finder.find_all(&content);
    if raw_hits.is_empty() {
        return Vec::new();
    }

    // 逐行跟踪当前 commit hash 与日期，让每个命中归属到正确的提交
    let mut commit_at: Vec<Option<(String, String)>> = Vec::with_capacity(raw_hits.len());
    let mut cur_hash: Option<String> = None;
    let mut cur_date = String::from("unknown");
    let mut byte_pos = 0usize;
    for line in content.split('\n') {
        let line_start = byte_pos;
        byte_pos += line.len() + 1;
        if let Some(rest) = line.strip_prefix("commit ") {
            cur_hash = Some(rest.trim().to_string());
        } else if let Some(d) = line.strip_prefix("Date:") {
            cur_date = normalize_git_date(d.trim());
        }
        // 该行是否含有命中起点
        let line_end = line_start + line.len();
        for h in &raw_hits {
            if h.start >= line_start && h.start <= line_end {
                commit_at.push(Some((cur_hash.clone().unwrap_or_default(), cur_date.clone())));
            }
        }
    }

    let mut out_hits = Vec::with_capacity(raw_hits.len());
    for (i, h) in raw_hits.iter().enumerate() {
        let (commit, date) = commit_at
            .get(i)
            .cloned()
            .flatten()
            .unwrap_or_else(|| (String::from("unknown"), String::from("unknown")));
        out_hits.push(LocatedHit {
            format_idx: h.format_idx,
            value: h.value.clone(),
            source: Source::Git { commit, date },
            context: line_text(&content, h.start),
            file_mtime: None,
        });
    }
    out_hits
}

/// 把 git 的原始 Date 归一化为 YYYY-MM-DD
fn normalize_git_date(raw: &str) -> String {
    // 形如: Fri Sep 27 12:00:00 2024 +0800
    let parts: Vec<&str> = raw.split_whitespace().collect();
    if parts.len() >= 5 {
        let year = parts[4];
        // 从月份名映射
        let month = match parts[1] {
            "Jan" => "01",
            "Feb" => "02",
            "Mar" => "03",
            "Apr" => "04",
            "May" => "05",
            "Jun" => "06",
            "Jul" => "07",
            "Aug" => "08",
            "Sep" => "09",
            "Oct" => "10",
            "Nov" => "11",
            "Dec" => "12",
            _ => "01",
        };
        if year.len() == 4 {
            return format!("{}-{}-{}", year, month, parts[2]);
        }
    }
    raw.to_string()
}

/// 掩码：保留前 4 后 4，中间用 *
pub fn mask_value(v: &str) -> String {
    let chars: Vec<char> = v.chars().collect();
    if chars.len() <= 10 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{}{}{}", head, "*".repeat(chars.len() - 8), tail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::Finder;

    #[test]
    fn test_mask() {
        assert_eq!(mask_value("AKIAIOSFODNN7EXAMPLE"), "AKIA************MPLE");
        assert_eq!(mask_value("short"), "*****");
    }

    #[test]
    fn test_line_helpers() {
        let content = "line1\nline2\nline3";
        assert_eq!(line_number(content, 0), 1);
        assert_eq!(line_number(content, 6), 2);
        assert_eq!(line_text(content, 7), "line2");
    }

    #[test]
    fn test_git_date_normalize() {
        assert_eq!(
            normalize_git_date("Fri Sep 27 12:00:00 2024 +0800"),
            "2024-09-27"
        );
    }

    #[test]
    fn test_scan_file_basic() {
        let finder = Finder::builder().unwrap();
        let dir = std::env::temp_dir().join("secretscan_scan_test");
        let _ = fs::create_dir_all(&dir);
        let f = dir.join("creds.env");
        fs::write(&f, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n").unwrap();
        let hits = scan_file(&finder, &f, &ScanOptions::default()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].value, "AKIAIOSFODNN7EXAMPLE");
        match &hits[0].source {
            Source::File { line, .. } => assert_eq!(*line, 1),
            _ => panic!("expected file source"),
        }
    }
}
