//! secretscan 库：密钥格式识别与轮换治理核心模块。
//!
//! - `formats`：内置 20+ 服务密钥格式 + 自定义格式扩展
//! - `scan`：文件 / 环境变量 / git 历史扫描
//! - `validate`：格式校验 + 误报过滤
//! - `risk`：类型 / 年龄风险评分
//! - `rotate`：轮换清单（动作 + 提示 + CSV）
//! - `report`：CLI 表格 + HTML 看板 + JSON 报告

pub mod formats;
pub mod report;
pub mod risk;
pub mod rotate;
pub mod scan;
pub mod validate;
