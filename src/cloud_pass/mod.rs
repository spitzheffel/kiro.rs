//! Cloud Pass 模块
//!
//! 从 kiro-cloud-pass (eskysoft) 服务器自动获取和刷新凭证
//! 支持定时刷新、心跳保活、kicked 检测

pub mod client;
pub mod model;
pub mod state;
pub mod worker;
