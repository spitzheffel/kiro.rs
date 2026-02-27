//! Cloud Pass 运行时共享状态
//!
//! Worker 写入，Admin API 读取

use std::sync::Arc;

use parking_lot::RwLock;
use serde::Serialize;
use tokio::sync::Notify;

/// Cloud Pass 运行时状态（线程安全共享）
#[derive(Clone)]
pub struct CloudPassState {
    inner: Arc<RwLock<CloudPassStatusInner>>,
    /// 手动刷新通知器
    refresh_notify: Arc<Notify>,
}

/// 内部状态数据
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudPassStatusInner {
    /// 是否已启用（配置了 cloud_pass）
    pub enabled: bool,
    /// 是否已连接（至少成功刷新过一次）
    pub connected: bool,
    /// 服务器地址
    pub server_url: String,
    /// 设备 ID
    pub device_id: String,
    /// 激活码（脱敏，只显示前6位）
    pub license_code_masked: String,
    /// 刷新间隔（秒）
    pub refresh_interval: u64,
    /// 是否启用抢占
    pub reassign: bool,
    /// 客户端版本
    pub client_version: String,
    /// 上次刷新时间（RFC3339）
    pub last_refresh_at: Option<String>,
    /// 上次刷新是否成功
    pub last_refresh_ok: bool,
    /// 上次刷新错误信息
    pub last_refresh_error: Option<String>,
    /// 成功刷新次数
    pub refresh_success_count: u64,
    /// 失败刷新次数
    pub refresh_failure_count: u64,
    /// License 到期时间
    pub license_expires_at: Option<String>,
    /// 是否被踢出
    pub kicked: bool,
    /// 注入的凭据 ID（最近一次）
    pub injected_credential_id: Option<u64>,
}

impl CloudPassState {
    /// 创建未启用的空状态
    pub fn disabled() -> Self {
        Self {
            refresh_notify: Arc::new(Notify::new()),
            inner: Arc::new(RwLock::new(CloudPassStatusInner {
                enabled: false,
                connected: false,
                server_url: String::new(),
                device_id: String::new(),
                license_code_masked: String::new(),
                refresh_interval: 0,
                reassign: false,
                client_version: String::new(),
                last_refresh_at: None,
                last_refresh_ok: false,
                last_refresh_error: None,
                refresh_success_count: 0,
                refresh_failure_count: 0,
                license_expires_at: None,
                kicked: false,
                injected_credential_id: None,
            })),
        }
    }

    /// 从配置创建初始状态
    pub fn from_config(
        server_url: &str,
        device_id: &str,
        license_code: &str,
        refresh_interval: u64,
        reassign: bool,
        client_version: &str,
    ) -> Self {
        let masked = if license_code.len() > 6 {
            format!("{}***", &license_code[..6])
        } else {
            format!("{}***", license_code)
        };

        Self {
            refresh_notify: Arc::new(Notify::new()),
            inner: Arc::new(RwLock::new(CloudPassStatusInner {
                enabled: true,
                connected: false,
                server_url: server_url.to_string(),
                device_id: device_id.to_string(),
                license_code_masked: masked,
                refresh_interval,
                reassign,
                client_version: client_version.to_string(),
                last_refresh_at: None,
                last_refresh_ok: false,
                last_refresh_error: None,
                refresh_success_count: 0,
                refresh_failure_count: 0,
                license_expires_at: None,
                kicked: false,
                injected_credential_id: None,
            })),
        }
    }

    /// 记录刷新成功
    pub fn record_success(
        &self,
        credential_id: Option<u64>,
        license_expires_at: Option<String>,
        kicked: bool,
    ) {
        let mut inner = self.inner.write();
        inner.connected = true;
        inner.last_refresh_at = Some(chrono::Utc::now().to_rfc3339());
        inner.last_refresh_ok = true;
        inner.last_refresh_error = None;
        inner.refresh_success_count += 1;
        inner.kicked = kicked;
        if let Some(id) = credential_id {
            inner.injected_credential_id = Some(id);
        }
        if license_expires_at.is_some() {
            inner.license_expires_at = license_expires_at;
        }
    }

    /// 记录刷新失败
    pub fn record_failure(&self, error: &str) {
        let mut inner = self.inner.write();
        inner.last_refresh_at = Some(chrono::Utc::now().to_rfc3339());
        inner.last_refresh_ok = false;
        inner.last_refresh_error = Some(error.to_string());
        inner.refresh_failure_count += 1;
    }

    /// 记录被踢出
    pub fn record_kicked(&self) {
        let mut inner = self.inner.write();
        inner.kicked = true;
    }

    /// 获取当前状态快照
    pub fn snapshot(&self) -> CloudPassStatusInner {
        self.inner.read().clone()
    }

    /// 获取设备 ID
    pub fn device_id(&self) -> String {
        self.inner.read().device_id.clone()
    }

    /// 触发手动刷新
    pub fn trigger_refresh(&self) {
        self.refresh_notify.notify_one();
    }

    /// 等待手动刷新通知
    pub fn wait_for_refresh(&self) -> Arc<Notify> {
        self.refresh_notify.clone()
    }
}
