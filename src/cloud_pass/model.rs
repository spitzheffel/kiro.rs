//! Cloud Pass API 数据模型

use serde::{Deserialize, Serialize};

/// 获取凭证请求体
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetCredentialsRequest {
    pub code: String,
    pub device_id: String,
    pub client_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reassign: Option<bool>,
}

/// 心跳/声明活跃请求体
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatRequest {
    pub code: String,
    pub device_id: String,
}

/// Cloud Pass API 原始响应（加密或非加密）
///
/// 加密时：data 是 base64 字符串，需要 RSA+AES-GCM 解密
/// 非加密时：字段直接在顶层或嵌套在 data/credentials 中
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudPassRawResponse {
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub message: Option<String>,

    // 加密响应字段
    #[serde(default)]
    pub encrypted: Option<bool>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub iv: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    /// 加密时为 base64 字符串，非加密时为 JSON 对象
    #[serde(default)]
    pub data: Option<serde_json::Value>,

    // 非加密时直接包含凭证字段
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub profile_arn: Option<String>,
    #[serde(default)]
    pub kicked: Option<bool>,
    #[serde(default)]
    pub license_expires_at: Option<String>,

    // 嵌套的 credentials 对象（服务器可能返回）
    #[serde(default)]
    pub credentials: Option<CloudPassCredentials>,
}

/// 解密后的完整响应
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudPassResponse {
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub message: Option<String>,

    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub profile_arn: Option<String>,
    #[serde(default)]
    pub kicked: Option<bool>,
    #[serde(default)]
    pub license_expires_at: Option<String>,

    #[serde(default)]
    pub credentials: Option<CloudPassCredentials>,

    #[serde(default)]
    pub data: Option<CloudPassData>,
}

/// 响应中的 data 字段
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudPassData {
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub profile_arn: Option<String>,
    #[serde(default)]
    pub kicked: Option<bool>,
    #[serde(default)]
    pub license_expires_at: Option<String>,
    #[serde(default)]
    pub credentials: Option<CloudPassCredentials>,
}

/// 凭证数据（完整字段）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudPassCredentials {
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub profile_arn: Option<String>,
}

/// 从响应中提取最终的凭证数据
///
/// 服务器响应格式可能有多种：
/// 1. 字段直接在顶层
/// 2. 字段在 data 对象中
/// 3. 字段在 data.credentials 或顶层 credentials 中
/// 优先级：credentials > data > 顶层
pub struct ResolvedCredentials {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub expires_at: Option<String>,
    pub region: Option<String>,
    pub profile_arn: Option<String>,
    pub kicked: bool,
    pub license_expires_at: Option<String>,
}

impl CloudPassResponse {
    /// 从响应中解析出最终凭证，合并多层嵌套
    pub fn resolve(&self) -> ResolvedCredentials {
        // 先从 credentials / data.credentials 取
        let nested_creds = self
            .credentials
            .as_ref()
            .or_else(|| self.data.as_ref().and_then(|d| d.credentials.as_ref()));

        // 再从 data 取
        let data = self.data.as_ref();

        // 合并：nested_creds > data > 顶层，每个字段取第一个非 None
        let access_token = nested_creds
            .and_then(|c| c.access_token.clone())
            .or_else(|| data.and_then(|d| d.access_token.clone()))
            .or_else(|| self.access_token.clone());

        let refresh_token = nested_creds
            .and_then(|c| c.refresh_token.clone())
            .or_else(|| data.and_then(|d| d.refresh_token.clone()))
            .or_else(|| self.refresh_token.clone());

        let client_id = nested_creds
            .and_then(|c| c.client_id.clone())
            .or_else(|| data.and_then(|d| d.client_id.clone()))
            .or_else(|| self.client_id.clone());

        let client_secret = nested_creds
            .and_then(|c| c.client_secret.clone())
            .or_else(|| data.and_then(|d| d.client_secret.clone()))
            .or_else(|| self.client_secret.clone());

        let expires_at = nested_creds
            .and_then(|c| c.expires_at.clone())
            .or_else(|| data.and_then(|d| d.expires_at.clone()))
            .or_else(|| self.expires_at.clone());

        let region = nested_creds
            .and_then(|c| c.region.clone())
            .or_else(|| data.and_then(|d| d.region.clone()))
            .or_else(|| self.region.clone());

        let profile_arn = nested_creds
            .and_then(|c| c.profile_arn.clone())
            .or_else(|| data.and_then(|d| d.profile_arn.clone()))
            .or_else(|| self.profile_arn.clone());

        let kicked = data
            .and_then(|d| d.kicked)
            .or(self.kicked)
            .unwrap_or(false);

        let license_expires_at = data
            .and_then(|d| d.license_expires_at.clone())
            .or_else(|| self.license_expires_at.clone());

        ResolvedCredentials {
            access_token,
            refresh_token,
            client_id,
            client_secret,
            expires_at,
            region,
            profile_arn,
            kicked,
            license_expires_at,
        }
    }
}
