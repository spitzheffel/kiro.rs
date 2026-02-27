//! Cloud Pass HTTP 客户端

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};

use crate::model::config::CloudPassConfig;

use super::model::{
    CloudPassRawResponse, CloudPassResponse, GetCredentialsRequest, HeartbeatRequest,
    ResolvedCredentials,
};

/// RSA 公钥（与 kiro-cloud-pass 插件一致）
const RSA_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzSEy6tgft6momfTbXV54
H1gTUgIqkjA103aQwyiolpdXmPY1NoCVR4IzgkZppoXNyYGtfJP1bbxYJHR3l0kX
ksnUe0Y8iuV75bjvHYMgOdNR1iqqRlQ8DM7FAq0IJ1Y5sY8UN8zqzkI9tGUrDaCh
0aIl7dXpKbhfBw4EbIGzsjTmSlbK1i25Jcq55knvKZVlH4E9N+zqETUIY5Njd3Xd
bVz53eaxXu1etKCf8VoFZWp7J3/0WR4CvThsZRtjls0YGTpZCuFwSg9byWwF0VKv
Mvr1L6n3eCH7UdEnLCJ2w9VSaGQ+lfcLBt5LTAhZzZrGikvyrllYmbUX9Ts3UzyQ
GQIDAQAB
-----END PUBLIC KEY-----";

/// Cloud Pass API 客户端
pub struct CloudPassClient {
    http_client: reqwest::Client,
    server_url: String,
    license_code: String,
    device_id: String,
    client_version: String,
    rsa_public_key: RsaPublicKey,
}

impl CloudPassClient {
    /// 创建客户端实例
    pub fn new(config: &CloudPassConfig) -> Self {
        let device_id = config
            .device_id
            .clone()
            .unwrap_or_else(|| Self::read_or_generate_device_id());

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("创建 HTTP 客户端失败");

        let rsa_public_key =
            RsaPublicKey::from_public_key_pem(RSA_PUBLIC_KEY_PEM).expect("解析 RSA 公钥失败");

        Self {
            http_client,
            server_url: config.server_url.clone(),
            license_code: config.license_code.clone(),
            device_id,
            client_version: config.client_version.clone(),
            rsa_public_key,
        }
    }

    /// 获取设备 ID
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// 调用 /api/get-credentials 获取凭证
    pub async fn get_credentials(
        &self,
        reassign: bool,
    ) -> anyhow::Result<ResolvedCredentials> {
        let url = format!("{}/api/get-credentials", self.server_url);

        let req = GetCredentialsRequest {
            code: self.license_code.clone(),
            device_id: self.device_id.clone(),
            client_version: self.client_version.clone(),
            reassign: if reassign { Some(true) } else { None },
        };

        let raw_resp = self
            .http_client
            .post(&url)
            .json(&req)
            .send()
            .await?
            .json::<CloudPassRawResponse>()
            .await?;

        // 处理加密响应
        let resp: CloudPassResponse = if raw_resp.encrypted.unwrap_or(false) {
            self.decrypt_response(&raw_resp)?
        } else {
            // 非加密：将 raw 转为 CloudPassResponse
            let data_obj = raw_resp.data.and_then(|v| {
                if v.is_object() {
                    serde_json::from_value(v).ok()
                } else {
                    None
                }
            });
            CloudPassResponse {
                success: raw_resp.success,
                message: raw_resp.message,
                access_token: raw_resp.access_token,
                refresh_token: raw_resp.refresh_token,
                client_id: raw_resp.client_id,
                client_secret: raw_resp.client_secret,
                expires_at: raw_resp.expires_at,
                region: raw_resp.region,
                profile_arn: raw_resp.profile_arn,
                kicked: raw_resp.kicked,
                license_expires_at: raw_resp.license_expires_at,
                credentials: raw_resp.credentials,
                data: data_obj,
            }
        };

        if !resp.success {
            let msg = resp.message.unwrap_or_else(|| "未知错误".to_string());
            anyhow::bail!("获取凭证失败: {}", msg);
        }

        Ok(resp.resolve())
    }

    /// 解密加密响应（RSA 公钥解密 AES key + AES-256-GCM 解密 data）
    ///
    /// Node.js 的 crypto.publicDecrypt 使用 RSA 公钥做原始模幂运算恢复数据，
    /// 等价于 RSA 签名验证的原始操作（m = c^e mod n），然后去除 PKCS#1 v1.5 padding。
    fn decrypt_response(
        &self,
        raw: &CloudPassRawResponse,
    ) -> anyhow::Result<CloudPassResponse> {
        let enc_key = BASE64
            .decode(raw.key.as_deref().ok_or_else(|| anyhow::anyhow!("缺少加密 key"))?)
            .map_err(|e| anyhow::anyhow!("key base64 解码失败: {}", e))?;
        let iv_bytes = BASE64
            .decode(raw.iv.as_deref().ok_or_else(|| anyhow::anyhow!("缺少加密 iv"))?)
            .map_err(|e| anyhow::anyhow!("iv base64 解码失败: {}", e))?;
        let tag_bytes = BASE64
            .decode(raw.tag.as_deref().ok_or_else(|| anyhow::anyhow!("缺少加密 tag"))?)
            .map_err(|e| anyhow::anyhow!("tag base64 解码失败: {}", e))?;

        // data 字段在加密时是 base64 字符串
        let enc_data_str = raw
            .data
            .as_ref()
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("加密响应缺少 data 字符串"))?;
        let enc_data = BASE64
            .decode(enc_data_str)
            .map_err(|e| anyhow::anyhow!("data base64 解码失败: {}", e))?;

        // RSA 公钥解密：c^e mod n，然后去除 PKCS#1 v1.5 签名 padding
        let aes_key = rsa_public_decrypt(&self.rsa_public_key, &enc_key)?;

        if aes_key.len() != 32 {
            anyhow::bail!(
                "RSA 解密后 AES 密钥长度错误: {} (期望 32)",
                aes_key.len()
            );
        }

        // AES-256-GCM 解密
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| anyhow::anyhow!("创建 AES cipher 失败: {}", e))?;
        let nonce = Nonce::from_slice(&iv_bytes);

        // 拼接密文 + tag（aes-gcm crate 期望 ciphertext||tag 格式）
        let mut ciphertext_with_tag = enc_data;
        ciphertext_with_tag.extend_from_slice(&tag_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext_with_tag.as_ref())
            .map_err(|e| anyhow::anyhow!("AES-GCM 解密失败: {}", e))?;

        let json_str = String::from_utf8(plaintext)
            .map_err(|e| anyhow::anyhow!("解密后 UTF-8 解码失败: {}", e))?;

        tracing::debug!("Cloud Pass 解密成功，明文长度: {}", json_str.len());

        let resp: CloudPassResponse = serde_json::from_str(&json_str)
            .map_err(|e| anyhow::anyhow!("解密后 JSON 解析失败: {}", e))?;

        Ok(resp)
    }

    /// 调用 /api/heartbeat 心跳保活
    pub async fn heartbeat(&self) -> anyhow::Result<()> {
        let url = format!("{}/api/heartbeat", self.server_url);

        let req = HeartbeatRequest {
            code: self.license_code.clone(),
            device_id: self.device_id.clone(),
        };

        let resp = self
            .http_client
            .post(&url)
            .json(&req)
            .send()
            .await?;

        if !resp.status().is_success() {
            tracing::warn!("心跳请求失败: HTTP {}", resp.status());
        }

        Ok(())
    }

    /// 调用 /api/claim-active 声明活跃（被踢后重新抢占）
    pub async fn claim_active(&self) -> anyhow::Result<()> {
        let url = format!("{}/api/claim-active", self.server_url);

        let req = HeartbeatRequest {
            code: self.license_code.clone(),
            device_id: self.device_id.clone(),
        };

        let resp = self
            .http_client
            .post(&url)
            .json(&req)
            .send()
            .await?;

        if !resp.status().is_success() {
            tracing::warn!("claim-active 请求失败: HTTP {}", resp.status());
        }

        Ok(())
    }

    /// 读取或生成设备 ID
    ///
    /// 优先从 ~/.kiro-device-id 读取，不存在则生成 32 位 hex 并写入
    fn read_or_generate_device_id() -> String {
        let home = dirs_path();
        let path = home.join(".kiro-device-id");

        // 尝试读取
        if let Ok(content) = fs::read_to_string(&path) {
            let id = content.trim().to_string();
            if !id.is_empty() {
                return id;
            }
        }

        // 生成新的 device ID（32 位 hex）
        let id: String = (0..32)
            .map(|_| format!("{:x}", fastrand::u8(..16)))
            .collect();

        // 尝试写入（失败不影响使用）
        if let Err(e) = fs::write(&path, &id) {
            tracing::warn!("写入设备 ID 文件失败: {}", e);
        }

        id
    }
}

/// RSA 公钥解密（等价于 Node.js crypto.publicDecrypt）
///
/// 执行原始 RSA 操作：m = c^e mod n，然后去除 PKCS#1 v1.5 type 1 padding
/// 这是 RSA 签名验证的底层操作，用于恢复被私钥加密的数据
fn rsa_public_decrypt(public_key: &RsaPublicKey, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let n = public_key.n();
    let e = public_key.e();
    let key_len = (n.bits() + 7) / 8;

    if ciphertext.len() != key_len as usize {
        anyhow::bail!(
            "RSA 密文长度错误: {} (期望 {})",
            ciphertext.len(),
            key_len
        );
    }

    // 原始 RSA：m = c^e mod n
    let c = BigUint::from_bytes_be(ciphertext);
    let m = c.modpow(e, n);
    let mut m_bytes = m.to_bytes_be();

    // 左侧补零到 key_len
    while m_bytes.len() < key_len as usize {
        m_bytes.insert(0, 0);
    }

    // 去除 PKCS#1 v1.5 type 1 padding: 0x00 0x01 [0xFF...] 0x00 [data]
    if m_bytes.len() < 11 || m_bytes[0] != 0x00 || m_bytes[1] != 0x01 {
        anyhow::bail!("RSA PKCS#1 v1.5 padding 格式错误");
    }

    // 跳过 0xFF 填充字节，找到 0x00 分隔符
    let mut i = 2;
    while i < m_bytes.len() && m_bytes[i] == 0xFF {
        i += 1;
    }

    if i >= m_bytes.len() || m_bytes[i] != 0x00 {
        anyhow::bail!("RSA PKCS#1 v1.5 padding 缺少 0x00 分隔符");
    }

    // 分隔符之后就是原始数据
    Ok(m_bytes[i + 1..].to_vec())
}

/// 获取用户 home 目录
fn dirs_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("C:\\Users\\Default"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"))
    }
}
