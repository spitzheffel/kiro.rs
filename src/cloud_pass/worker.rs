//! Cloud Pass 后台刷新任务

use std::sync::Arc;
use std::time::Duration;

use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::token_manager::MultiTokenManager;
use crate::model::config::CloudPassConfig;

use super::client::CloudPassClient;
use super::state::CloudPassState;

/// 启动 Cloud Pass 后台刷新任务
///
/// 定时从 eskysoft 服务器获取凭证并注入到 token_manager
pub async fn start_cloud_pass_worker(
    token_manager: Arc<MultiTokenManager>,
    config: CloudPassConfig,
    state: CloudPassState,
) {
    let client = CloudPassClient::new(&config);
    let interval = Duration::from_secs(config.refresh_interval);
    let reassign = config.reassign;

    tracing::info!("Cloud Pass 后台刷新任务启动");
    tracing::info!("  服务器: {}", config.server_url);
    tracing::info!("  设备 ID: {}", client.device_id());
    tracing::info!("  刷新间隔: {}s", config.refresh_interval);
    tracing::info!(
        "  激活码: {}***",
        &config.license_code[..config.license_code.len().min(6)]
    );

    // 等待 5 秒让 kiro-rs 完成初始化
    tokio::time::sleep(Duration::from_secs(5)).await;

    loop {
        match do_refresh(&client, &token_manager, reassign, &state, &config).await {
            Ok(()) => {
                tracing::info!("Cloud Pass 凭证刷新成功");
            }
            Err(e) => {
                state.record_failure(&e.to_string());
                tracing::error!("Cloud Pass 凭证刷新失败: {}", e);
            }
        }

        // 心跳保活（失败不影响主流程）
        if let Err(e) = client.heartbeat().await {
            tracing::warn!("Cloud Pass 心跳失败: {}", e);
        }

        // 等待定时刷新或手动刷新信号
        let notify = state.wait_for_refresh();
        tokio::select! {
            _ = tokio::time::sleep(interval) => {},
            _ = notify.notified() => {
                tracing::info!("Cloud Pass 收到手动刷新请求");
            },
        }
    }
}

/// 执行一次凭证刷新
async fn do_refresh(
    client: &CloudPassClient,
    token_manager: &MultiTokenManager,
    reassign: bool,
    state: &CloudPassState,
    config: &CloudPassConfig,
) -> anyhow::Result<()> {
    // 获取凭证
    let creds = client.get_credentials(reassign).await?;

    // 检查 kicked 状态
    if creds.kicked {
        state.record_kicked();
        tracing::warn!("Cloud Pass: 当前设备已被踢出");
        if reassign {
            tracing::info!("Cloud Pass: 尝试重新抢占...");
            client.claim_active().await?;
            // 重新获取凭证
            let creds = client.get_credentials(true).await?;
            if creds.kicked {
                anyhow::bail!("重新抢占后仍被踢出，请检查激活码");
            }
            return inject_credentials(client, token_manager, &creds, state, config).await;
        }
        anyhow::bail!("设备已被踢出，启用 reassign 可自动抢占");
    }

    if let Some(ref expires) = creds.license_expires_at {
        tracing::info!("Cloud Pass license 有效至: {}", expires);
    }

    inject_credentials(client, token_manager, &creds, state, config).await
}

/// 将凭证注入到 token_manager
async fn inject_credentials(
    client: &CloudPassClient,
    token_manager: &MultiTokenManager,
    creds: &super::model::ResolvedCredentials,
    state: &CloudPassState,
    config: &CloudPassConfig,
) -> anyhow::Result<()> {
    let refresh_token = creds
        .refresh_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("服务器未返回 refreshToken"))?;

    // 构建完整的 KiroCredentials，写入所有字段
    let new_cred = KiroCredentials {
        id: None,
        access_token: creds.access_token.clone(),
        refresh_token: Some(refresh_token.clone()),
        profile_arn: creds.profile_arn.clone(),
        expires_at: creds.expires_at.clone(),
        auth_method: Some("idc".to_string()),
        client_id: creds.client_id.clone(),
        client_secret: creds.client_secret.clone(),
        priority: 0,
        region: creds.region.clone(),
        auth_region: None,
        api_region: None,
        machine_id: config.machine_id.clone().or_else(|| Some(client.device_id().to_string())), // 优先使用配置的固定 machineId，否则用 deviceId
        email: None,
        subscription_title: None,
        proxy_url: None,
        proxy_username: None,
        proxy_password: None,
        disabled: false,
    };

    // 日志（脱敏）
    tracing::info!(
        "Cloud Pass 凭证: accessToken={}***, refreshToken={}***, region={}, profileArn={}",
        creds
            .access_token
            .as_deref()
            .unwrap_or("N/A")
            .get(..8)
            .unwrap_or("N/A"),
        refresh_token.get(..8).unwrap_or("N/A"),
        creds.region.as_deref().unwrap_or("N/A"),
        creds.profile_arn.as_deref().unwrap_or("N/A"),
    );

    // 通过 token_manager 注入（与 Admin API 相同路径）
    match token_manager.add_credential(new_cred).await {
        Ok(id) => {
            tracing::info!("Cloud Pass 凭证已注入，ID: {}", id);
            state.record_success(
                Some(id),
                creds.license_expires_at.clone(),
                creds.kicked,
            );
            // 主动获取订阅等级
            if let Err(e) = token_manager.get_usage_limits_for(id).await {
                tracing::warn!("获取订阅等级失败（不影响使用）: {}", e);
            }
            Ok(())
        }
        Err(e) => {
            let err_msg = e.to_string();
            // refreshToken 重复 = 凭证没变，不需要注入
            if err_msg.contains("重复") || err_msg.contains("duplicate") {
                tracing::info!("Cloud Pass 凭证未变化，跳过注入");
                state.record_success(
                    None,
                    creds.license_expires_at.clone(),
                    creds.kicked,
                );
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}
