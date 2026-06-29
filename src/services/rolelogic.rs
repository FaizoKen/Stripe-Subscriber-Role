use std::time::Duration;

use crate::error::AppError;

/// Hard cap for a single `PUT /users` request (server-side limit).
const PUT_MAX_USERS: usize = 100_000;
/// Per-chunk cap for the chunked upload flow (server-side limit).
const CHUNK_SIZE: usize = 100_000;
/// Per-request timeout for a single chunk POST.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(120);
/// Per-request timeout for the commit POST.
const COMMIT_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Body substring RoleLogic returns when our token isn't found server-side.
/// Convention 47: this signals the role link was deleted upstream; the caller
/// must clean up the local row, not retry forever.
const RL_LINK_GONE_ERROR_MSG: &str = "Invalid or revoked token";
/// Body substring RoleLogic returns when the role link exists but its owner
/// toggled it off. NOT a deletion (that is `RL_LINK_GONE_ERROR_MSG`): leave the
/// link + config intact and skip syncing it this cycle instead of erroring and
/// retrying forever. Source: `role-link-token.guard.ts`.
const RL_LINK_DISABLED_ERROR_MSG: &str = "This role link is disabled";

#[derive(Clone)]
pub struct RoleLogicClient {
    http: reqwest::Client,
    base_url: String,
}

impl RoleLogicClient {
    pub fn new(base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Get user count and limit for a role link.
    pub async fn get_user_info(
        &self,
        guild_id: &str,
        role_id: &str,
        token: &str,
    ) -> Result<(usize, usize), AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users",
            self.base_url, guild_id, role_id
        );

        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_GONE_ERROR_MSG) {
                return Err(AppError::RoleLinkNotFound);
            }
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_DISABLED_ERROR_MSG)
            {
                return Err(AppError::RoleLinkDisabled);
            }
            return Err(AppError::RoleLogic(format!(
                "Get user info failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        let user_count = body["data"]["user_count"].as_u64().unwrap_or(0) as usize;
        let user_limit = body["data"]["user_limit"].as_u64().unwrap_or(100) as usize;

        Ok((user_count, user_limit))
    }

    pub async fn add_user(
        &self,
        guild_id: &str,
        role_id: &str,
        user_id: &str,
        token: &str,
    ) -> Result<bool, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/{}",
            self.base_url, guild_id, role_id, user_id
        );

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_GONE_ERROR_MSG) {
                return Err(AppError::RoleLinkNotFound);
            }
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_DISABLED_ERROR_MSG)
            {
                return Err(AppError::RoleLinkDisabled);
            }

            if (status == reqwest::StatusCode::BAD_REQUEST
                || status == reqwest::StatusCode::FORBIDDEN)
                && body.contains("limit")
            {
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                let limit = parsed["data"]["user_limit"].as_u64().unwrap_or(100) as usize;
                return Err(AppError::UserLimitReached { limit });
            }

            return Err(AppError::RoleLogic(format!(
                "Add user failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        Ok(body["data"]["added"].as_bool().unwrap_or(false))
    }

    pub async fn remove_user(
        &self,
        guild_id: &str,
        role_id: &str,
        user_id: &str,
        token: &str,
    ) -> Result<bool, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/{}",
            self.base_url, guild_id, role_id, user_id
        );

        let resp = self
            .http
            .delete(&url)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_GONE_ERROR_MSG) {
                return Err(AppError::RoleLinkNotFound);
            }
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_DISABLED_ERROR_MSG)
            {
                return Err(AppError::RoleLinkDisabled);
            }
            return Err(AppError::RoleLogic(format!(
                "Remove user failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        Ok(body["data"]["removed"].as_bool().unwrap_or(false))
    }

    /// Replace the full user set in a single atomic `PUT /users` request.
    /// Server rejects anything over `PUT_MAX_USERS`. For larger sets, callers
    /// should use [`upload_users`] which routes to the chunked flow.
    pub async fn replace_users(
        &self,
        guild_id: &str,
        role_id: &str,
        user_ids: &[String],
        token: &str,
    ) -> Result<usize, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users",
            self.base_url, guild_id, role_id
        );

        let resp = self
            .http
            .put(&url)
            .header("Authorization", format!("Token {token}"))
            .json(user_ids)
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_GONE_ERROR_MSG) {
                return Err(AppError::RoleLinkNotFound);
            }
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_DISABLED_ERROR_MSG)
            {
                return Err(AppError::RoleLinkDisabled);
            }
            return Err(AppError::RoleLogic(format!(
                "Replace users failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        Ok(body["data"]["user_count"].as_u64().unwrap_or(0) as usize)
    }

    /// High-level user-set upload. Picks the right transport for the size:
    /// - `len <= 100_000`: single atomic `PUT /users`.
    /// - `len > 100_000`: chunked flow (init → chunks → commit).
    ///
    /// Returns the deduped `user_count` reported by the server.
    pub async fn upload_users(
        &self,
        guild_id: &str,
        role_id: &str,
        user_ids: &[String],
        token: &str,
    ) -> Result<usize, AppError> {
        if user_ids.len() <= PUT_MAX_USERS {
            return self.replace_users(guild_id, role_id, user_ids, token).await;
        }

        let total = user_ids.len();
        tracing::info!(
            guild_id,
            role_id,
            total,
            "Bulk user set exceeds PUT cap; using chunked upload"
        );

        let upload_id = self.start_upload(guild_id, role_id, token).await?;
        let chunk_count = user_ids.chunks(CHUNK_SIZE).count();

        for (i, chunk) in user_ids.chunks(CHUNK_SIZE).enumerate() {
            if let Err(e) = self
                .upload_chunk(guild_id, role_id, &upload_id, chunk, token)
                .await
            {
                tracing::error!(
                    guild_id,
                    role_id,
                    upload_id,
                    chunk_idx = i,
                    chunk_count,
                    "Chunk upload failed; cancelling session: {e}"
                );
                if let Err(cancel_err) = self
                    .cancel_upload(guild_id, role_id, &upload_id, token)
                    .await
                {
                    tracing::warn!(
                        guild_id,
                        role_id,
                        upload_id,
                        "Cancel after chunk failure also failed: {cancel_err}"
                    );
                }
                return Err(e);
            }
        }

        let final_count = self
            .commit_upload(guild_id, role_id, &upload_id, token)
            .await?;
        tracing::info!(
            guild_id,
            role_id,
            upload_id,
            chunks = chunk_count,
            final_count,
            "Chunked upload committed"
        );
        Ok(final_count)
    }

    /// Step 1: open a chunked-upload session. Returns the `upload_id`.
    pub async fn start_upload(
        &self,
        guild_id: &str,
        role_id: &str,
        token: &str,
    ) -> Result<String, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/upload",
            self.base_url, guild_id, role_id
        );

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_GONE_ERROR_MSG) {
                return Err(AppError::RoleLinkNotFound);
            }
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_DISABLED_ERROR_MSG)
            {
                return Err(AppError::RoleLinkDisabled);
            }
            return Err(AppError::RoleLogic(format!(
                "Start upload failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        body["data"]["upload_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| AppError::RoleLogic("Start upload response missing upload_id".into()))
    }

    /// Step 2: append a chunk (≤ `CHUNK_SIZE` user IDs) to an open session.
    pub async fn upload_chunk(
        &self,
        guild_id: &str,
        role_id: &str,
        upload_id: &str,
        user_ids: &[String],
        token: &str,
    ) -> Result<(), AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/upload/{}/chunk",
            self.base_url, guild_id, role_id, upload_id
        );

        let resp = self
            .http
            .post(&url)
            .timeout(CHUNK_TIMEOUT)
            .header("Authorization", format!("Token {token}"))
            .json(user_ids)
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::RoleLogic(format!(
                "Upload chunk failed: {status} - {body}"
            )));
        }

        Ok(())
    }

    /// Step 3: commit a chunked upload. Server dedupes across chunks and
    /// atomically swaps in the new user set. Returns the final user_count.
    pub async fn commit_upload(
        &self,
        guild_id: &str,
        role_id: &str,
        upload_id: &str,
        token: &str,
    ) -> Result<usize, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/upload/{}/commit",
            self.base_url, guild_id, role_id, upload_id
        );

        let resp = self
            .http
            .post(&url)
            .timeout(COMMIT_TIMEOUT)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::RoleLogic(format!(
                "Commit upload failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        Ok(body["data"]["user_count"].as_u64().unwrap_or(0) as usize)
    }

    /// Cancel an open upload session (best-effort cleanup on failure).
    pub async fn cancel_upload(
        &self,
        guild_id: &str,
        role_id: &str,
        upload_id: &str,
        token: &str,
    ) -> Result<(), AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/upload/{}",
            self.base_url, guild_id, role_id, upload_id
        );

        let resp = self
            .http
            .delete(&url)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::RoleLogic(format!(
                "Cancel upload failed: {status} - {body}"
            )));
        }

        Ok(())
    }
}
