use std::env;

#[derive(Clone, Debug)]
pub struct DbPoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_secs: u64,
    pub idle_timeout_secs: u64,
}

impl DbPoolConfig {
    fn from_env() -> Self {
        Self {
            max_connections: env::var("DB_MAX_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(16),
            min_connections: env::var("DB_MIN_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2),
            acquire_timeout_secs: env::var("DB_ACQUIRE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            idle_timeout_secs: env::var("DB_IDLE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(600),
        }
    }
}

#[derive(Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub session_secret: String,
    pub base_url: String,
    pub listen_addr: String,
    /// Base URL of the Auth Gateway (no trailing slash, no `/auth` suffix).
    pub auth_gateway_url: String,
    /// Shared secret for plugin → gateway /auth/internal/* calls.
    pub internal_api_key: String,
    /// Origin allowed to embed this plugin in an iframe (the dashboard origin).
    pub rl_dashboard_origin: Option<String>,
    /// Base URL of the RoleLogic API used by `RoleLogicClient`. No trailing slash.
    pub rolelogic_api_url: String,
    /// Stripe API base. Override only for testing against a mock server.
    pub stripe_api_base: String,
    /// How many job-polling worker tasks to spawn.
    pub worker_concurrency: u32,
    pub db_pool: DbPoolConfig,
}

/// Extract the origin (scheme://host[:port]) from BASE_URL, dropping any path.
pub(crate) fn derive_origin(base_url: &str) -> String {
    if let Some(scheme_end) = base_url.find("://") {
        let after_scheme = scheme_end + 3;
        if let Some(path_slash) = base_url[after_scheme..].find('/') {
            return base_url[..after_scheme + path_slash].to_string();
        }
    }
    base_url.to_string()
}

impl AppConfig {
    pub fn from_env() -> Self {
        let base_url = env::var("BASE_URL").expect("BASE_URL must be set");
        let auth_gateway_url = env::var("AUTH_GATEWAY_URL")
            .ok()
            .map(|s| s.trim_end_matches('/').to_string())
            .unwrap_or_else(|| derive_origin(&base_url));

        Self {
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
            session_secret: env::var("SESSION_SECRET").expect("SESSION_SECRET must be set"),
            base_url,
            listen_addr: env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8096".to_string()),
            auth_gateway_url,
            internal_api_key: env::var("INTERNAL_API_KEY")
                .expect("INTERNAL_API_KEY must be set (must match the Auth Gateway's value)"),
            rl_dashboard_origin: env::var("RL_DASHBOARD_ORIGIN")
                .ok()
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| Some("https://rolelogic.faizo.net".to_string())),
            rolelogic_api_url: env::var("ROLELOGIC_API_URL")
                .ok()
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "https://api-rolelogic.faizo.net".to_string()),
            stripe_api_base: env::var("STRIPE_API_BASE")
                .ok()
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| crate::services::stripe::DEFAULT_API_BASE.to_string()),
            worker_concurrency: env::var("WORKER_CONCURRENCY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4),
            db_pool: DbPoolConfig::from_env(),
        }
    }
}
