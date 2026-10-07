use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Capture {
    #[default]
    Manual,
    System,
    Tun,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub capture: Capture,
    pub mixed_port: u16,
    pub allow_lan: bool,
    pub auto_dns: bool,
    pub tun_interface: Option<String>,
    pub theme: String,
    pub launch_at_login: bool,
    pub auto_connect: bool,
    pub subscription_interval_hours: u16,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            capture: Capture::Manual,
            mixed_port: 7890,
            allow_lan: false,
            auto_dns: true,
            tun_interface: None,
            theme: "system".into(),
            launch_at_login: false,
            auto_connect: false,
            subscription_interval_hours: 24,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.mixed_port >= 1024, "代理端口必须在 1024–65535 之间");
        ensure!(
            ["light", "dark", "system"].contains(&self.theme.as_str()),
            "无效主题"
        );
        ensure!(
            self.subscription_interval_hours <= 720,
            "订阅更新间隔不能超过 720 小时"
        );
        ensure!(
            self.tun_interface
                .as_ref()
                .is_none_or(|s| s.len() <= 64 && !s.contains('\0')),
            "无效网络接口"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_takes_over_system_dns_unless_turned_off() {
        assert!(Settings::default().auto_dns);
        let saved: Settings = serde_json::from_str(r#"{"capture":"tun"}"#).unwrap();
        assert!(saved.auto_dns);
        let off: Settings = serde_json::from_str(r#"{"autoDns":false}"#).unwrap();
        assert!(!off.auto_dns);
    }
}
