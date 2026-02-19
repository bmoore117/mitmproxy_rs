use anyhow::{Context, anyhow, ensure};
use ipnet::IpNet;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::{LazyLock, RwLock};

pub type PID = u32;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: PID,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct DropDecision {
    pub drop: bool,
    pub reason: &'static str,
    pub log: bool,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct InterceptConf {
    default: bool,
    actions: Vec<Action>,
}

#[derive(PartialEq, Eq, Debug, Clone)]
enum Action {
    Include(Pattern),
    Exclude(Pattern),
}

#[derive(PartialEq, Eq, Debug, Clone)]
enum Pattern {
    Pid(PID),
    Process(String),
}

impl Pattern {
    #[inline(always)]
    fn matches(&self, process_info: &ProcessInfo) -> bool {
        match self {
            Pattern::Pid(pid) => process_info.pid == *pid,
            Pattern::Process(name) => process_info
                .process_name
                .as_ref()
                .map(|n| {
                    #[cfg(windows)]
                    {
                        n.to_ascii_lowercase().contains(&name.to_ascii_lowercase())
                    }
                    #[cfg(not(windows))]
                    {
                        n.contains(name)
                    }
                })
                .unwrap_or(false),
        }
    }
}

impl TryFrom<&str> for InterceptConf {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let val = value.trim();
        if val.is_empty() {
            return Ok(InterceptConf::new(vec![]));
        }
        let actions: Vec<&str> = val.split(',').collect();
        InterceptConf::try_from(actions).map_err(|_| anyhow!("invalid intercept spec: {value}"))
    }
}

impl<T: AsRef<str>> TryFrom<Vec<T>> for InterceptConf {
    type Error = anyhow::Error;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        let actions = value
            .into_iter()
            .map(|a| Action::try_from(a.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(InterceptConf::new(actions))
    }
}

impl TryFrom<&str> for Action {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value.trim();
        if let Some(value) = value.strip_prefix('!') {
            Ok(Action::Exclude(Pattern::try_from(value)?))
        } else {
            Ok(Action::Include(Pattern::try_from(value)?))
        }
    }
}

impl TryFrom<&str> for Pattern {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value.trim();
        ensure!(!value.is_empty(), "pattern must not be empty");
        Ok(match value.parse::<PID>() {
            Ok(pid) => Pattern::Pid(pid),
            Err(_) => Pattern::Process(value.to_string()),
        })
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Include(pat) => write!(f, "{pat}"),
            Action::Exclude(pat) => write!(f, "!{pat}"),
        }
    }
}

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pattern::Pid(pid) => write!(f, "{pid}"),
            Pattern::Process(name) => write!(f, "{name}"),
        }
    }
}

impl InterceptConf {
    fn new(actions: Vec<Action>) -> Self {
        let default = matches!(actions.first(), Some(Action::Exclude(_)));
        Self { default, actions }
    }

    pub fn disabled() -> Self {
        Self::new(vec![])
    }

    pub fn actions(&self) -> Vec<String> {
        self.actions.iter().map(|a| a.to_string()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    pub fn default(&self) -> bool {
        self.default
    }

    pub fn should_intercept(&self, process_info: &ProcessInfo) -> bool {
        let mut intercept = self.default;
        for action in &self.actions {
            match action {
                Action::Include(pattern) => {
                    intercept = intercept || pattern.matches(process_info);
                }
                Action::Exclude(pattern) => {
                    intercept = intercept && !pattern.matches(process_info);
                }
            }
        }
        intercept
    }

    pub fn description(&self) -> String {
        if self.actions.is_empty() {
            return "Intercept nothing.".to_string();
        }
        let parts: Vec<String> = self
            .actions
            .iter()
            .map(|a| match a {
                Action::Include(Pattern::Pid(pid)) => format!("Include PID {pid}."),
                Action::Include(Pattern::Process(name)) => {
                    format!("Include processes matching \"{name}\".")
                }
                Action::Exclude(Pattern::Pid(pid)) => format!("Exclude PID {pid}."),
                Action::Exclude(Pattern::Process(name)) => {
                    format!("Exclude processes matching \"{name}\".")
                }
            })
            .collect();
        parts.join(" ")
    }
}

static INTERCEPT_CONF_STATE: LazyLock<RwLock<InterceptConf>> =
    LazyLock::new(|| RwLock::new(InterceptConf::disabled()));
static STARTUP_INTERCEPT_CONF_STATE: LazyLock<RwLock<Option<InterceptConf>>> =
    LazyLock::new(|| RwLock::new(None));

#[derive(Debug, Clone)]
pub struct NetworkBlockPolicy {
    pub enabled: bool,
    pub blocked_paths: Vec<String>,
    pub block_udp_ports: Vec<u16>,
    pub block_tcp_ports: Vec<u16>,
    pub block_remote_cidrs: Vec<IpNet>,
    pub blocked_cidr_exceptions: Vec<IpNet>,
    pub log_decisions: bool,
}

#[derive(Debug, Deserialize)]
struct RawConfigDocument {
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    blocked_paths: Vec<String>,
    #[serde(default)]
    whitelisted_paths: Vec<String>,
    #[serde(default)]
    block_udp_ports: Vec<u16>,
    #[serde(default)]
    block_tcp_ports: Vec<u16>,
    #[serde(default)]
    block_remote_cidrs: Vec<String>,
    #[serde(default)]
    blocked_cidr_exceptions: Vec<String>,
    #[serde(default = "default_log_decisions")]
    log_decisions: bool,
}

fn default_enabled() -> bool {
    true
}

fn default_log_decisions() -> bool {
    true
}

impl NetworkBlockPolicy {
    fn from_raw(raw: &RawConfigDocument) -> Result<Self, anyhow::Error> {
        Ok(Self {
            enabled: raw.enabled,
            blocked_paths: normalize_patterns(raw.blocked_paths.clone()),
            block_udp_ports: raw.block_udp_ports.clone(),
            block_tcp_ports: raw.block_tcp_ports.clone(),
            block_remote_cidrs: parse_cidrs(raw.block_remote_cidrs.clone(), "block_remote_cidrs")?,
            blocked_cidr_exceptions: parse_cidrs(
                raw.blocked_cidr_exceptions.clone(),
                "blocked_cidr_exceptions",
            )?,
            log_decisions: raw.log_decisions,
        })
    }

    fn evaluate(
        &self,
        transport: Transport,
        dst_addr: SocketAddr,
        info: &ProcessInfo,
    ) -> Option<DropDecision> {
        if !self.enabled {
            return None;
        }

        if is_safety_exempt(info.process_name.as_deref()) {
            return Some(DropDecision {
                drop: false,
                reason: "safety_exempt",
                log: self.log_decisions,
            });
        }

        if ip_in_any_cidr(dst_addr.ip(), &self.blocked_cidr_exceptions) {
            return Some(DropDecision {
                drop: false,
                reason: "blocked_cidr_exception",
                log: self.log_decisions,
            });
        }

        if matches_any_process(info.process_name.as_deref(), &self.blocked_paths) {
            return Some(DropDecision {
                drop: true,
                reason: "block_path",
                log: self.log_decisions,
            });
        }

        if ip_in_any_cidr(dst_addr.ip(), &self.block_remote_cidrs) {
            return Some(DropDecision {
                drop: true,
                reason: "block_cidr",
                log: self.log_decisions,
            });
        }

        let blocked_port = match transport {
            Transport::Tcp => self.block_tcp_ports.contains(&dst_addr.port()),
            Transport::Udp => self.block_udp_ports.contains(&dst_addr.port()),
        };
        if blocked_port {
            return Some(DropDecision {
                drop: true,
                reason: "block_port",
                log: self.log_decisions,
            });
        }

        None
    }
}

static NETWORK_BLOCK_POLICY_STATE: LazyLock<RwLock<Option<NetworkBlockPolicy>>> =
    LazyLock::new(|| RwLock::new(None));

pub fn set_intercept_conf(conf: InterceptConf) {
    if let Ok(mut guard) = INTERCEPT_CONF_STATE.write() {
        *guard = conf;
    }
}

pub fn set_startup_intercept_conf(conf: InterceptConf) {
    if let Ok(mut guard) = STARTUP_INTERCEPT_CONF_STATE.write()
        && guard.is_none()
    {
        *guard = Some(conf);
    }
}

pub fn get_intercept_conf() -> InterceptConf {
    INTERCEPT_CONF_STATE
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_else(|_| InterceptConf::disabled())
}

pub fn load_config_document(value: &str) -> Result<InterceptConf, anyhow::Error> {
    let value = value.trim();
    if value.is_empty() {
        // An empty policy file intentionally means "allow everything" for network
        // drop checks while preserving the startup redirector interception spec.
        set_network_block_policy(None);
        let conf = prepend_startup_intercept_conf(InterceptConf::disabled());
        set_intercept_conf(conf.clone());
        return Ok(conf);
    }

    let raw: RawConfigDocument =
        serde_json::from_str(value).context("failed to parse config JSON document")?;
    let policy = NetworkBlockPolicy::from_raw(&raw)?;
    let intercept_conf = prepend_startup_intercept_conf(build_redirector_intercept_conf(&raw)?);
    set_network_block_policy(Some(policy));
    set_intercept_conf(intercept_conf.clone());
    Ok(intercept_conf)
}

pub fn set_network_block_policy(policy: Option<NetworkBlockPolicy>) {
    if let Ok(mut guard) = NETWORK_BLOCK_POLICY_STATE.write() {
        *guard = policy;
    }
}

pub fn decide_drop(transport: Transport, dst_addr: SocketAddr, info: &ProcessInfo) -> DropDecision {
    if let Ok(policy_guard) = NETWORK_BLOCK_POLICY_STATE.read()
        && let Some(policy) = policy_guard.as_ref()
        && let Some(decision) = policy.evaluate(transport, dst_addr, info)
    {
        return decision;
    }

    DropDecision {
        drop: false,
        reason: "default_allow",
        log: false,
    }
}

fn normalize_patterns(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect()
}

fn normalize_intercept_patterns(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|v| v.trim().trim_start_matches('!').to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

fn build_redirector_intercept_conf(raw: &RawConfigDocument) -> Result<InterceptConf, anyhow::Error> {
    let actions = normalize_intercept_patterns(raw.whitelisted_paths.clone())
        .into_iter()
        .map(|pattern| format!("!{pattern}"))
        .collect::<Vec<_>>();
    InterceptConf::try_from(actions).context("failed to build redirector intercept configuration")
}

fn prepend_startup_intercept_conf(conf: InterceptConf) -> InterceptConf {
    let policy_actions = conf.actions.clone();

    let Some(startup_conf) = STARTUP_INTERCEPT_CONF_STATE
        .read()
        .ok()
        .and_then(|guard| guard.clone())
    else {
        log::info!(
            "No startup intercept config available, using policy intercept config only (policy_actions={policy_actions:?})."
        );
        return conf;
    };

    let startup_actions = startup_conf.actions.clone();
    let mut actions = startup_conf.actions;
    actions.extend(conf.actions);
    let effective_actions = actions.clone();
    log::info!(
        "Composed intercept config from startup + policy (startup_actions={startup_actions:?}, policy_actions={policy_actions:?}, effective_actions={effective_actions:?})."
    );
    InterceptConf::new(actions)
}

fn parse_cidrs(values: Vec<String>, field: &str) -> Result<Vec<IpNet>, anyhow::Error> {
    values
        .into_iter()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(|raw| {
            raw.parse::<IpNet>()
                .with_context(|| format!("{field} contains invalid CIDR: {raw}"))
        })
        .collect()
}

fn matches_any_process(process_name: Option<&str>, patterns: &[String]) -> bool {
    let Some(process_name) = process_name else {
        return false;
    };
    let haystack = process_name.to_ascii_lowercase();
    patterns.iter().any(|needle| haystack.contains(needle))
}

fn ip_in_any_cidr(ip: IpAddr, cidrs: &[IpNet]) -> bool {
    cidrs.iter().any(|cidr| cidr.contains(&ip))
}

fn is_safety_exempt(process_name: Option<&str>) -> bool {
    let Some(name) = process_name else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    ["mitmproxy", "mitmdump", "mitmweb"]
        .iter()
        .any(|needle| name.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intercept_conf() {
        let a = ProcessInfo {
            pid: 1,
            process_name: Some("a".into()),
        };
        let b = ProcessInfo {
            pid: 2242,
            process_name: Some("mitmproxy".into()),
        };

        let conf = InterceptConf::try_from("1,2,3").unwrap();
        assert!(conf.should_intercept(&a));
        assert!(!conf.should_intercept(&b));

        let conf = InterceptConf::try_from("").unwrap();
        assert!(!conf.should_intercept(&a));
        assert!(!conf.should_intercept(&b));
        assert_eq!(conf, InterceptConf::disabled());

        let conf = InterceptConf::try_from("!1234").unwrap();
        assert!(conf.should_intercept(&a));
        assert!(conf.should_intercept(&b));

        let conf = InterceptConf::try_from("mitm").unwrap();
        assert!(!conf.should_intercept(&a));
        assert!(conf.should_intercept(&b));

        #[cfg(windows)]
        {
            let p = ProcessInfo {
                pid: 101,
                process_name: Some(
                    "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".into(),
                ),
            };
            let conf =
                InterceptConf::try_from("!c:\\windows\\system32\\windowspowershell\\v1.0").unwrap();
            assert!(!conf.should_intercept(&p));
        }

        assert!(InterceptConf::try_from(",,").is_err());
    }

    #[test]
    fn test_json_document_loading_and_decision() {
        let doc = r#"{
            "enabled": true,
            "block_udp_ports": [51820],
            "block_remote_cidrs": ["10.0.0.0/8"],
            "blocked_paths": ["wireguard"],
            "log_decisions": false
        }"#;

        let conf = load_config_document(doc).unwrap();
        assert!(conf.default());
        let info = ProcessInfo {
            pid: 9000,
            process_name: Some("wireguard.exe".into()),
        };
        let decision = decide_drop(Transport::Udp, "1.1.1.1:51820".parse().unwrap(), &info);
        assert!(decision.drop);
        assert_eq!(decision.reason, "block_path");
    }

    #[test]
    fn test_json_document_whitelisted_paths_to_intercept_conf() {
        let doc = r#"{
            "enabled": true,
            "whitelisted_paths": ["steam.exe", "C:\\Program Files (x86)\\Steam\\"]
        }"#;

        let conf = load_config_document(doc).unwrap();
        let steam = ProcessInfo {
            pid: 1000,
            process_name: Some("C:\\Program Files (x86)\\Steam\\steam.exe".into()),
        };
        let chrome = ProcessInfo {
            pid: 1001,
            process_name: Some("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe".into()),
        };

        assert!(!conf.should_intercept(&steam));
        assert!(conf.should_intercept(&chrome));
    }
}
