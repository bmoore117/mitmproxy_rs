use crate::intercept_conf::{get_intercept_conf, ProcessInfo};
use crate::messages::TunnelInfo;

pub(crate) fn should_drop(tunnel_info: &TunnelInfo) -> bool {
    let TunnelInfo::LocalRedirector {
        pid,
        process_name,
        ..
    } = tunnel_info
    else {
        return false;
    };

    let conf = get_intercept_conf();
    if conf.is_empty() {
        return false;
    }

    if pid.is_none() && process_name.is_none() {
        return false;
    }

    let info = ProcessInfo {
        pid: pid.unwrap_or(0),
        process_name: process_name.clone(),
    };

    let intercept = conf.should_intercept(&info);
    log::info!(
        "Local redirect decision: intercept={} pid={:?} process={:?} actions={:?}",
        intercept,
        pid,
        process_name,
        conf.actions()
    );
    !intercept
}
