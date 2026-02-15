use crate::intercept_conf::{ProcessInfo, Transport, decide_drop};
use crate::messages::TunnelInfo;
use std::net::SocketAddr;

const INTERCEPT_TRACE_TAG: &str = "[INTERCEPT_TRACE]";

pub(crate) fn should_drop(
    tunnel_info: &TunnelInfo,
    transport: Transport,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
) -> bool {
    let TunnelInfo::LocalRedirector {
        pid, process_name, ..
    } = tunnel_info
    else {
        return false;
    };

    if pid.is_none() && process_name.is_none() {
        return false;
    }

    let info = ProcessInfo {
        pid: pid.unwrap_or(0),
        process_name: process_name.clone(),
    };

    let decision = decide_drop(transport, dst_addr, &info);
    if decision.log {
        log::info!(
            "{INTERCEPT_TRACE_TAG} Unified policy decision: drop={} reason={} transport={:?} src={} dst={} pid={:?} process={:?}",
            decision.drop,
            decision.reason,
            transport,
            src_addr,
            dst_addr,
            pid,
            process_name
        );
    }
    decision.drop
}
