# Network Policy Test Plan

This plan validates `network-policy.sample.json` with local redirect mode and hot reload.

## Scope

- Validate process/path blocking (`blocked_paths`)
- Validate port blocking (`block_udp_ports`, `block_tcp_ports`)
- Validate baseline usability (normal traffic not on blocked signals)
- Validate live policy reload behavior

## Prerequisites

- Built stack with your current `mitmproxy_rs` changes.
- Admin/root privileges for local redirect mode.
- A test host with internet access.
- Optional tools for proxy testing:
  - SOCKS/HTTP proxy app (for example Clash/V2Ray/Proxifier/Charles/Fiddler/Burp)
  - VPN client (for example WireGuard/OpenVPN/Tailscale)

## Setup

1. Set env var to the active policy file path (either point directly to `network-policy.sample.json` or a copied `network-policy.json`):
   - Windows PowerShell (session):
     - `$env:MITMPROXY_NETWORK_POLICY_PATH = "C:\Users\User\Code\mitmproxy_rs\network-policy.json"`
   - Linux/macOS shell (session):
     - `export MITMPROXY_NETWORK_POLICY_PATH="/path/to/mitmproxy_rs/network-policy.json"`
2. Start mitmproxy local mode:
   - `mitmdump --mode local`
3. Confirm startup log contains:
   - `Network block policy watcher loaded ...`

## Test Matrix

## T1: Baseline direct browsing

- Action: Open browser and access normal HTTPS sites.
- Expected:
  - Most normal traffic succeeds.
  - No broad blocking for non-matching process/path/ports.

## T2: Process blocking (path substring)

- Action:
  - Start a known VPN or proxy app listed in `blocked_paths` (for example NordVPN/WireGuard/OpenVPN/Tailscale/Clash/Proxifier/Charles/Fiddler/Burp).
  - Trigger network activity (for example VPN connect or proxy request).
- Expected:
  - Connection attempts fail quickly or app behavior indicates blocked networking.
  - Decision logs show `reason=block_path` for that process.

## T3: UDP port blocking

- Action: Generate UDP traffic to blocked VPN-like ports (for example 51820, 500, 4500).
- Expected:
  - Traffic is blocked.
  - Decision logs show `reason=block_port`.
  - `udp-sample-traffic-test.ps1` can be used to generate traffic to a UDP port blocked in `network-policy.sample.json`

## T4: TCP port blocking

- Action:
  - Route a TCP request through a blocked destination port (for example 1080/3128/7890/8080/9090).
  - `portquiz.net` is a convenient target for non-standard port checks (for example `http://portquiz.net:9090/`).
- Expected:
  - Requests fail or connection reset/closed behavior is observed.
  - Decision logs show `reason=block_port`.

## T5: Configuration reload behavior (NordVPN flow)

1. Launch `mitmdump --mode local` using the sample configuration (`network-policy.sample.json`) as the active policy file.
2. Launch NordVPN.
3. Click **Log in**.
   - Expected:
     - App spins/fails to complete login initiation.
     - Decision logs show drop entries with `reason=block_path` for the NordVPN process (same style as other intercept decision logs).
4. Exit NordVPN, then blank out the policy file contents and save.
5. Relaunch NordVPN and attempt to log in again.
   - Expected:
     - Reload occurs after save.
     - Login initiation proceeds (blocking behavior stops with empty policy semantics).

## T6: Invalid JSON resilience

- Action: Introduce malformed JSON, save file.
- Expected:
  - Warning log: invalid network block policy.
  - Previously loaded valid policy remains active.

## Optional Exception Tests

If you intentionally use exceptions:

- `blocked_pid_exceptions`:
  - Add active blocked PID to exception list.
  - Expected `reason=blocked_pid_exception` and traffic allowed.
- `blocked_cidr_exceptions`:
  - Add destination CIDR that overlaps blocked ranges.
  - Expected `reason=blocked_cidr_exception` and traffic allowed.

## Troubleshooting

- No reload events:
  - Re-check `MITMPROXY_NETWORK_POLICY_PATH` path and file permissions.
- Too many false positives:
  - Remove broad port entries first (for example 8080/9090).
  - Prefer process/path rules over port-only blocking.
- No blocks at all:
  - Confirm file is valid JSON and `enabled` is `true`.
  - Confirm expected process path actually contains one of `blocked_paths` tokens.

## Pass Criteria

- VPN and proxy attempts are blocked in representative scenarios.
- Normal browsing remains functional enough for your target environment.
- Hot reload works for valid updates, and invalid updates do not crash or clear policy unintentionally.
