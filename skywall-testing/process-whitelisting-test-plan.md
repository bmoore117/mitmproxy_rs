# Network Policy Test Plan

This plan validates `network-policy.sample.json` with local redirect mode and hot reload.

## Scope

- Validate application traffic that fails due to remote port connections not surviving redirection succeed when process whitelisted

## Prerequisites

- Built stack with your current `mitmproxy_rs` changes.
- Admin/root privileges for local redirect mode.
- A test host with internet access.
- NordVPN PC install

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
4. Exit mitmproxy, log in to NordVPN

## Test Matrix

## T1: Connect unwhitelisted NordVPN while proxy running

- Action: With NordVPN open and logged in, launch `mitmproxy --mode local`, and then attempt to connect NordVPN
- Expected:
  - Connection fails

## T2: 

- Action:
  - Add NordVPN to whitelisted processes in config
  - Attempt to connect
- Expected:
  - Connection succeeds

## Pass Criteria

- T1 and T2 as expected
