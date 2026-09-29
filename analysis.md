
Here’s what the log shows, from the end of the file back to the first semaphore error.

---

## Summary: Error Timeline and Likely Causes

### 1. **First semaphore error (WinError 121)**

**Location:** Line 22803 at **02:27:59.448**

**Context:** About 15 connections that had been opened at **02:27:38.413–422** (ports 62887–62902) all hit the semaphore timeout at the same time. They were trying to reach **92.38.145.145:80**.

### 2. **Errors before the first semaphore timeout**

- **02:27:40.952** – `[WinError 1225] The remote computer refused the network connection` (client 62897)
- **02:27:41.331** – Same `[WinError 1225]` (client 62887)
- **02:27:56.808** – Same `[WinError 1225]` (client 62967)

So the first semaphore errors were preceded by **WinError 1225** (connection refused).

### 3. **Critical failure: redirect daemon**

**Location:** Line 100106 at **10:48:44.538**

```
[10:48:44.538] Task failed: redirect daemon exited prematurely.
disabled backtrace
[10:48:44.781][192.168.8.242:61065] error establishing server connection: [WinError 121] The semaphore timeout period has expired
```

This is the most important event for traffic stopping. The **redirect daemon** (which handles SkyWall’s redirect logic) exited unexpectedly, and semaphore errors immediately follow.

### 4. **Unhandled asyncio error**

**Location:** Lines 27738–27741 at **04:32:14.016**

```
[04:32:14.016] Unhandled error in task.
Traceback (most recent call last):
  File "asyncio\events.py", line 88, in _run
  File "asyncio\proactor_events.py", line 165, in _call_connection_lost
ConnectionAbortedError: [WinError 10053] An established connection was aborted by the software in your host machine
```

This suggests a connection was abruptly closed by something on the host (e.g. firewall, antivirus, or another process).

### 5. **Log statistics**

- **361** semaphore errors (WinError 121)
- **26** WinError 1225 errors

---

## Likely causes and sequence

1. **WinError 1225** – Remote servers refused connections (e.g. rate limiting, overload, or firewall blocking).
2. **WinError 121 (semaphore timeout)** – Windows TCP/IP stack waited too long for a connection. Typical causes:
   - Network congestion
   - Overloaded remote servers
   - Too many connections in flight
3. **Redirect daemon failure** – The redirect daemon crashed or exited unexpectedly. The log shows “disabled backtrace” and no detailed traceback. After this, traffic through the proxy likely stopped even though the process kept running.
4. **WinError 10053** – Connection aborted by local software on the host, often related to firewall or antivirus.

---

## Why the process stays running but traffic stops

The redirect daemon is a separate task that handles redirecting traffic through the proxy. When it exits with “redirect daemon exited prematurely,” the main mitmdump process can keep running, but the redirect logic is broken.

So traffic stops because:

- The redirect daemon is no longer running.
- New connections fail with semaphore timeouts.
- New traffic is not being routed through the proxy.

---

## Recommendations

1. **Restart mitmdump** – Restarting the process will bring the redirect daemon back.
2. **Check firewall/antivirus** – Temporarily exclude mitmdump or its ports to rule out WinError 10053.
3. **Monitor connection load** – If the semaphore errors correlate with many connections (e.g. 92.38.145.145), consider reducing load or connection limits.
4. **Enable backtraces** – If possible, enable the full backtrace for the redirect daemon so you can see why it exited.
5. **Watch for long-lived connections** – The log shows “Closing connection due to inactivity” around 04:32:13; long idle sessions may have contributed to the state before the daemon failure.

If you share the exact mitmdump command and SkyWall config you use, I can suggest concrete changes to reduce these errors.