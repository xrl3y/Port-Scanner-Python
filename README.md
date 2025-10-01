# Fast TCP Port Scanner

A compact, multi-threaded TCP port scanner written in Python.  
This repository contains a small, configurable scanner that attempts TCP connections to a target host, optionally probes open ports with a minimal HTTP `HEAD` request to capture a banner/first-response line, prints results with optional colored output, and cleans up sockets gracefully on Ctrl+C.

---

## Table of contents
- [Description](#description)  
- [Features](#features)  
- [Requirements](#requirements)  
- [Usage](#usage)  
- [Command-line options](#command-line-options)  
- [How it works (implementation notes)](#how-it-works-implementation-notes)  
- [Examples](#examples)  
- [Troubleshooting & common issues](#troubleshooting--common-issues)
- [Author](#author)
- [License](#license)   

---

## Description
This project provides a fast, multi-threaded TCP port scanner implemented in Python. It is designed as an educational tool and a lightweight utility for authorized security testing. The scanner supports scanning single ports, comma-separated lists of ports, and port ranges. When a TCP connection is successful, the scanner can send a minimal HTTP `HEAD` probe to retrieve a first-line banner (useful for identifying HTTP-like services). The script is configurable (timeout, worker threads) and includes graceful SIGINT handling to close open sockets when the user aborts the scan.

---

## Features
- Concurrent scanning using `ThreadPoolExecutor`.
- Accepts:
  - Single port (e.g. `80`)
  - Comma-separated ports (e.g. `22,80,443`)
  - Ranges (e.g. `1-1024`)
- Minimal HTTP `HEAD` probe for open TCP ports to capture service banners.
- Configurable socket timeout and number of worker threads.
- Colored output using `termcolor` (falls back to plain text if the library is not present).
- Graceful Ctrl+C handling (closes open sockets and exits cleanly).
- Simple, dependency-light implementation suitable for study and modification.

---

## Requirements
- Python 3.6+
- (Optional) `termcolor` for colored console output:
  
```bash
pip install termcolor
```

---

## Usage

```bash
python3 scanner.py -t <target> -p <ports> [-T <timeout>] [-w <workers>]
```

Quick examples

- Scan ports 1–100 on 192.168.1.1:

```bash
python3 scanner.py -t 192.168.1.1 -p 1-100
```

- Scan ports 22, 80, and 443 on example.com with a shorter timeout and fewer workers:

```bash
python3 scanner.py -t example.com -p 22,80,443 -T 0.5 -w 50
```

---

## Command-line options

-t, --target — Target host to scan (IP or hostname). Required.

-p, --port — Ports to scan. Accepts a single port (80), a comma-separated list (22,80,443), or a range (1-1024). Required.

-T, --timeout — Socket timeout in seconds (float). Default: 1.0.

-w, --workers — Number of concurrent worker threads. Default: 100. Lower this if your machine or network handles fewer threads well.

---

## How it works (implementation notes)

Argument parsing: The script uses argparse to read the target, the port specification, timeout, and worker count.

1. Port parsing: The given -p string is parsed into an iterable of integer port numbers. Ranges produce Python range objects (end inclusive handled correctly).

2. Socket creation: For each attempted connection, the script creates an IPv4 TCP socket with the configured timeout and registers it in a global list (open_sockets) so the SIGINT handler can close them.

3. Connection attempt: The port_scanner routine calls connect((host, port)). If the connection succeeds, the port is considered open.

4. Optional banner probe: After a successful TCP handshake, the scanner attempts to send a minimal HEAD / HTTP/1.0\r\n\r\n payload and reads up to 1024 bytes to capture a first response line when possible. This is optional and best-effort — many services will not respond to an HTTP probe, and that’s fine.

5. Concurrency: A ThreadPoolExecutor runs multiple port_scanner tasks concurrently. The worker count is adjustable.

6. Cleanup & SIGINT: Pressing Ctrl+C triggers a signal handler that closes all open sockets in open_sockets and exits cleanly, preventing lingering file descriptors.

7. Output: The scanner prints only open ports (and the banner line if available) for noise minimization. Coloring is optional (uses termcolor if present).

---

## Examples 

(sample output)

```python

[i] Scanning 192.168.1.1 ports: 1-100 (timeout=1.0s, workers=100)

[+] Port 22 is open
    SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
[+] Port 80 is open
    HTTP/1.1 200 OK
[i] Scan finished.
```

---

## Troubleshooting & common issues

- Permission errors: Regular TCP scans do not require root, but some environments restrict raw sockets or have firewall rules. Ensure the host running the scan has normal network privileges.
- False negatives / timeouts: If many ports appear closed, try increasing the -T timeout. Networks with latency or packet loss require higher timeouts.
- Too many threads: If your system becomes unresponsive or you see many socket errors, lower -w (workers) to a more conservative number (e.g., 20–50).
- termcolor missing: If colored output is missing, install termcolor (pip install termcolor) or accept the fallback to plain text.
- Unicode/banner decoding errors: Banner decoding uses errors="ignore" to avoid crashes from non-UTF8 bytes. This may drop some characters but preserves stability.

If you encounter an error, include the exact command you ran and the full traceback/output so the issue can be diagnosed.

---

## Author

This project was developed by **xrl3y**.

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

--- 


## License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

