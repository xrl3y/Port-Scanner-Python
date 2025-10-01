#!/usr/bin/env python3
"""
Fast TCP Port Scanner (corrected & commented)

Usage examples:
  python3 scanner.py -t 192.168.1.1 -p 1-100
  python3 scanner.py -t example.com -p 22,80,443 -T 0.5 -w 50

This script:
 - Parses command-line args (target, ports)
 - Creates multiple threads to try TCP connects
 - Attempts a minimal HTTP HEAD when a TCP connection succeeds (to show a banner)
 - Prints open ports (and a first response line when available)
 - Handles Ctrl+C gracefully and closes open sockets
"""

import socket
import argparse
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import partial

# Optional colored output. If termcolor is not installed we fallback to a no-op.
try:
    from termcolor import colored
except Exception:
    def colored(text, _color=None):
        return text

# Global list of open sockets so the SIGINT handler can close them cleanly.
open_sockets = []

def sigint_handler(sig, frame):
    """
    SIGINT handler to close sockets and exit gracefully when user presses Ctrl+C.
    """
    print(colored("\n[!] Exiting program (SIGINT received)...", "red"))
    # Close any sockets we left open
    for s in list(open_sockets):
        try:
            s.close()
        except Exception:
            pass
        try:
            open_sockets.remove(s)
        except ValueError:
            pass
    sys.exit(1)

# Register the handler for Ctrl+C
signal.signal(signal.SIGINT, sigint_handler)


def get_arguments():
    """
    Parse CLI arguments for target, ports, timeout, and worker count.
    Returns: (target, ports_str, timeout, workers)
    """
    parser = argparse.ArgumentParser(description="Fast TCP Port Scanner")
    parser.add_argument(
        "-t", "--target",
        dest="target",
        required=True,
        help="Target host to scan (IP or hostname), e.g. -t 192.168.1.1"
    )
    parser.add_argument(
        "-p", "--port",
        dest="port",
        required=True,
        help="Ports to scan: single (80), comma list (22,80), or range (1-1024)"
    )
    parser.add_argument(
        "-T", "--timeout",
        dest="timeout",
        required=False,
        type=float,
        default=1.0,
        help="Socket timeout in seconds (default: 1.0)"
    )
    parser.add_argument(
        "-w", "--workers",
        dest="workers",
        required=False,
        type=int,
        default=100,
        help="Number of concurrent worker threads (default: 100)"
    )

    opts = parser.parse_args()
    return opts.target, opts.port, opts.timeout, opts.workers


def parse_ports(ports_str):
    """
    Convert a ports string into an iterable of ints.
    Supported formats:
      - "80" -> [80]
      - "22,80,443" -> [22,80,443]
      - "1-1024" -> range(1,1025)
    Returns a list or range (iterable) of ints.
    """
    s = ports_str.strip()
    if "-" in s:
        # Split once in case there are accidental extra '-' characters
        a, b = s.split("-", 1)
        start, end = int(a.strip()), int(b.strip())
        # Use range with end+1 because range end is exclusive
        return range(start, end + 1)
    elif "," in s:
        parts = [p.strip() for p in s.split(",") if p.strip()]
        return [int(p) for p in parts]
    else:
        return [int(s)]


def create_socket(timeout):
    """
    Create a TCP socket (IPv4), set timeout and register it in open_sockets.
    The returned socket should be closed by the caller (or in finally).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    open_sockets.append(s)
    return s


def port_scanner(port, host, timeout):
    """
    Try to connect to (host, port). If successful, optionally send a minimal HTTP
    HEAD to get a response line. Print results accordingly.

    Important: always close the socket in the finally clause and remove it from
    the global open_sockets list to prevent resource leakage.
    """
    s = create_socket(timeout)
    try:
        # Attempt to establish TCP connection
        s.connect((host, port))
        # If connect doesn't raise, port is open
        # Try a simple HEAD request to get a banner if it's an HTTP-like service
        response_line = ""
        try:
            # Some services will close if they don't like the payload; wrap in try/except
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            raw = s.recv(1024)
            # decode safely and get the first non-empty line
            text = raw.decode(errors="ignore")
            # splitlines is better than split('\n') because it handles different endings
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            if lines:
                response_line = lines[0]
        except Exception:
            # If the send/recv fails, we still know the TCP port is open
            response_line = ""

        # Print open port
        print(colored(f"\n[+] Port {port} is open", "green"))
        if response_line:
            print(colored(f"    {response_line}", "grey"))

    except (ConnectionRefusedError, socket.timeout, OSError):
        # ConnectionRefused -> port closed; socket.timeout -> no response in time.
        # OSError covers other cases (e.g., network unreachable). We ignore these
        # because we only print open ports.
        return
    finally:
        # Always close the socket and remove it from the global list
        try:
            s.close()
        except Exception:
            pass
        try:
            open_sockets.remove(s)
        except ValueError:
            pass


def scan_ports(ports, target, timeout, workers):
    """
    Launch a ThreadPoolExecutor and scan the provided ports concurrently.

    We use executor.map with two iterables: ports and a repeated target value.
    Using functools.partial or lambda also works; here we use partial + map.
    """
    # Convert ports iterable to a list so we can get its length and iterate it multiple times
    ports_list = list(ports)

    if not ports_list:
        print("[!] No ports to scan.")
        return

    # Use a reasonable worker count; too many threads can hurt performance
    max_workers = min(workers, len(ports_list))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Create a partial function binding host and timeout, leaving port as the first arg
        func = partial(port_scanner, host=target, timeout=timeout)
        # executor.map will pass each port in ports_list to func(port)
        executor.map(func, ports_list)


def main():
    """
    Main program flow:
    - Parse arguments
    - Parse ports string
    - Call scan_ports with the chosen concurrency and timeout
    """
    target, ports_str, timeout, workers = get_arguments()
    ports = parse_ports(ports_str)
    print(colored(f"[i] Scanning {target} ports: {ports_str} (timeout={timeout}s, workers={workers})", "cyan"))
    scan_ports(ports, target, timeout, workers)
    print(colored("\n[i] Scan finished.", "cyan"))


if __name__ == "__main__":
    main()

