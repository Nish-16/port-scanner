"""
Port-Scanner V4 - a multithreaded TCP connect port scanner with basic,
port-number-based service inference and simple banner grabbing.

For learning purposes only. Only scan machines you own or have
explicit permission to test.
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Our own file (services.py, next to this one): port number -> likely service.
from services import COMMON_SERVICES


DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1024
DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 100
MIN_PORT = 1
MAX_PORT = 65535
MIN_THREADS = 1
MAX_THREADS = 1000

# Banner grabbing settings.
MAX_BANNER_BYTES = 1024     # read at most this much from a service
MAX_BANNER_LENGTH = 80      # show at most this many characters
HTTP_PORTS = {80, 8000, 8080}   # client speaks first: we send a HEAD request
TLS_PORTS = {443}               # encrypted: V4 does not speak TLS, so it skips these
NO_BANNER = "No banner"
TLS_BANNER_UNAVAILABLE = "Banner unavailable (TLS)"


def parse_arguments() -> argparse.Namespace:
    """Read the target, port range, timeout and thread count from the command line."""
    parser = argparse.ArgumentParser(
        description="Basic TCP connect port scanner (V4, multithreaded, likely-service lookup, banner grabbing)."
    )
    parser.add_argument("target", help="hostname or IPv4 address to scan")
    parser.add_argument(
        "--start",
        type=int,
        default=DEFAULT_START_PORT,
        help=f"first port to scan (default: {DEFAULT_START_PORT})",
    )
    parser.add_argument(
        "--end",
        type=int,
        default=DEFAULT_END_PORT,
        help=f"last port to scan (default: {DEFAULT_END_PORT})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"seconds to wait for each connection (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"number of worker threads, {MIN_THREADS}-{MAX_THREADS} (default: {DEFAULT_THREADS})",
    )
    return parser.parse_args()


def validate_arguments(start_port: int, end_port: int, timeout: float, threads: int) -> str:
    """Return an error message if the input is invalid, or an empty string if it is fine."""
    if start_port < MIN_PORT or start_port > MAX_PORT:
        return f"start port must be between {MIN_PORT} and {MAX_PORT}."
    if end_port < MIN_PORT or end_port > MAX_PORT:
        return f"end port must be between {MIN_PORT} and {MAX_PORT}."
    if start_port > end_port:
        return "start port cannot be greater than end port."
    if timeout <= 0:
        return "timeout must be greater than 0."
    if threads < MIN_THREADS or threads > MAX_THREADS:
        return f"threads must be between {MIN_THREADS} and {MAX_THREADS}."
    return ""


def resolve_target(target: str) -> str:
    """Turn a hostname (or IP string) into an IPv4 address.

    Raises socket.gaierror if the name cannot be resolved.
    """
    return socket.gethostbyname(target)


def scan_port(target_ip: str, port: int, timeout: float) -> tuple[int, bool]:
    """Try a TCP connection to one port. Return (port, is_open).

    The port number is returned too, because results from worker threads
    arrive in whatever order they finish, not in port order.
    """
    # AF_INET = IPv4, SOCK_STREAM = TCP.
    # The "with" block closes the socket automatically when it ends.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        # connect_ex returns 0 on success, or an error code instead of
        # raising an exception (e.g. "connection refused" or a timeout).
        result = sock.connect_ex((target_ip, port))
    is_open = result == 0
    return port, is_open


def guess_service(port: int) -> str:
    """Return the service commonly associated with this port, or "UNKNOWN".

    This is only an educated guess based on the port number. It does not
    talk to the service, so it cannot confirm what is really running.
    """
    return COMMON_SERVICES.get(port, "UNKNOWN")


def scan_ports(target_ip: str, start_port: int, end_port: int, timeout: float, threads: int) -> list[int]:
    """Phase 1 - TCP discovery.

    Scan every port from start_port to end_port (inclusive) using a pool of
    threads and return a sorted list of the open ports.

    Workers only scan and return a result. Only this (main) thread
    touches the open_ports list, so no lock is needed.
    """
    open_ports = []
    executor = ThreadPoolExecutor(max_workers=threads)
    try:
        # Hand one scan_port task per port to the pool. submit() returns
        # immediately with a Future: a placeholder for the result.
        futures = []
        for port in range(start_port, end_port + 1):
            future = executor.submit(scan_port, target_ip, port, timeout)
            futures.append(future)

        # as_completed gives us each Future as soon as its task finishes,
        # in finishing order (not port order).
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    finally:
        # Normal finish: every task is already done, so this returns quickly.
        # Ctrl+C: cancel the ports that have not started yet, then wait for
        # the few that are running (at most `timeout` seconds) so their
        # sockets are closed before we exit.
        executor.shutdown(wait=True, cancel_futures=True)

    open_ports.sort()
    return open_ports


def clean_banner(data: bytes) -> str:
    """Turn raw bytes from a service into one short, safe, printable line."""
    # Network data is bytes. errors="replace" turns invalid UTF-8 into a
    # replacement symbol instead of raising UnicodeDecodeError.
    text = data.decode("utf-8", errors="replace")

    # Keep only printable ASCII characters of each line:
    # - control characters (tabs, escape codes, bells...) are dropped, so a
    #   remote service cannot mess with our terminal;
    # - any non-ASCII character becomes "?", because some terminals (e.g. a
    #   redirected Windows console using cp1252) cannot print it and would crash.
    lines = []
    for line in text.splitlines():
        printable_line = ""
        for char in line:
            if not char.isascii():
                printable_line += "?"
            elif char.isprintable():
                printable_line += char
        printable_line = printable_line.strip()
        if printable_line:
            lines.append(printable_line)

    # Show multi-line responses (like HTTP headers) on one line.
    banner = " | ".join(lines)
    if len(banner) > MAX_BANNER_LENGTH:
        banner = banner[:MAX_BANNER_LENGTH - 3] + "..."
    if banner == "":
        return NO_BANNER
    return banner


def grab_banner(target_ip: str, port: int, timeout: float) -> tuple[int, str]:
    """Connect to an OPEN port, read a small response and return (port, banner).

    Any failure (timeout, reset, nothing sent...) just means "No banner";
    one unusual service must never stop the scan.
    """
    if port in TLS_PORTS:
        # The service expects an encrypted TLS handshake first. V4 keeps
        # things simple and does not speak TLS.
        return port, TLS_BANNER_UNAVAILABLE

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target_ip, port))

            if port in HTTP_PORTS:
                # HTTP servers wait for the client to speak first. HEAD asks
                # only for the response headers, never the page itself.
                request = f"HEAD / HTTP/1.0\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
                sock.sendall(request.encode("ascii"))

            # Server-speaks-first services (like SSH) send their banner right
            # after connecting. One recv() of at most MAX_BANNER_BYTES is enough.
            data = sock.recv(MAX_BANNER_BYTES)
    except OSError:
        # Includes timeouts (TimeoutError is a subclass of OSError).
        return port, NO_BANNER

    return port, clean_banner(data)


def grab_banners(target_ip: str, open_ports: list[int], timeout: float, threads: int) -> list[tuple[int, str]]:
    """Phase 2 - application-level interaction.

    Grab a banner from every OPEN port using a pool of threads and return a
    sorted list of (port, banner). Closed ports are never contacted again.
    """
    banners = []
    executor = ThreadPoolExecutor(max_workers=threads)
    try:
        futures = []
        for port in open_ports:
            future = executor.submit(grab_banner, target_ip, port, timeout)
            futures.append(future)

        for future in as_completed(futures):
            port, banner = future.result()
            banners.append((port, banner))
    finally:
        # Same clean-up rule as scan_ports (see there).
        executor.shutdown(wait=True, cancel_futures=True)

    # Tuples sort by their first item, so this sorts by port number.
    banners.sort()
    return banners


def is_real_banner(banner: str) -> bool:
    """True if the banner text came from the service (not one of our placeholders)."""
    return banner != NO_BANNER and banner != TLS_BANNER_UNAVAILABLE


def print_header(target: str, target_ip: str, start_port: int, end_port: int, timeout: float, threads: int) -> None:
    print("=" * 40)
    print("TCP PORT SCANNER V4".center(40))
    print("=" * 40)
    print(f"Target: {target}")
    print(f"IP: {target_ip}")
    print(f"Port range: {start_port}-{end_port}")
    print(f"Timeout: {timeout}s")
    print(f"Threads: {threads}")
    print()
    print("Scanning...")
    print()


def print_summary(ports_scanned: int, results: list[tuple[int, str, str]], elapsed: float) -> None:
    """Print one row per open port: (port, likely_service, banner), then totals."""
    banners_found = 0
    if len(results) == 0:
        print("No open ports found.")
    else:
        # LIKELY SERVICE comes from our lookup table (port number only).
        # BANNER comes from the service itself.
        print(f"{'PORT':<9}{'STATE':<11}{'LIKELY SERVICE':<19}BANNER")
        print("-" * 64)
        for port, service, banner in results:
            print(f"{port:<9}{'OPEN':<11}{service:<19}{banner}")
            if is_real_banner(banner):
                banners_found += 1
    print()
    print("-" * 40)
    print("Scan complete")
    print(f"Ports scanned: {ports_scanned}")
    print(f"Open ports: {len(results)}")
    print(f"Banners found: {banners_found}")
    print(f"Time taken: {elapsed:.2f} seconds")
    print("-" * 40)


def main() -> None:
    args = parse_arguments()

    error_message = validate_arguments(args.start, args.end, args.timeout, args.threads)
    if error_message:
        print(f"Error: {error_message}", file=sys.stderr)
        sys.exit(1)

    try:
        target_ip = resolve_target(args.target)
    except socket.gaierror:
        print(f"Error: could not resolve hostname '{args.target}'.", file=sys.stderr)
        sys.exit(1)

    print_header(args.target, target_ip, args.start, args.end, args.timeout, args.threads)

    start_time = time.perf_counter()
    try:
        # Phase 1: which ports accept a TCP connection?
        open_ports = scan_ports(target_ip, args.start, args.end, args.timeout, args.threads)

        # Phase 2: ask only the OPEN ports for a banner.
        if len(open_ports) > 0:
            print(f"Grabbing banners from {len(open_ports)} open port(s)...")
            print()
        banners = grab_banners(target_ip, open_ports, args.timeout, args.threads)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(1)
    except OSError as error:
        # Closed ports do NOT end up here (connect_ex returns an error code
        # for those). This only catches unexpected problems, such as the
        # system running out of sockets or no network being available.
        print(f"Error: unexpected socket error: {error}", file=sys.stderr)
        sys.exit(1)
    elapsed = time.perf_counter() - start_time

    # Combine the three kinds of information for each open port.
    results = []
    for port, banner in banners:
        results.append((port, guess_service(port), banner))

    ports_scanned = args.end - args.start + 1
    print_summary(ports_scanned, results, elapsed)


if __name__ == "__main__":
    main()
