# Port-Scanner

## 1. Project

A basic **TCP connect port scanner** written in Python. Give it a hostname or IPv4
address and a range of ports; it tries to open a TCP connection to each port and
reports which ports are **open**.

**Current version: V4** – a multithreaded TCP connect scanner (V2) that shows the
service *commonly associated* with each open port (V3) and tries to read a short
**banner** from each open service (see [V4 – Banner Grabbing](#v4--banner-grabbing)).

> Only scan machines you own or have explicit permission to test.
> `localhost` / `127.0.0.1` (your own computer) is always a safe target.

## 2. Why it exists

This is a learning project. The goal is to understand the foundations of network
reconnaissance by building them by hand:

- IP addresses and hostnames (and how one becomes the other)
- TCP and ports
- sockets and connection attempts
- timeouts
- what "open" vs "closed" actually means
- why scanning one port at a time is slow (V1)
- how threads speed up I/O-bound work (V2)
- the difference between an open port and the service running on it (V3)
- talking to a service and reading its banner, safely (V4)

The code is intentionally small and readable rather than feature-rich.

## 3. Technologies

- Python 3 (tested on Python 3.13, Windows 11)
- Python standard library only:
  - `socket` – create TCP sockets and attempt connections
  - `argparse` – read command-line arguments
  - `time` – measure how long the scan takes
  - `concurrent.futures` – `ThreadPoolExecutor` for running scans in parallel threads
  - `sys` – print errors to stderr and exit with a status code

Project files:

```
Port-Scanner/
├── scanner.py     the scanner (CLI, scanning, banner grabbing, output)
├── services.py    COMMON_SERVICES: common TCP port → likely service
├── README.md
├── .gitignore
└── progress/      one report per version (V1.md, V2.md, ...)
```

## 4. How it works

For **each port**, the scanner does this:

```
Target (e.g. "localhost")
  → IP resolution          socket.gethostbyname("localhost") → "127.0.0.1"
  → port range             e.g. 1 to 1024
  → TCP socket             socket.socket(AF_INET, SOCK_STREAM)
  → connection attempt     sock.connect_ex(("127.0.0.1", port))
  → result                 0 = OPEN, anything else = not open
  → if OPEN: likely service  COMMON_SERVICES.get(port, "UNKNOWN")   (V3)
  → if OPEN: banner          connect again, (send HEAD for HTTP), recv()   (V4)
  → next port
```

In V1 the ports were handled one after another. In V2 up to `--threads` ports are
handled at the same time (see [Multithreading](#multithreading-v2)). In V3 each
open port also gets a *likely* service name looked up from its port number.

**What does an open port mean?** A port is a number (1–65535) that identifies a
specific program on a computer. If a program is *listening* on a port, the
operating system will accept a TCP connection to it — the connection succeeds and
the port is **open**. If nothing is listening, the OS refuses the connection
(**closed**), or a firewall silently drops it and the attempt times out
(**filtered**). The scanner only distinguishes "open" from "not open".

## Multithreading (V2)

### Why V1 was slow

V1 scanned sequentially. Each port had to finish — or time out — before the next
one started:

```
port 1 → wait
port 2 → wait
port 3 → wait
...
```

Almost all of that time is spent **waiting for the network**, not computing.
The CPU sits idle. Scanning 1024 ports with a 1-second timeout took ~17 minutes
on Windows.

### What V2 does

Port scanning is **I/O-bound**: the work is mostly waiting for replies. While one
connection attempt is waiting, another thread can start a connection attempt on a
different port. The waits overlap instead of adding up:

```
port 1 ─┐
port 2 ─┤
port 3 ─┤
port 4 ─┤
         └→ concurrent scanning
```

Each port is independent (scanning port 80 does not depend on port 79), so they
can safely be scanned at the same time.

### ThreadPoolExecutor

```python
executor = ThreadPoolExecutor(max_workers=100)
```

creates a **pool** of up to 100 worker threads. We **submit** one `scan_port` task
per port to the pool. The tasks wait in a queue, and whenever a worker is free it
picks up the next task. So the pool *can* run up to 100 scans at once — it does not
guarantee exactly 100 active connections at every moment (for example, near the
end of a scan, or when there are fewer ports than workers). If you scan 3 ports
with 100 workers, only as many threads as needed are started.

`submit()` returns a **Future** – a placeholder for a result that will exist later.
`as_completed()` hands each Future back as soon as its task finishes.

### Collecting results safely

Workers **do not** touch a shared list. Each worker only returns `(port, is_open)`:

```
worker → scans one port → returns (port, is_open)
                              ↓
main thread → reads the result → adds open ports to its own list
```

Only the main thread ever modifies `open_ports`, so there is no shared mutable
state and no lock is needed.

Because threads finish in whatever order their network replies arrive, results can
come back as `445, 135, ...`. The open ports are **sorted** before printing, so the
output never depends on thread timing.

### Thread limit

`--threads` must be between **1 and 1000**. Each thread uses memory and each
running scan holds an open socket; thousands of threads would waste resources and
could hit operating-system limits. For a scanner that mostly waits on the network,
1000 concurrent attempts is already far more than enough for learning purposes.

### Ctrl+C

On Ctrl+C the scanner cancels all ports that have not started yet, waits for the
scans already running to finish (at most `--timeout` seconds) so their sockets are
closed, then prints `Scan interrupted by user.`

### V1 vs V2

| Feature | V1 | V2 |
|---------|----|----|
| TCP scanning | Yes | Yes |
| Sequential | Yes | No |
| Multithreading | No | Yes |
| Configurable timeout | Yes | Yes |
| Configurable port range | Yes | Yes |
| Configurable threads | No | Yes |
| Service detection | No | No |
| UDP | No | No |

V2 is still fundamentally the **same TCP connect scanner** – `scan_port()` does
exactly what it did in V1. The major change is **how the scanning work is
scheduled**: many ports at once instead of one at a time.

### Benchmark

Real results on Windows 11, Python 3.13, scanning `127.0.0.1`, ports 1–100,
`--timeout 1`:

| Threads | Time taken |
|---------|-----------:|
| 1       | 100.67 s   |
| 10      | 10.08 s    |
| 100     | 1.03 s     |

Full default range (1–1024) with 100 threads: **11.10 s** (V1: ~17 minutes).

The speedup here is almost exactly proportional because, on Windows, nearly every
closed port waits for the full timeout (see the note below), so every task takes
the same ~1 second. **That will not always be true.** Real performance depends on
network behavior, the operating system, the timeout, how the target responds,
firewalls, the thread count, and system resource limits. On a target that refuses
connections instantly, there is much less waiting to overlap, and adding threads
helps less.

## V3 – Service Detection

### The question each version answers

| Version | Question |
|---------|----------|
| V2 | *Is the port open?* |
| V3 | *What service is **commonly associated** with this open port?* |

"A port is open" and "a service is probably running on that port" are different
statements. V2 proves the first one (the TCP handshake succeeded). V3 adds an
educated guess about the second one.

### Ports vs services

- A **port** is a numbered endpoint (1–65535) on a machine. It is just a number
  the operating system uses to deliver a connection to the right program.
- A **service** is the application/protocol that is actually listening on that
  endpoint – e.g. an SSH server or a web server.

By **convention**, many services use a standard port:

```
22  → commonly SSH
80  → commonly HTTP
443 → commonly HTTPS
```

But the number itself does not prove anything. Any program can listen on any
port. An administrator can run SSH on port `2222`, and someone can run a game
server on port `80`. So port-based service detection is only an **inference**.

### How V3 does it

A dictionary, `COMMON_SERVICES`, maps well-known ports to the service commonly
associated with them. It started in V3 with 13 entries inside `scanner.py`:

| Port | Likely service | Port | Likely service |
|------|----------------|------|----------------|
| 21   | FTP            | 443  | HTTPS          |
| 22   | SSH            | 3306 | MySQL          |
| 23   | Telnet         | 5432 | PostgreSQL     |
| 25   | SMTP           | 6379 | Redis          |
| 53   | DNS            | 8080 | HTTP-Alt       |
| 80   | HTTP           |      |                |
| 110  | POP3           |      |                |
| 143  | IMAP           |      |                |

In V4 it moved to its own file, **`services.py`**, and grew to **92** commonly seen
TCP ports (grouped as classic Internet services, Windows, remote access, databases,
web, messaging, DevOps/monitoring and other). `scanner.py` imports it:

```python
from services import COMMON_SERVICES
```

Keeping the data in its own file means the list can grow without cluttering the
scanning code. It is still a curated list, not the full IANA registry (which has
thousands of entries), and UDP-only ports are left out.

After a port is found to be **open**, the main thread looks it up:

```python
COMMON_SERVICES.get(port, "UNKNOWN")
```

Ports not in the dictionary show `UNKNOWN`. Since V4 the list includes Windows
ports such as 135 (`MSRPC`) and 445 (`SMB`) – like every entry, these are
conventional associations, not confirmed identifications.

The scanning logic (`scan_port()`) is unchanged from V2. The lookup happens
**after** the scan, and **no extra network connection is made**.

### Why V3 is limited

V3 uses the port number to make a basic service guess. It does **not**
communicate with the service to confirm its identity.

For example, `8080 → HTTP-Alt` does not prove that HTTP is actually running there.
During testing, a plain test socket that speaks no protocol at all was opened on
port 8080, and V3 still labelled it `HTTP-Alt`, because it only looks at the
number.

More advanced service detection could inspect protocol responses or banners
(what the service says when you connect), but that is intentionally outside V3.

### V1 vs V2 vs V3

| Feature | V1 | V2 | V3 |
|---------|----|----|----|
| TCP connect scanning | Yes | Yes | Yes |
| Multithreading | No | Yes | Yes |
| Configurable threads | No | Yes | Yes |
| Likely service (from port number) | No | No | Yes |
| Confirms service by talking to it | No | No | No |
| Banner grabbing | No | No | No |
| UDP | No | No | No |

## V4 – Banner Grabbing

### How the versions build on each other

```
V1  Basic TCP scanning                 Is the port open?          (one at a time)
V2  Multithreaded scanning             Is the port open?          (many at once)
V3  Port-based service inference       What usually runs here?    (lookup table)
V4  Application-level banner grabbing  What does the service say? (real response)
```

### Networking layers (simplified)

```
IP                    127.0.0.1               which machine
 ↓
TCP                   reliable connection
 ↓
Port                  22                      which program on that machine
 ↓
Application protocol  SSH                     the "language" the program speaks
 ↓
Service response      SSH-2.0-OpenSSH_...     what the program actually says
```

V1–V3 only worked at the **TCP connection** level: can a connection be made?
V4 is the first version that interacts with the **application layer**: it reads
(and for HTTP, sends) actual protocol data.

### Port inference vs banner

| | Example | Where it comes from |
|---|---|---|
| **Port inference** (V3) | `8080 → HTTP-Alt` | Our own lookup table. The service was never asked. |
| **Banner** (V4) | `HTTP/1.0 200 OK \| Server: SimpleHTTP/0.6 ...` | Sent by the remote service itself. |

A banner is **stronger evidence** than a port number, because it comes from the
service. But it is still not absolute proof: services can hide their banner, fake
it, customise it, or send incomplete information.

The two are independent. During testing, an SSH-style test server on port 2222
showed `LIKELY SERVICE = UNKNOWN` but `BANNER = SSH-2.0-TestServer_1.0`.

### Server speaks first vs client speaks first

This is the most important V4 idea. Protocols have different conversation
patterns, so `connect()` + `recv()` does **not** work for every service.

**Server speaks first** (e.g. SSH, MySQL, FTP, SMTP): the service greets you as
soon as you connect.

```
connect()
   ↓
recv()
   ↓
SSH-2.0-OpenSSH_9.6
```

**Client speaks first** (e.g. HTTP): the server waits silently for a request.
Just calling `recv()` gets nothing until the timeout.

```
connect()
   ↓
send "HEAD / HTTP/1.0"
   ↓
recv()
   ↓
HTTP/1.0 200 OK
```

What V4 does:

| Port(s) | Behaviour |
|---|---|
| 80, 8000, 8080 | Send a minimal `HEAD / HTTP/1.0` request (headers only – no page download, no redirects), then read |
| 443 | Skipped: HTTPS expects an encrypted TLS handshake first. V4 does not speak TLS and shows `Banner unavailable (TLS)` |
| Everything else | Connect and read whatever the service sends first |

A client-speaks-first service on a port that is **not** in the HTTP list will
simply show `No banner`, because V4 never sends it anything.

### Bytes vs text

`recv()` returns **bytes**, not a Python string. Bytes have to be decoded to become
text – and not every service sends text (MySQL, for example, sends a binary
greeting packet). So the scanner decodes safely:

```python
data.decode("utf-8", errors="replace")   # invalid bytes become a replacement symbol, no crash
```

### Safe output

A banner is untrusted data from another machine. It can contain newlines, tabs,
terminal escape codes (e.g. `ESC[2J` clears the screen) or characters the
terminal cannot print. `clean_banner()`:

1. decodes the bytes safely,
2. keeps only printable ASCII characters (control characters are dropped,
   non-ASCII characters become `?`),
3. joins multiple lines with ` | ` so each banner fits on one row,
4. trims whitespace and cuts the result to 80 characters.

Keeping only ASCII matters on Windows: during testing, printing a banner that
contained `�` crashed the scanner with `UnicodeEncodeError` when output was
redirected (the console used the `cp1252` encoding). Restricting output to ASCII
fixed that.

At most 1024 bytes are read from any service.

### Timeouts

Banner grabbing **reuses `--timeout`**. A silent service would otherwise make
`recv()` wait forever; with the timeout, it just shows `No banner`. A separate
`--banner-timeout` option was not added: one timeout is simpler, and the default
(1 s) suits both steps.

### Two phases

```
Phase 1 – TCP discovery (thread pool)     scan_port() for every port in the range
      ↓
open ports only (sorted)
      ↓
Phase 2 – banner grabbing (thread pool)   grab_banner() for each OPEN port
      ↓
likely service (lookup table) + banner
      ↓
sorted table
```

Closed ports are **never** contacted a second time. Each phase uses its own thread
pool, one after the other (no nested pools). Every banner socket is opened in a
`with` block, so it is always closed. Any error during banner grabbing (timeout,
reset, nothing sent) just becomes `No banner` – one odd service cannot stop the
scan. Ctrl+C works in both phases.

### Cost of banner grabbing

Real measurements on this machine (localhost, real services only):

| Range | Timeout | Threads | Open ports | V3 time | V4 time | Banners |
|---|---|---|---|---|---|---|
| 1–1024 | 1.0 s | 100 | 2 | 11.11 s | 12.12 s | 0 |
| 1–65535 | 0.2 s | 500 | 47 | 28.47 s | 28.74 s | 2 |

V4 is **not** faster – it does more work. Because banners are grabbed in parallel,
the extra time is roughly **one timeout** (silent services wait for it), not one
timeout per open port.

### V1 vs V2 vs V3 vs V4

| Feature | V1 | V2 | V3 | V4 |
|---------|----|----|----|----|
| TCP connect scanning | Yes | Yes | Yes | Yes |
| Multithreading | No | Yes | Yes | Yes |
| Likely service (port number) | No | No | Yes | Yes |
| Talks to the service | No | No | No | Yes (minimal) |
| Banner grabbing | No | No | No | Yes |
| HTTPS/TLS banners | No | No | No | No |
| Version / vulnerability detection | No | No | No | No |
| UDP | No | No | No | No |

## 5. Installation

No external packages are required. Just check that Python 3 is installed:

```
python --version
```

## 6. Usage

```
python scanner.py localhost
python scanner.py 127.0.0.1 --start 1 --end 1024
python scanner.py localhost --start 20 --end 100 --timeout 0.5
python scanner.py 127.0.0.1 --start 1 --end 1000 --threads 100
python scanner.py localhost --start 1 --end 1000 --threads 50
```

| Argument    | Meaning                                   | Default |
|-------------|-------------------------------------------|---------|
| `target`    | hostname or IPv4 address (required)       | –       |
| `--start`   | first port to scan                        | 1       |
| `--end`     | last port to scan                         | 1024    |
| `--timeout` | seconds to wait for each connection       | 1.0     |
| `--threads` | number of worker threads (1–1000)         | 100     |

Press **Ctrl+C** at any time to stop the scan.

## 7. Example output

```
> python scanner.py localhost
========================================
          TCP PORT SCANNER V4
========================================
Target: localhost
IP: 127.0.0.1
Port range: 1-1024
Timeout: 1.0s
Threads: 100

Scanning...

Grabbing banners from 2 open port(s)...

PORT     STATE      LIKELY SERVICE     BANNER
----------------------------------------------------------------
135      OPEN       MSRPC              No banner
445      OPEN       SMB                No banner

----------------------------------------
Scan complete
Ports scanned: 1024
Open ports: 2
Banners found: 0
Time taken: 12.14 seconds
----------------------------------------
```

Selected rows from a scan with **local test listeners** (small Python test servers,
not real services) plus one **real** local MySQL server:

```
PORT     STATE      LIKELY SERVICE     BANNER
----------------------------------------------------------------
22       OPEN       SSH                SSH-2.0-TestServer_1.0                       (test listener)
443      OPEN       HTTPS              Banner unavailable (TLS)                     (test listener)
2222     OPEN       UNKNOWN            SSH-2.0-TestServer_1.0                       (test listener)
3306     OPEN       MySQL              J | 8.0.43 | p%@d?????:z-5+q%E?ocaching_...    (REAL service)
8080     OPEN       HTTP-Alt           HTTP/1.0 200 OK | Server: SimpleHTTP/0.6 ... (test listener)
50007    OPEN       UNKNOWN            No banner                                    (test listener, silent)
50008    OPEN       UNKNOWN            ??[2J[31mRED-TEXT[0mTAB | ???????????...     (test listener, binary)
```

(The right-hand notes were added here for explanation; the scanner does not print them.)

Invalid input produces a short error instead of a traceback:

```
> python scanner.py localhost --start 1000 --end 10
Error: start port cannot be greater than end port.

> python scanner.py localhost --threads 0
Error: threads must be between 1 and 1000.

> python scanner.py no-such-host.invalid
Error: could not resolve hostname 'no-such-host.invalid'.
```

**Note for Windows users:** on Windows, a connection attempt to a *closed* port
is not rejected instantly, even on localhost – Windows retries for about 2
seconds. That means almost every closed port waits for the full `--timeout`, so
each scan task takes about `--timeout` seconds. With threads, total time is roughly
`(number of ports ÷ threads) × timeout`.

## 8. Limitations

The scanner is deliberately minimal. It:

- only scans **TCP** (no UDP)
- performs a basic **connect scan** (a full TCP handshake, easily logged by the target)
- only **guesses** the likely service from the port number, and the guess can be
  wrong (e.g. a non-HTTP program on 8080 is still shown as `HTTP-Alt`)
- knows a curated list of 92 common ports (`services.py`); everything else is `UNKNOWN`
- grabs only simple banners: it reads what a service sends first, and sends a
  `HEAD` request only to ports 80, 8000 and 8080 – other client-speaks-first
  services show `No banner`
- does **not** speak TLS, so HTTPS (443) shows `Banner unavailable (TLS)`
- is **not** a version detector: a banner is evidence, not proof, and is not parsed
- does **not** detect vulnerabilities
- does **not** perform stealth scanning
- only supports IPv4
- does not distinguish "closed" from "filtered" ports
- prints open ports only when the scan finishes (so they can be shown sorted)

## 9. Future versions

- ~~**V2** – multithreading~~ ✅ done
- ~~**V3** – service detection (port-number based)~~ ✅ done
- ~~**V4** – banner grabbing~~ ✅ done

Ideas for later versions (not implemented):

- **V5** – JSON/CSV output
- **V6** – richer terminal UI

## 10. Responsible use

This tool is intended for learning and authorized testing. Only scan systems you
own or have explicit permission to test.
