"""
Common TCP ports and the services COMMONLY associated with them.

These are conventions (mostly from the IANA port registry and common practice),
not guarantees: any program can listen on any port. The scanner only uses this
table to make a "likely service" guess from the port number.

This is a curated list of commonly seen TCP ports, not the full IANA registry
(which has thousands of entries). Ports used mainly over UDP (e.g. DHCP 67/68,
NTP 123, SNMP 161) are left out because this scanner only scans TCP.

Used by scanner.py:  from services import COMMON_SERVICES
"""

COMMON_SERVICES = {
    # --- Classic Internet services ---
    7: "Echo",
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    43: "WHOIS",
    53: "DNS",
    79: "Finger",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "RPCbind",
    113: "Ident",
    119: "NNTP",
    143: "IMAP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    464: "Kerberos-Passwd",
    465: "SMTPS",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    515: "LPD-Printer",
    548: "AFP",
    554: "RTSP",
    587: "SMTP-Submission",
    631: "IPP-Printer",
    636: "LDAPS",
    873: "rsync",
    989: "FTPS-Data",
    990: "FTPS",
    993: "IMAPS",
    995: "POP3S",

    # --- Windows ---
    135: "MSRPC",
    139: "NetBIOS-SSN",
    445: "SMB",
    593: "MSRPC-over-HTTP",
    3268: "LDAP-GlobalCatalog",
    3389: "RDP",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",

    # --- Remote access / VPN / proxies ---
    1080: "SOCKS-Proxy",
    1194: "OpenVPN",
    1723: "PPTP",
    3128: "Squid-Proxy",
    5900: "VNC",
    6000: "X11",

    # --- Databases ---
    1433: "MSSQL",
    1521: "Oracle-DB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9042: "Cassandra",
    11211: "Memcached",
    27017: "MongoDB",
    33060: "MySQL-X",

    # --- Web servers, alternate HTTP/HTTPS ports ---
    3000: "HTTP-Dev",
    4443: "HTTPS-Alt",
    5000: "HTTP-Dev",
    7001: "WebLogic",
    8000: "HTTP-Alt",
    8008: "HTTP-Alt",
    8080: "HTTP-Alt",
    8081: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",

    # --- Messaging, queues, streaming ---
    1883: "MQTT",
    5222: "XMPP",
    5672: "AMQP",
    6667: "IRC",
    9092: "Kafka",
    15672: "RabbitMQ-Mgmt",

    # --- DevOps, containers, monitoring, search ---
    2049: "NFS",
    2181: "ZooKeeper",
    2375: "Docker",
    2376: "Docker-TLS",
    2379: "etcd",
    3690: "SVN",
    4369: "Erlang-EPMD",
    5601: "Kibana",
    6443: "Kubernetes-API",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Node",
    9418: "Git",

    # --- Other ---
    902: "VMware-Auth",
    5060: "SIP",
    5061: "SIP-TLS",
    9100: "Printer-JetDirect",
    25565: "Minecraft",
}
