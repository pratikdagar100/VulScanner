"""Well-known port to service mapping and exposure classification."""

from __future__ import annotations

import ipaddress

WELL_KNOWN_PORTS: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp-server", 68: "dhcp-client", 69: "tftp", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
    389: "ldap", 443: "https", 445: "microsoft-ds", 464: "kpasswd", 465: "smtps",
    500: "isakmp", 514: "syslog", 515: "printer", 546: "dhcpv6-client",
    547: "dhcpv6-server", 587: "submission", 593: "http-rpc-epmap", 623: "ipmi",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn",
    1433: "ms-sql-s", 1434: "ms-sql-m", 1521: "oracle", 1723: "pptp", 1883: "mqtt",
    1900: "upnp", 2049: "nfs", 2179: "vmrdp", 2375: "docker", 2376: "docker-tls",
    2483: "oracle-db", 3000: "http-alt", 3128: "squid-http", 3268: "globalcatldap",
    3269: "globalcatldaps", 3306: "mysql", 3389: "ms-wbt-server", 4444: "krb524",
    5000: "upnp-http", 5040: "windows-deployment", 5060: "sip", 5061: "sips",
    5222: "xmpp-client", 5353: "mdns", 5357: "wsdapi", 5432: "postgresql",
    5555: "freeciv/adb", 5672: "amqp", 5900: "vnc", 5901: "vnc-1", 5985: "wsman-http",
    5986: "wsman-https", 6379: "redis", 6443: "kubernetes-api", 7680: "delivery-optimization",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9090: "websm",
    9100: "jetdirect", 9200: "elasticsearch", 9300: "elasticsearch-transport",
    10000: "webmin", 11211: "memcached", 27017: "mongodb", 27018: "mongodb-shard",
    47001: "winrm-http-listener", 49152: "dynamic-rpc",
}

UDP_PORTS: dict[int, str] = {
    53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp", 123: "ntp",
    137: "netbios-ns", 138: "netbios-dgm", 161: "snmp", 500: "isakmp",
    514: "syslog", 1900: "upnp", 3702: "ws-discovery", 4500: "ipsec-nat-t",
    5050: "mmcc", 5353: "mdns", 5355: "llmnr", 27036: "steam",
}

# Ports whose exposure to a network materially raises risk, with a rationale.
HIGH_RISK_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP", "Transmits credentials and data without encryption."),
    23: ("Telnet", "Transmits credentials in cleartext and has no modern use case."),
    69: ("TFTP", "Unauthenticated file transfer."),
    135: ("MSRPC", "Endpoint mapper commonly abused for lateral movement."),
    137: ("NetBIOS Name Service", "Legacy name resolution vulnerable to spoofing."),
    139: ("NetBIOS Session", "Legacy SMB transport."),
    445: ("SMB", "Primary lateral-movement and ransomware propagation path."),
    1433: ("Microsoft SQL Server", "Database directly reachable over the network."),
    3306: ("MySQL", "Database directly reachable over the network."),
    3389: ("RDP", "Prime target for credential attacks and known RCE flaws."),
    5432: ("PostgreSQL", "Database directly reachable over the network."),
    5900: ("VNC", "Frequently deployed without authentication or encryption."),
    5985: ("WinRM HTTP", "Remote management over an unencrypted transport."),
    6379: ("Redis", "Historically ships without authentication."),
    9200: ("Elasticsearch", "Historically ships without authentication."),
    11211: ("Memcached", "Unauthenticated and usable for reflection attacks."),
    27017: ("MongoDB", "Historically ships without authentication."),
    2375: ("Docker API", "Unauthenticated Docker API grants host-level control."),
}

# Listening addresses meaning "every interface".
WILDCARD_ADDRESSES = {"0.0.0.0", "::", "*", ""}


def service_for(port: int, protocol: str = "tcp") -> str:
    table = UDP_PORTS if protocol.lower() == "udp" else WELL_KNOWN_PORTS
    return table.get(port, "")


def classify_exposure(local_address: str) -> str:
    """Classify how widely a listening socket is reachable."""
    address = (local_address or "").strip().strip("[]").split("%")[0]
    if address in WILDCARD_ADDRESSES:
        return "all-interfaces"
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    return "public"


def remote_scope(remote_address: str) -> str:
    address = (remote_address or "").strip().strip("[]").split("%")[0]
    if not address or address in WILDCARD_ADDRESSES:
        return "unspecified"
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private or ip.is_link_local:
        return "private"
    return "public"


def port_risk(port: int, exposure: str) -> tuple[float, str]:
    """Score a listening port 0-100 with a short rationale."""
    if exposure == "loopback":
        return 0.0, "Bound to loopback only; not reachable from the network."

    entry = HIGH_RISK_PORTS.get(port)
    reachable = exposure in ("all-interfaces", "private", "public")
    if entry:
        name, rationale = entry
        base = 55.0
        if exposure == "public":
            base = 90.0
        elif exposure == "all-interfaces":
            base = 70.0
        return base, f"{name} reachable on a {exposure} scope. {rationale}"

    if not reachable:
        return 5.0, f"Listening on a {exposure} scope."
    if exposure == "public":
        return 45.0, "Service is reachable from a publicly routable address."
    return 15.0, f"Service is reachable on a {exposure} scope."
