"""Role based access control and the scan authorization boundary.

Two distinct concerns live here:

1. *Who* may perform an action  -> :class:`Role` and :func:`require_role`.
2. *What* may be scanned        -> :func:`authorize_target`.

The second is a hard product boundary: VulScanner refuses to scan anything the
operator has not declared as authorized.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from enum import Enum

from app.core.config import settings


class Role(str, Enum):
    ADMINISTRATOR = "administrator"
    ANALYST = "analyst"
    VIEWER = "viewer"


# Higher number == more privilege.
_RANK = {Role.VIEWER: 1, Role.ANALYST: 2, Role.ADMINISTRATOR: 3}

# Capability matrix. Anything not listed is administrator-only.
PERMISSIONS: dict[str, Role] = {
    "scan:read": Role.VIEWER,
    "scan:create": Role.ANALYST,
    "scan:cancel": Role.ANALYST,
    "asset:read": Role.VIEWER,
    "finding:read": Role.VIEWER,
    "finding:update": Role.ANALYST,
    "finding:accept_risk": Role.ADMINISTRATOR,
    "vulnerability:read": Role.VIEWER,
    "network:read": Role.VIEWER,
    "report:read": Role.VIEWER,
    "report:create": Role.ANALYST,
    "target:read": Role.VIEWER,
    "target:create": Role.ANALYST,
    "target:delete": Role.ADMINISTRATOR,
    "user:manage": Role.ADMINISTRATOR,
    "audit:read": Role.ADMINISTRATOR,
    "settings:write": Role.ADMINISTRATOR,
}


def role_satisfies(actual: Role | str, required: Role | str) -> bool:
    actual_role = Role(actual)
    required_role = Role(required)
    return _RANK[actual_role] >= _RANK[required_role]


def has_permission(role: Role | str, permission: str) -> bool:
    required = PERMISSIONS.get(permission, Role.ADMINISTRATOR)
    return role_satisfies(role, required)


# --------------------------------------------------------------------------
# Scan authorization
# --------------------------------------------------------------------------
class AuthorizationError(PermissionError):
    """Raised when a target falls outside the configured authorized scope."""


@dataclass(slots=True)
class TargetAuthorization:
    target: str
    normalized: str
    kind: str  # local | ip | cidr | hostname
    resolved_ips: list[str]
    matched_scope: str


LOCAL_ALIASES = {"local", "localhost", "127.0.0.1", "::1", "self", "this"}


def _scope_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []
    for scope in settings.authorized_scopes:
        try:
            networks.append(ipaddress.ip_network(scope, strict=False))
        except ValueError:
            continue  # hostname scopes are handled separately
    return networks


def _scope_hostnames() -> set[str]:
    hostnames = set()
    for scope in settings.authorized_scopes:
        try:
            ipaddress.ip_network(scope, strict=False)
        except ValueError:
            hostnames.add(scope.lower())
    return hostnames


def classify_target(target: str) -> str:
    value = (target or "").strip()
    if value.lower() in LOCAL_ALIASES:
        return "local"
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return "cidr"
        except ValueError:
            return "hostname"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        return "hostname"


def resolve_hostname(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


def authorize_target(
    target: str, extra_authorized: list[str] | None = None
) -> TargetAuthorization:
    """Validate that ``target`` is inside an authorized scope.

    ``extra_authorized`` carries scopes registered in the database as explicitly
    authorized targets, which extend the environment-configured scopes.
    """
    value = (target or "").strip()
    if not value:
        raise AuthorizationError("No target supplied.")

    kind = classify_target(value)
    if kind == "local":
        return TargetAuthorization(value, "localhost", "local", ["127.0.0.1"], "local")

    allowed = list(settings.authorized_scopes) + list(extra_authorized or [])
    networks = _scope_networks()
    for scope in extra_authorized or []:
        try:
            networks.append(ipaddress.ip_network(scope, strict=False))
        except ValueError:
            continue
    hostnames = _scope_hostnames() | {
        s.lower() for s in (extra_authorized or []) if classify_target(s) == "hostname"
    }

    if kind == "cidr":
        requested = ipaddress.ip_network(value, strict=False)
        for network in networks:
            if requested.version == network.version and requested.subnet_of(network):  # type: ignore[arg-type]
                return TargetAuthorization(
                    value, str(requested), "cidr", [], str(network)
                )
        raise AuthorizationError(
            f"Network {value} is not inside an authorized scope. "
            f"Authorized scopes: {', '.join(allowed) or '(none configured)'}. "
            "Add it to VULSCANNER_AUTHORIZED_SCOPES or register it as an "
            "authorized target before scanning."
        )

    if kind == "ip":
        address = ipaddress.ip_address(value)
        for network in networks:
            if address.version == network.version and address in network:
                return TargetAuthorization(
                    value, str(address), "ip", [str(address)], str(network)
                )
        raise AuthorizationError(
            f"Address {value} is not inside an authorized scope. "
            f"Authorized scopes: {', '.join(allowed) or '(none configured)'}."
        )

    # hostname
    if value.lower() in hostnames:
        return TargetAuthorization(
            value, value.lower(), "hostname", resolve_hostname(value), value.lower()
        )
    resolved = resolve_hostname(value)
    if not resolved:
        raise AuthorizationError(
            f"Hostname {value} could not be resolved, so authorization cannot be "
            "verified. Add the hostname to the authorized scopes explicitly."
        )
    for ip_text in resolved:
        address = ipaddress.ip_address(ip_text)
        for network in networks:
            if address.version == network.version and address in network:
                return TargetAuthorization(
                    value, value.lower(), "hostname", resolved, str(network)
                )
    raise AuthorizationError(
        f"Hostname {value} resolves to {', '.join(resolved)}, which is outside "
        f"the authorized scopes ({', '.join(allowed) or '(none configured)'})."
    )
