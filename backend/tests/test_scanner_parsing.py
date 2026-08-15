"""Collector parsing, registry decoding and network classification tests."""

from __future__ import annotations

import pytest

from app.scanner.network.oui import lookup_vendor
from app.scanner.network.ports import parse_netstat
from app.scanner.network.services import classify_exposure, port_risk, service_for
from app.scanner.util import (
    boolean,
    compare_versions,
    dicts,
    enum_name,
    get,
    integer,
    normalize_mac,
    parse_datetime,
    text,
    version_tuple,
)
from app.scanner.windows.antivirus import decode_product_state
from app.scanner.windows.audit_policy import parse_auditpol_csv
from app.scanner.windows.group_policy import parse_secpol
from app.scanner.windows.local_users import parse_net_accounts
from app.scanner.windows.rdp import parse_quser


class TestJsonNormalisation:
    def test_single_object_becomes_a_list(self):
        assert dicts({"Name": "one"}) == [{"Name": "one"}]

    def test_null_becomes_empty_list(self):
        assert dicts(None) == []

    def test_case_insensitive_lookup(self):
        record = {"DisplayName": "Chrome"}
        assert get(record, "displayname") == "Chrome"
        assert get(record, "missing", default="fallback") == "fallback"

    def test_boolean_coercion(self):
        assert boolean("True") is True
        assert boolean("disabled") is False
        assert boolean(1) is True
        assert boolean("maybe", default=None) is None

    def test_integer_rejects_booleans(self):
        # True is an int subclass in Python; a registry DWORD must not become 1.
        assert integer(True, default=None) is None
        assert integer("42") == 42

    def test_text_strips(self):
        assert text("  value  ") == "value"
        assert text(None, default="-") == "-"


class TestDateParsing:
    def test_powershell_ms_date(self):
        parsed = parse_datetime("/Date(1700000000000)/")
        assert parsed is not None and parsed.year == 2023

    def test_iso_date(self):
        parsed = parse_datetime("2026-01-15T10:30:00Z")
        assert parsed is not None and parsed.month == 1

    def test_nested_datetime_object(self):
        assert parse_datetime({"DateTime": "2026-01-15T10:30:00Z"}) is not None

    def test_garbage_returns_none(self):
        assert parse_datetime("not a date") is None


class TestVersions:
    def test_version_tuple(self):
        assert version_tuple("120.0.6099.71") == (120, 0, 6099, 71)

    @pytest.mark.parametrize(
        "left,right,expected",
        [("1.2.3", "1.2.4", -1), ("2.0", "1.9.9", 1), ("1.0", "1.0.0", 0)],
    )
    def test_compare(self, left, right, expected):
        assert compare_versions(left, right) == expected


class TestMacHandling:
    def test_normalises_separators(self):
        assert normalize_mac("00-1b-21-aa-bb-cc") == "00:1B:21:AA:BB:CC"

    def test_rejects_all_zero_and_short(self):
        assert normalize_mac("00:00:00:00:00:00") is None
        assert normalize_mac("00:1b:21") is None

    def test_vendor_lookup(self):
        vendor, oui = lookup_vendor("00:0C:29:11:22:33")
        assert vendor == "VMware" and oui == "000C29"

    def test_randomised_mac_is_labelled(self):
        # Bit 1 of the first octet marks a locally administered address.
        vendor, _ = lookup_vendor("02:11:22:33:44:55")
        assert "Randomized" in vendor


class TestSecurityCenterDecoding:
    def test_enabled_and_current(self):
        state = decode_product_state(0x061100)
        assert state["enabled"] is True
        assert state["up_to_date"] is True

    def test_signatures_out_of_date(self):
        assert decode_product_state(0x061110)["up_to_date"] is False

    def test_missing_state(self):
        assert decode_product_state(None)["enabled"] is None


class TestAuditPolParsing:
    CSV = (
        "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\n"
        "HOST,System,Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,\n"
        "HOST,System,Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},No Auditing,\n"
    )

    def test_parses_subcategories(self):
        records = parse_auditpol_csv(self.CSV)
        assert len(records) == 2
        assert records[0]["subcategory"] == "Logon"
        assert records[1]["setting"] == "No Auditing"

    def test_empty_input(self):
        assert parse_auditpol_csv("") == []
        assert parse_auditpol_csv("Access is denied.") == []


class TestNetAccountsParsing:
    OUTPUT = """
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              8
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
The command completed successfully.
"""

    def test_parses_policy(self):
        policy = parse_net_accounts(self.OUTPUT)
        assert policy["min_password_length"] == 8
        assert policy["max_password_age_days"] == 42
        # "Never" must be preserved as unset, not silently coerced to 0.
        assert policy["lockout_threshold"] is None
        assert policy["lockout_threshold_raw"] == "Never"


class TestSecpolParsing:
    EXPORT = """[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 42
MinimumPasswordLength = 14
PasswordComplexity = 1
LockoutBadCount = 10
EnableGuestAccount = 0
NewAdministratorName = "LocalAdmin"
[Event Audit]
AuditSystemEvents = 3
"""

    def test_parses_system_access_only(self):
        policy = parse_secpol(self.EXPORT)
        assert policy["minimum_password_length"] == 14
        assert policy["password_complexity"] == 1
        assert policy["administrator_renamed_to"] == "LocalAdmin"
        assert "AuditSystemEvents" not in policy


class TestQuserParsing:
    OUTPUT = """ USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>alice                 console             1  Active      none   1/2/2026 9:00 AM
 bob                                       2  Disc        5      1/2/2026 8:00 AM
"""

    def test_parses_sessions(self):
        sessions = parse_quser(self.OUTPUT)
        assert len(sessions) == 2
        assert sessions[0]["username"] == "alice"
        assert sessions[0]["current_session"] is True
        assert sessions[1]["state"].lower() == "disc"

    def test_ignores_error_output(self):
        assert parse_quser("No User exists for *") == []


class TestNetstatFallback:
    OUTPUT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:5432         0.0.0.0:0              LISTENING       900
  TCP    192.168.0.5:52000      93.184.216.34:443      ESTABLISHED     1200
  UDP    0.0.0.0:5353           *:*                                    2100
"""

    def test_only_listening_tcp_and_udp(self):
        entries = parse_netstat(self.OUTPUT)
        ports = {(e["protocol"], e["local_port"]) for e in entries}
        assert ("tcp", 445) in ports
        assert ("udp", 5353) in ports
        # An established connection is not a listening port.
        assert ("tcp", 52000) not in ports

    def test_process_id_captured(self):
        entries = parse_netstat(self.OUTPUT)
        smb = next(e for e in entries if e["local_port"] == 445)
        assert smb["process_id"] == 4


class TestExposureClassification:
    @pytest.mark.parametrize(
        "address,expected",
        [
            ("0.0.0.0", "all-interfaces"),
            ("::", "all-interfaces"),
            ("127.0.0.1", "loopback"),
            ("::1", "loopback"),
            ("192.168.1.10", "private"),
            ("8.8.8.8", "public"),
            ("169.254.1.1", "link-local"),
        ],
    )
    def test_classification(self, address, expected):
        assert classify_exposure(address) == expected

    def test_loopback_is_zero_risk(self):
        score, rationale = port_risk(445, "loopback")
        assert score == 0.0
        assert "loopback" in rationale.lower()

    def test_smb_on_all_interfaces_scores_high(self):
        score, _ = port_risk(445, "all-interfaces")
        assert score >= 70

    def test_public_binding_scores_higher_than_private(self):
        assert port_risk(3389, "public")[0] > port_risk(3389, "private")[0]

    def test_service_lookup(self):
        assert service_for(3389) == "ms-wbt-server"
        assert service_for(53, "udp") == "dns"
        assert service_for(65000) == ""


class TestEnumName:
    def test_int_maps(self):
        assert enum_name(1, {1: "Inbound", 2: "Outbound"}) == "Inbound"

    def test_string_passthrough(self):
        assert enum_name("Inbound", {1: "Inbound"}) == "Inbound"

    def test_numeric_string(self):
        assert enum_name("2", {2: "Outbound"}) == "Outbound"
