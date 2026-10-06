import json
import os
import subprocess
import tempfile
import unittest
from ipaddress import ip_address
from pathlib import Path
from time import monotonic, sleep

import yaml

from ..mock_lapi import MockLAPI
from ..utils import generate_n_decisions, new_decision, run_cmd

SCRIPT_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent.parent
BINARY_PATH = PROJECT_ROOT.joinpath("crowdsec-firewall-bouncer")
CONFIG_PATH = SCRIPT_DIR.joinpath("crowdsec-firewall-bouncer.yaml")


class TestNFTables(unittest.TestCase):
    def setUp(self):
        self.fb = subprocess.Popen([BINARY_PATH, "-c", CONFIG_PATH])
        self.lapi = MockLAPI()
        self.lapi.start()
        return super().setUp()

    def tearDown(self):
        self.fb.kill()
        self.fb.wait()
        self.lapi.stop()
        run_cmd("nft", "delete", "table", "ip", "crowdsec", ignore_error=True)
        run_cmd("nft", "delete", "table", "ip6", "crowdsec6", ignore_error=True)

    def test_table_rule_set_are_created(self):
        d1 = generate_n_decisions(3)
        d2 = generate_n_decisions(1, ipv4=False)
        self.lapi.ds.insert_decisions(d1 + d2)
        sleep(1)
        output = json.loads(run_cmd("nft", "-j", "list", "tables"))
        tables = {(node["table"]["family"], node["table"]["name"]) for node in output["nftables"] if "table" in node}
        assert ("ip6", "crowdsec6") in tables
        assert ("ip", "crowdsec") in tables

        # IPV4
        output = json.loads(run_cmd("nft", "-j", "list", "table", "ip", "crowdsec"))
        sets = {
            (node["set"]["family"], node["set"]["name"], node["set"]["type"])
            for node in output["nftables"]
            if "set" in node
        }
        assert ("ip", "crowdsec-blacklists-script", "ipv4_addr") in sets
        rules = {node["rule"]["chain"] for node in output["nftables"] if "rule" in node}  # maybe stricter check ?
        assert "crowdsec-chain-forward" in rules
        assert "crowdsec-chain-input" in rules

        # IPV6
        output = json.loads(run_cmd("nft", "-j", "list", "table", "ip6", "crowdsec6"))
        sets = {
            (node["set"]["family"], node["set"]["name"], node["set"]["type"])
            for node in output["nftables"]
            if "set" in node
        }
        assert ("ip6", "crowdsec6-blacklists-script", "ipv6_addr") in sets

        rules = {node["rule"]["chain"] for node in output["nftables"] if "rule" in node}  # maybe stricter check ?
        assert "crowdsec6-chain-input" in rules
        assert "crowdsec6-chain-forward" in rules

    def test_duplicate_decisions_across_decision_stream(self):
        d1, d2, d3 = generate_n_decisions(3, dup_count=1)
        self.lapi.ds.insert_decisions([d1])
        sleep(1)
        self.assertEqual(
            get_set_elements("ip", "crowdsec", "crowdsec-blacklists-script"),
            {"0.0.0.0"},
        )

        self.lapi.ds.insert_decisions([d2, d3])
        sleep(1)
        assert self.fb.poll() is None
        self.assertEqual(
            get_set_elements("ip", "crowdsec", "crowdsec-blacklists-script"),
            {"0.0.0.0", "0.0.0.1"},
        )

        self.lapi.ds.delete_decision_by_id(d1["id"])
        self.lapi.ds.delete_decision_by_id(d2["id"])
        sleep(1)
        self.assertEqual(get_set_elements("ip", "crowdsec", "crowdsec-blacklists-script"), set())
        assert self.fb.poll() is None

        self.lapi.ds.delete_decision_by_id(d3["id"])
        sleep(1)
        self.assertEqual(get_set_elements("ip", "crowdsec", "crowdsec-blacklists-script"), set())
        assert self.fb.poll() is None

    def test_decision_insertion_deletion_ipv4(self):
        total_decisions, duplicate_decisions = 100, 23
        decisions = generate_n_decisions(total_decisions, dup_count=duplicate_decisions)
        self.lapi.ds.insert_decisions(decisions)
        sleep(1)  # let the bouncer insert the decisions

        set_elements = get_set_elements("ip", "crowdsec", "crowdsec-blacklists-script")
        self.assertEqual(len(set_elements), total_decisions - duplicate_decisions)
        assert {i["value"] for i in decisions} == set_elements
        assert "0.0.0.0" in set_elements

        self.lapi.ds.delete_decisions_by_ip("0.0.0.0")
        sleep(1)

        set_elements = get_set_elements("ip", "crowdsec", "crowdsec-blacklists-script")
        assert {i["value"] for i in decisions if i["value"] != "0.0.0.0"} == set_elements
        assert len(set_elements) == total_decisions - duplicate_decisions - 1
        assert "0.0.0.0" not in set_elements

    def test_decision_insertion_deletion_ipv6(self):
        total_decisions, duplicate_decisions = 100, 23
        decisions = generate_n_decisions(total_decisions, dup_count=duplicate_decisions, ipv4=False)
        self.lapi.ds.insert_decisions(decisions)
        sleep(1)

        set_elements = get_set_elements("ip6", "crowdsec6", "crowdsec6-blacklists-script")
        set_elements = set(map(ip_address, set_elements))
        assert len(set_elements) == total_decisions - duplicate_decisions
        assert {ip_address(i["value"]) for i in decisions} == set_elements
        assert ip_address("::1:0:3") in set_elements

        self.lapi.ds.delete_decisions_by_ip("::1:0:3")
        sleep(1)

        set_elements = get_set_elements("ip6", "crowdsec6", "crowdsec6-blacklists-script")
        set_elements = set(map(ip_address, set_elements))
        self.assertEqual(len(set_elements), total_decisions - duplicate_decisions - 1)
        assert (
            {ip_address(i["value"]) for i in decisions if ip_address(i["value"]) != ip_address("::1:0:3")}
        ) == set_elements
        assert ip_address("::1:0:3") not in set_elements

    def test_timeout_refresh_across_stream_updates(self):
        self.check_timeout_refresh()

    def prepare_set_only(self):
        self.fb.kill()
        self.fb.wait()
        self.lapi.ds.bouncer_lastpull_by_api_key.clear()
        config = yaml.safe_load(CONFIG_PATH.read_text())
        for family, table, datatype, blacklist in (
            ("ip", "crowdsec", "ipv4_addr", "crowdsec-blacklists"),
            ("ip6", "crowdsec6", "ipv6_addr", "crowdsec6-blacklists"),
        ):
            run_cmd("nft", "delete", "table", family, table, ignore_error=True)
            run_cmd("nft", "add", "table", family, table)
            run_cmd("nft", "add", "set", family, table, blacklist, f"{{ type {datatype}; flags timeout; }}")
        for family in ("ipv4", "ipv6"):
            config["nftables"][family]["set-only"] = True
        return config

    def test_set_only_timeout_refresh_across_stream_updates(self):
        config = self.prepare_set_only()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "firewall.yaml"
            path.write_text(yaml.safe_dump(config))
            self.fb = subprocess.Popen([BINARY_PATH, "-c", path])
            self.check_timeout_refresh(set_only=True)

    def test_set_only_preserves_permanent_elements(self):
        config = self.prepare_set_only()
        # Exercise permanent-first IPv4 and timed-first IPv6 JSON ordering.
        addresses = (
            ("ip", "crowdsec", "crowdsec-blacklists", "192.0.2.1"),
            ("ip6", "crowdsec6", "crowdsec6-blacklists", "2001:db8::2"),
        )
        for address in addresses:
            run_cmd("nft", "add", "element", *address[:3], f"{{ {address[3]} }}")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "firewall.yaml"
            path.write_text(yaml.safe_dump(config))
            self.fb = subprocess.Popen([BINARY_PATH, "-c", path])
            self.wait_for(lambda: bool(self.lapi.ds.bouncer_lastpull_by_api_key), "bouncer did not reach LAPI")
            decisions = [new_decision(address[3]) | {"duration": "3s"} for address in addresses]
            sentinels = [new_decision(ip) | {"duration": "6s"} for ip in ("192.0.2.2", "2001:db8::1")]
            incoming_expiry = monotonic() + 3
            self.lapi.ds.insert_decisions(decisions + sentinels)
            self.wait_for(
                lambda: all(
                    sentinel["value"] in get_set_elements(*address[:3])
                    for sentinel, address in zip(sentinels, addresses, strict=True)
                ),
                "finite decisions were not processed",
            )
            # Isolate kernel expiration from explicit LAPI deletion, which
            # intentionally still removes an address, including permanent ones.
            self.lapi.ds.decisions = []
            for sentinel, address in zip(sentinels, addresses, strict=True):
                timeouts = dict(get_set_elements(*address[:3], with_timeout=True))
                assert timeouts[address[3]] is None, f"permanent ban became timed: {timeouts}"
                assert timeouts[sentinel["value"]] > 0
                assert dict(get_set_elements(*address[:3], with_expires=True))[address[3]] is None

            while monotonic() <= incoming_expiry + 0.2:
                assert self.fb.poll() is None
                assert all(
                    dict(get_set_elements(*address[:3], with_timeout=True))[address[3]] is None for address in addresses
                )
                sleep(0.02)
            for sentinel, address in zip(sentinels, addresses, strict=True):
                expires = dict(get_set_elements(*address[:3], with_expires=True))
                assert expires[address[3]] is None
                assert expires[sentinel["value"]] > 0
            self.wait_for(
                lambda: all(get_set_elements(*address[:3]) == {address[3]} for address in addresses),
                "timed sentinels did not expire while permanent bans remained",
            )
            assert self.fb.poll() is None

    def wait_for(self, predicate, message, timeout=10):
        deadline = monotonic() + timeout
        while monotonic() < deadline:
            assert self.fb.poll() is None, "bouncer exited during nft update"
            if predicate():
                return
            sleep(0.01)
        self.fail(f"{message}: {run_cmd('nft', 'list', 'ruleset')}")

    def wait_for_sets(self, addresses, timeout=10):
        deadline = monotonic() + timeout
        for address in addresses:
            command = ("nft", "-j", "list", "set", *address[:3])
            last_error = "query deadline elapsed"
            while monotonic() < deadline:
                assert self.fb.poll() is None, "bouncer exited while waiting for nft sets"
                try:
                    result = subprocess.run(command, capture_output=True, text=True, timeout=1)
                except subprocess.TimeoutExpired as error:
                    last_error = str(error)
                else:
                    if result.returncode == 0:
                        break
                    last_error = f"exit code {result.returncode}: {result.stderr}{result.stdout}"
                sleep(0.01)
            else:
                self.fail(f"nft set query did not succeed before deadline: {command}: {last_error}")

    def check_timeout_refresh(self, *, set_only=False):
        self.wait_for(lambda: bool(self.lapi.ds.bouncer_lastpull_by_api_key), "bouncer did not reach LAPI")
        suffix = "" if set_only else "-script"
        addresses = (
            ("ip", "crowdsec", "crowdsec-blacklists" + suffix, "192.0.2.1"),
            ("ip6", "crowdsec6", "crowdsec6-blacklists" + suffix, "2001:db8::1"),
        )

        def insert(duration):
            decisions = [new_decision(address[3]) | {"duration": duration} for address in addresses]
            self.lapi.ds.insert_decisions(decisions)
            return decisions

        def remaining(address):
            return dict(get_set_elements(*address[:3], with_expires=True)).get(address[3], 0)

        short = insert("3s")
        original_expiry = monotonic() + 3
        self.wait_for_sets(addresses)
        self.wait_for(lambda: all(remaining(address) > 0 for address in addresses), "initial bans were not installed")
        # The mock emits deletions for each sibling, unlike LAPI's effective
        # ban stream. Retire the superseded records without emitting deletions.
        self.lapi.ds.decisions = [d for d in self.lapi.ds.decisions if d not in short]
        long = [new_decision(address[3]) | {"duration": "8s"} for address in addresses]
        # Equivalent IPv6 spellings in one batch must keep the longest timeout.
        alias = new_decision("2001:db8:0:0:0:0:0:1") | {"duration": "4s"}
        self.lapi.ds.insert_decisions([*long, alias])
        self.wait_for(
            lambda: all(remaining(address) > 6 for address in addresses), "existing timeouts were not extended"
        )
        refreshed_expiry = monotonic() + min(remaining(address) for address in addresses)
        self.lapi.ds.decisions = [d for d in self.lapi.ds.decisions if d != alias]

        # New sentinel keys prove the shorter update was applied by both
        # families before checking that it did not shorten the existing bans.
        shorter = [new_decision(address[3]) | {"duration": "1s"} for address in addresses]
        sentinels = [new_decision(ip) | {"duration": "8s"} for ip in ("192.0.2.2", "2001:db8::2")]
        self.lapi.ds.insert_decisions(shorter + sentinels)
        self.wait_for(
            lambda: all(
                sentinel["value"] in get_set_elements(*address[:3])
                for sentinel, address in zip(sentinels, addresses, strict=True)
            ),
            "shorter update was not processed",
        )
        assert all(remaining(address) > 6 for address in addresses)
        self.lapi.ds.decisions = [d for d in self.lapi.ds.decisions if d not in shorter]
        for sentinel in sentinels:
            self.lapi.ds.delete_decision_by_id(sentinel["id"])
        self.wait_for(
            lambda: all(
                sentinel["value"] not in get_set_elements(*address[:3])
                for sentinel, address in zip(sentinels, addresses, strict=True)
            ),
            "explicit deletions were not processed",
        )

        assert refreshed_expiry > original_expiry
        while monotonic() < refreshed_expiry - 0.2:
            assert all(remaining(address) > 0 for address in addresses)
            sleep(0.02)
        self.wait_for(
            lambda: all(not get_set_elements(*address[:3]) for address in addresses), "final bans did not expire"
        )
        assert monotonic() > original_expiry

    def test_longest_decision_insertion(self):
        decisions = [
            {
                "value": "123.45.67.12",
                "scope": "ip",
                "type": "ban",
                "origin": "script",
                "duration": f"{i}h",
                "reason": "for testing",
            }
            for i in range(1, 201)
        ]
        self.lapi.ds.insert_decisions(decisions)
        sleep(1)
        elems = get_set_elements("ip", "crowdsec", "crowdsec-blacklists-script", with_timeout=True)
        assert len(elems) == 1
        elems = list(elems)
        assert elems[0][0] == "123.45.67.12"
        assert abs(elems[0][1] - 200 * 60 * 60) <= 3


def get_set_elements(family, table_name, set_name, with_timeout=False, with_expires=False):
    output = json.loads(run_cmd("nft", "-j", "list", "set", family, table_name, set_name))
    elements = set()
    field = "expires" if with_expires else "timeout"
    for node in output["nftables"]:
        if "set" not in node:
            continue
        for item in node["set"].get("elem", []):
            # Permanent and timed entries can coexist in either order.
            if isinstance(item, dict):
                element = item["elem"]
                value, duration = element["val"], element.get(field)
            else:
                value, duration = item, None
            if with_timeout or with_expires:
                elements.add((value, duration))
            else:
                elements.add(value)
    return elements
