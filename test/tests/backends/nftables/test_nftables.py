import json
import os
import subprocess
import unittest
from ipaddress import ip_address, ip_network
from pathlib import Path
from time import sleep

import pytest

from ..mock_lapi import MockLAPI
from ..utils import generate_n_decisions, new_decision, new_range_decision, run_cmd

SCRIPT_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent.parent
BINARY_PATH = PROJECT_ROOT.joinpath("crowdsec-firewall-bouncer")
CONFIG_PATH = SCRIPT_DIR.joinpath("crowdsec-firewall-bouncer.yaml")
RANGES_CONFIG_PATH = SCRIPT_DIR.joinpath("crowdsec-firewall-bouncer-ranges.yaml")


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


def get_set_elements(family, table_name, set_name, with_timeout=False):
    output = json.loads(run_cmd("nft", "-j", "list", "set", family, table_name, set_name))
    for node in output["nftables"]:
        if "set" not in node or "elem" not in node["set"]:
            continue
        if not isinstance(node["set"]["elem"][0], dict):
            return set(node["set"]["elem"])

        if not with_timeout:
            return {elem["elem"]["val"] for elem in node["set"]["elem"]}
        return {(elem["elem"]["val"], elem["elem"]["timeout"]) for elem in node["set"]["elem"]}
    return set()


def get_set_intervals(family, table_name, set_name):
    output = json.loads(run_cmd("nft", "-j", "list", "set", family, table_name, set_name))
    intervals = []
    for node in output["nftables"]:
        if "set" not in node or "elem" not in node["set"]:
            continue
        for elem in node["set"]["elem"]:
            val = elem["elem"]["val"]
            if isinstance(val, str):
                first = last = ip_address(val)
            elif "range" in val:
                first, last = (ip_address(i) for i in val["range"])
            else:
                network = ip_network(f"{val['prefix']['addr']}/{val['prefix']['len']}")
                first, last = network[0], network[-1]
            intervals.append((first, last, elem["elem"]["timeout"]))
    return sorted(intervals)


class TestNFTablesRanges(unittest.TestCase):
    def setUp(self):
        self.fb = subprocess.Popen([BINARY_PATH, "-c", RANGES_CONFIG_PATH])
        self.lapi = MockLAPI()
        self.lapi.start()
        return super().setUp()

    def tearDown(self):
        self.fb.kill()
        self.fb.wait()
        self.lapi.stop()
        run_cmd("nft", "delete", "table", "ip", "crowdsec", ignore_error=True)
        run_cmd("nft", "delete", "table", "ip6", "crowdsec6", ignore_error=True)

    def assert_intervals(self, family, table_name, set_name, expected):
        intervals = get_set_intervals(family, table_name, set_name)
        assert [(str(first), str(last)) for first, last, _ in intervals] == [
            (first, last) for first, last, _ in expected
        ]
        assert [timeout for _, _, timeout in intervals] == pytest.approx(
            [duration for _, _, duration in expected],
            abs=3,
        )

    def test_sets_are_intervals(self):
        self.lapi.ds.insert_decisions([new_range_decision("10.60.0.0/24")])
        sleep(1)
        output = json.loads(run_cmd("nft", "-j", "list", "table", "ip", "crowdsec"))
        flags = {node["set"]["name"]: set(node["set"].get("flags", [])) for node in output["nftables"] if "set" in node}
        assert "interval" in flags["crowdsec-blacklists-script"]

    def test_ipv4_written_in_ipv6_notation(self):
        self.lapi.ds.insert_decisions([new_decision("::ffff:10.60.0.9")])
        sleep(1)

        self.assert_intervals(
            "ip",
            "crowdsec",
            "crowdsec-blacklists-script",
            [("10.60.0.9", "10.60.0.9", 4 * 60 * 60)],
        )
        assert self.fb.poll() is None

    def test_range_decision(self):
        self.lapi.ds.insert_decisions(
            [
                new_range_decision("10.60.0.0/24"),
                new_range_decision("2001:db8::/48", duration="2h"),
            ]
        )
        sleep(1)
        self.assert_intervals(
            "ip",
            "crowdsec",
            "crowdsec-blacklists-script",
            [("10.60.0.0", "10.60.0.255", 4 * 60 * 60)],
        )
        self.assert_intervals(
            "ip6",
            "crowdsec6",
            "crowdsec6-blacklists-script",
            [("2001:db8::", "2001:db8:0:ffff:ffff:ffff:ffff:ffff", 2 * 60 * 60)],
        )

    def test_overlapping_decisions(self):
        outer = new_range_decision("10.60.0.0/24", duration="1h")
        inner = new_range_decision("10.60.0.64/28", duration="5h")
        self.lapi.ds.insert_decisions([outer, inner])
        sleep(1)

        self.assert_intervals(
            "ip",
            "crowdsec",
            "crowdsec-blacklists-script",
            [
                ("10.60.0.0", "10.60.0.63", 1 * 60 * 60),
                ("10.60.0.64", "10.60.0.79", 5 * 60 * 60),
                ("10.60.0.80", "10.60.0.255", 1 * 60 * 60),
            ],
        )

        self.lapi.ds.delete_decision_by_id(inner["id"])
        sleep(1)
        self.assert_intervals(
            "ip",
            "crowdsec",
            "crowdsec-blacklists-script",
            [("10.60.0.0", "10.60.0.255", 1 * 60 * 60)],
        )

        self.lapi.ds.delete_decision_by_id(outer["id"])
        sleep(1)
        assert get_set_intervals("ip", "crowdsec", "crowdsec-blacklists-script") == []
        assert self.fb.poll() is None

    def test_duplicate_decisions_are_tracked_separately(self):
        short = new_decision("10.60.0.42")
        long = new_decision("10.60.0.42")
        long["duration"] = "10h"
        self.lapi.ds.insert_decisions([short, long])
        sleep(1)
        self.assert_intervals(
            "ip",
            "crowdsec",
            "crowdsec-blacklists-script",
            [("10.60.0.42", "10.60.0.42", 10 * 60 * 60)],
        )

        self.lapi.ds.delete_decision_by_id(short["id"])
        sleep(1)
        self.assert_intervals(
            "ip",
            "crowdsec",
            "crowdsec-blacklists-script",
            [("10.60.0.42", "10.60.0.42", 10 * 60 * 60)],
        )

        self.lapi.ds.delete_decision_by_id(long["id"])
        sleep(1)
        assert get_set_intervals("ip", "crowdsec", "crowdsec-blacklists-script") == []

    def test_deletion_only_hits_its_own_origin(self):
        scripted = new_decision("10.60.0.42")
        listed = new_decision("10.60.0.42")
        listed["origin"] = "cscli"
        self.lapi.ds.insert_decisions([scripted, listed])
        sleep(1)

        for set_name in ("crowdsec-blacklists-script", "crowdsec-blacklists-cscli"):
            self.assert_intervals("ip", "crowdsec", set_name, [("10.60.0.42", "10.60.0.42", 4 * 60 * 60)])

        self.lapi.ds.delete_decision_by_id(scripted["id"])
        sleep(1)
        assert get_set_intervals("ip", "crowdsec", "crowdsec-blacklists-script") == []
        self.assert_intervals(
            "ip",
            "crowdsec",
            "crowdsec-blacklists-cscli",
            [("10.60.0.42", "10.60.0.42", 4 * 60 * 60)],
        )
