import json
import os
import subprocess
import sys
import unittest
from ipaddress import ip_address
from pathlib import Path
from time import sleep
from typing import List


from tests.nftables.mock_lapi import MockLAPI

SCRIPT_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent.parent
BINARY_PATH = PROJECT_ROOT.joinpath("crowdsec-firewall-bouncer")
CONFIG_PATH = SCRIPT_DIR.joinpath("crowdsec-firewall-bouncer.yaml")


def run_cmd(cmd: List[str], trace_error=True):
    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as p:
        if p.wait() and trace_error:
            raise SystemExit(
                f"{cmd} exited with non-zero code with following logs:\n {p.stdout.read().decode()}"
            )
        else:
            return p.stdout.read().decode()


def generate_n_decisions(n: int, action="ban", dup_count=0, ipv4=True):
    if dup_count >= n:
        print("generate_n_decisions got dup_count>=n")
        sys.exit(1)

    unique_decision_count = n - dup_count
    decisions = []
    for i in range(unique_decision_count):
        if ipv4:
            ip = ip_address(i)
        else:
            ip = ip_address(2 ** 32 + i)
        decisions.append(
            {
                "value": ip.__str__(),
                "scope": "ip",
                "type": action,
                "origin": "script",
                "duration": "4h",
                "reason": "for testing",
            }
        )
    decisions += decisions[: n % unique_decision_count]
    decisions *= n // unique_decision_count
    return decisions


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
        run_cmd(["nft", "delete", "table", "ip", "crowdsec"], trace_error=False)
        run_cmd(["nft", "delete", "table", "ip6", "crowdsec6"], trace_error=False)

    def test_table_rule_set_are_created(self):
        sleep(1)
        output = json.loads(run_cmd(["nft", "-j", "list", "tables"]))
        tables = {
            (node["table"]["family"], node["table"]["name"])
            for node in output["nftables"]
            if "table" in node
        }
        assert ("ip6", "crowdsec6") in tables
        assert ("ip", "crowdsec") in tables

        # IPV4
        output = json.loads(run_cmd(["nft", "-j", "list", "table", "ip", "crowdsec"]))
        sets = {
            (node["set"]["family"], node["set"]["name"], node["set"]["type"])
            for node in output["nftables"]
            if "set" in node
        }
        assert ("ip", "crowdsec-blacklists", "ipv4_addr") in sets
        rules = {
            node["rule"]["chain"] for node in output["nftables"] if "rule" in node
        }  # maybe stricter check ?
        assert "crowdsec-chain" in rules

        # IPV6
        output = json.loads(run_cmd(["nft", "-j", "list", "table", "ip6", "crowdsec6"]))
        sets = {
            (node["set"]["family"], node["set"]["name"], node["set"]["type"])
            for node in output["nftables"]
            if "set" in node
        }
        assert ("ip6", "crowdsec6-blacklists", "ipv6_addr") in sets

        rules = {
            node["rule"]["chain"] for node in output["nftables"] if "rule" in node
        }  # maybe stricter check ?
        assert "crowdsec6-chain" in rules

    def test_duplicate_decisions_across_decision_stream(self):
        d1, d2, d3 = generate_n_decisions(3, dup_count=1)
        self.lapi.ds.insert_decisions([d1])
        sleep(1)
        self.assertEqual(
            self.get_set_elements("ip", "crowdsec", "crowdsec-blacklists"), {"0.0.0.0"}
        )

        self.lapi.ds.insert_decisions([d2, d3])
        sleep(1)
        assert self.fb.poll() is None
        self.assertEqual(
            self.get_set_elements("ip", "crowdsec", "crowdsec-blacklists"), {"0.0.0.0", "0.0.0.1"}
        )

        self.lapi.ds.delete_decision_by_id(d1["id"])
        self.lapi.ds.delete_decision_by_id(d2["id"])
        sleep(1)
        self.assertEqual(self.get_set_elements("ip", "crowdsec", "crowdsec-blacklists"), set())
        assert self.fb.poll() is None

        self.lapi.ds.delete_decision_by_id(d3["id"])
        sleep(1)
        self.assertEqual(self.get_set_elements("ip", "crowdsec", "crowdsec-blacklists"), set())
        assert self.fb.poll() is None

    def test_decision_insertion_deletion_ipv4(self):
        total_decisions, duplicate_decisions = 100, 23
        decisions = generate_n_decisions(total_decisions, dup_count=duplicate_decisions)
        self.lapi.ds.insert_decisions(decisions)
        sleep(1)  # let the bouncer insert the decisions

        set_elements = self.get_set_elements("ip", "crowdsec", "crowdsec-blacklists")
        self.assertEqual(len(set_elements), total_decisions - duplicate_decisions)
        assert {i["value"] for i in decisions} == set_elements
        assert "0.0.0.0" in set_elements

        self.lapi.ds.delete_decisions_by_ip("0.0.0.0")
        sleep(1)

        set_elements = self.get_set_elements("ip", "crowdsec", "crowdsec-blacklists")
        assert {i["value"] for i in decisions if i["value"] != "0.0.0.0"} == set_elements
        assert len(set_elements) == total_decisions - duplicate_decisions - 1
        assert "0.0.0.0" not in set_elements

    def test_decision_insertion_deletion_ipv6(self):
        total_decisions, duplicate_decisions = 100, 23
        decisions = generate_n_decisions(total_decisions, dup_count=duplicate_decisions, ipv4=False)
        self.lapi.ds.insert_decisions(decisions)
        sleep(1)

        set_elements = self.get_set_elements("ip6", "crowdsec6", "crowdsec6-blacklists")
        set_elements = set(map(ip_address, set_elements))
        assert len(set_elements) == total_decisions - duplicate_decisions
        assert {ip_address(i["value"]) for i in decisions} == set_elements
        assert ip_address("::1:0:3") in set_elements

        self.lapi.ds.delete_decisions_by_ip("::1:0:3")
        sleep(1)

        set_elements = self.get_set_elements("ip6", "crowdsec6", "crowdsec6-blacklists")
        set_elements = set(map(ip_address, set_elements))
        self.assertEqual(len(set_elements), total_decisions - duplicate_decisions - 1)
        assert (
            {
                ip_address(i["value"])
                for i in decisions
                if ip_address(i["value"]) != ip_address("::1:0:3")
            }
        ) == set_elements
        assert ip_address("::1:0:3") not in set_elements

    @staticmethod
    def get_set_elements(family, table_name, set_name):
        output = json.loads(run_cmd(["nft", "-j", "list", "set", family, table_name, set_name]))
        for node in output["nftables"]:
            if "set" not in node or "elem" not in node["set"]:
                continue
            if not isinstance(node["set"]["elem"][0], dict):
                return set(node["set"]["elem"])
            else:
                return {elem["elem"]["val"] for elem in node["set"]["elem"]}
        return set()
