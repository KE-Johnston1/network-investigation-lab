import json
import unittest
from pathlib import Path

from investigation_pipeline import load_cases, load_inventory, load_network_telemetry


ROOT = Path(__file__).parents[1]


class InvestigationBoundaryTests(unittest.TestCase):
    def test_unknown_asset_case_is_intentionally_unauthorised(self):
        inventory = load_inventory()
        cases = load_cases(inventory=inventory)
        context = inventory[cases["NET-001"]["ip"]]

        self.assertFalse(context.authorised)
        self.assertEqual(context.owner, "Unknown")
        self.assertEqual(context.role, "Unknown")
        self.assertEqual(cases["NET-001"]["assessment_guidance"]["Requires Investigation"].startswith("Appropriate"), True)

    def test_unknown_asset_telemetry_correlates_across_sources(self):
        telemetry = load_network_telemetry()["NET-001"]
        events = telemetry["firewall"] + telemetry["ids"] + telemetry["ips"]

        self.assertEqual(len(events), 3)
        self.assertEqual({event["source_ip"] for event in events}, {"198.51.100.24"})
        self.assertEqual({event["destination_ip"] for event in events}, {"10.10.10.50"})
        self.assertEqual({event["destination_port"] for event in events}, {8080})
        self.assertEqual({event["protocol"] for event in events}, {"tcp"})
        self.assertEqual([event["action"] for event in events], ["allowed", "alerted", "blocked"])

    def test_expected_case_has_matching_inventory_and_baseline(self):
        inventory = load_inventory()
        cases = load_cases(inventory=inventory)
        case = cases["NET-002"]
        context = inventory[case["ip"]]

        self.assertTrue(context.authorised)
        self.assertEqual(set(case["expected_services"]), set(context.expected_services))
        self.assertEqual(
            {f"{item['protocol'].lower()}/{item['port']}" for item in case["discovered_services"]},
            set(case["expected_services"]),
        )

    def test_repository_contains_only_synthetic_private_documentation_networks(self):
        cases = load_cases()
        inventory = load_inventory()
        telemetry = load_network_telemetry()

        addresses = set(inventory) | {case["ip"] for case in cases.values()}
        addresses |= {
            event["source_ip"]
            for source_set in telemetry.values()
            for events in source_set.values()
            for event in events
        }
        addresses |= {
            event["destination_ip"]
            for source_set in telemetry.values()
            for events in source_set.values()
            for event in events
        }

        # RFC 1918 addresses and TEST-NET-2 are appropriate for synthetic lab data.
        self.assertIn("10.10.10.50", addresses)
        self.assertIn("198.51.100.24", addresses)
        self.assertTrue(all(
            address.startswith("10.") or address.startswith("192.0.2.") or address.startswith("198.51.100.")
            for address in addresses
        ))

    def test_case_and_telemetry_files_are_valid_json(self):
        for relative_path in (
            "data/cases.json",
            "data/asset_inventory.json",
            "data/network_telemetry.json",
        ):
            with self.subTest(path=relative_path):
                json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
