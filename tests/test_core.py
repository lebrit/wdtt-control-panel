import time
import unittest
from datetime import datetime, timezone

from wdtt_panel.core import (
    ValidationError,
    GIB,
    add_calendar_months,
    normalize_hashes,
    parse_expiration,
    quick_link,
    traffic_quota,
    validate_password,
    validate_ports,
)


class CoreTests(unittest.TestCase):
    def test_normalizes_full_vk_links_and_deduplicates(self):
        value = normalize_hashes("https://vk.com/call/join/abc_DEF, abc_DEF, xyz-123")
        self.assertEqual(value, "abc_DEF,xyz-123")

    def test_rejects_more_than_four_hashes(self):
        with self.assertRaises(ValidationError):
            normalize_hashes("one,two,three,four,five")

    def test_password_is_safe_for_colon_delimited_quick_link(self):
        self.assertEqual(validate_password("Good.Pass-123"), "Good.Pass-123")
        with self.assertRaises(ValidationError):
            validate_password("bad:password")

    def test_ports(self):
        self.assertEqual(validate_ports("56000, 56001,9000"), "56000,56001,9000")
        with self.assertRaises(ValidationError):
            validate_ports("56000,70000,9000")

    def test_expiration(self):
        now = int(time.time())
        self.assertEqual(parse_expiration({"unlimited": True}, now), 0)
        self.assertEqual(parse_expiration({"days": 2}, now), now + 172800)

    def test_calendar_month_expiration_keeps_end_of_month(self):
        january_31 = int(datetime(2025, 1, 31, 12, tzinfo=timezone.utc).timestamp())
        result = datetime.fromtimestamp(add_calendar_months(january_31, 1), timezone.utc)
        self.assertEqual((result.year, result.month, result.day), (2025, 2, 28))

    def test_traffic_quota_spends_primary_before_extra(self):
        quota = traffic_quota(
            {
                "traffic_managed": True,
                "traffic_primary_bytes": 35 * GIB,
                "traffic_extra_bytes": 10 * GIB,
                "down_bytes": 38 * GIB,
            }
        )
        self.assertEqual(quota["traffic_primary_remaining_bytes"], 0)
        self.assertEqual(quota["traffic_extra_remaining_bytes"], 7 * GIB)
        self.assertFalse(quota["quota_exhausted"])

    def test_quick_link_matches_android_parser_order(self):
        link = quick_link(
            "panel.example.com",
            "GoodPass123",
            {"ports": "56000,56001,9000", "vk_hash": "hash1,hash2"},
        )
        self.assertEqual(
            link,
            "wdtt://panel.example.com:56000:56001:9000:GoodPass123:hash1,hash2",
        )


if __name__ == "__main__":
    unittest.main()
