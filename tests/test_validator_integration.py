"""Run the shared-log outage test from a Compose validator container."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from sigilchain import config
from sigilchain.ledger import LedgerUnavailable, get_event


class EtcdIntegrationTests(unittest.TestCase):
    def test_unavailable_cluster_fails_closed(self):
        with patch.object(config, "ETCD_ENDPOINTS", ["http://127.0.0.1:1"]):
            with self.assertRaises(LedgerUnavailable):
                get_event("not-present")


if __name__ == "__main__":
    unittest.main()
