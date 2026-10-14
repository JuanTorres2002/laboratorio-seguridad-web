import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app


class SecurityLabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "lab.db"
        self.patch = patch.object(app, "DB_PATH", self.db)
        self.patch.start()
        app.init_db()

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def test_safe_search_treats_payload_as_data(self):
        rows, sql = app.search_products("' OR '1'='1' --", vulnerable=False)
        self.assertEqual(rows, [])
        self.assertIn("LIKE ?", sql)

    def test_normal_search_finds_product(self):
        rows, _ = app.search_products("teclado", vulnerable=False)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], "Teclado mecánico")

    def test_vulnerable_search_demonstrates_injection_in_local_db(self):
        rows, sql = app.search_products("' OR '1'='1' --", vulnerable=True)
        self.assertGreater(len(rows), 0)
        self.assertIn("OR '1'='1'", sql)


if __name__ == "__main__":
    unittest.main()
