from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from appsec_scan_router.environment import load_environment_file, project_environment


class EnvironmentFileTests(unittest.TestCase):
    def test_environment_file_supplies_missing_values_without_overriding_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                "APPLICATION_INVENTORY_GITHUB_APP_ID=123\n"
                "APPLICATION_INVENTORY_INVICTI_TOKEN='from-file'\n"
                "EXPLICIT_VALUE=from-file\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"EXPLICIT_VALUE": "from-process"}, clear=True):
                loaded = load_environment_file(env_file)

                self.assertEqual(loaded, env_file)
                self.assertEqual(os.environ["APPLICATION_INVENTORY_GITHUB_APP_ID"], "123")
                self.assertEqual(os.environ["APPLICATION_INVENTORY_INVICTI_TOKEN"], "from-file")
                self.assertEqual(os.environ["EXPLICIT_VALUE"], "from-process")

    def test_scoped_project_environment_restores_added_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text("SCOPED_VALUE=from-file\n", encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True):
                with project_environment(env_file):
                    self.assertEqual(os.environ["SCOPED_VALUE"], "from-file")
                self.assertNotIn("SCOPED_VALUE", os.environ)


if __name__ == "__main__":
    unittest.main()