from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]

from appsec_scan_router.environment import (
    load_environment_file,
    project_environment,
    project_environment_path,
)


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

    def test_appsec_atlas_environment_file_overrides_legacy_setting(self) -> None:
        with patch.dict(
            os.environ,
            {
                "APPSEC_ATLAS_ENV_FILE": "/tmp/appsec-atlas.env",
                "APPLICATION_INVENTORY_ENV_FILE": "/tmp/legacy.env",
            },
            clear=True,
        ):
            self.assertEqual(project_environment_path(), Path("/tmp/appsec-atlas.env"))

    def test_appsec_atlas_console_commands_preserve_legacy_aliases(self) -> None:
        pyproject = tomllib.loads(
            (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(
                encoding="utf-8"
            )
        )
        scripts = pyproject["project"]["scripts"]

        self.assertEqual(scripts["appsec-atlas"], "appsec_atlas.cli:main")
        self.assertEqual(scripts["appsec-atlas-ui"], "appsec_atlas.ui:main")
        self.assertEqual(scripts["appsec-atlas-aspm"], "appsec_atlas.aspm:main")
        self.assertEqual(
            scripts["application-inventory-service"], "appsec_atlas.cli:main"
        )


if __name__ == "__main__":
    unittest.main()