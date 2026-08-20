import os
from pathlib import Path
import shutil
import tempfile
import unittest

from wdtt_panel.wdtt_server_patch import EXTENSION_MARKER, patch_spaceneurox_tree


class WdttServerPatchTests(unittest.TestCase):
    def test_rejects_an_unknown_source_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "missing server/main.go"):
                patch_spaceneurox_tree(Path(directory))

    @unittest.skipUnless(os.environ.get("QWDTT_SOURCE"), "set QWDTT_SOURCE for upstream integration test")
    def test_patches_the_official_v1_4_2_tree_idempotently(self):
        source = Path(os.environ["QWDTT_SOURCE"]).resolve()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / "qwdtt"
            shutil.copytree(source, work, ignore=shutil.ignore_patterns(".git", "panel_extension.go", "panel_extension_test.go"))
            patch_spaceneurox_tree(work)
            patch_spaceneurox_tree(work)

            extension = (work / "server" / "panel_extension.go").read_text(encoding="utf-8")
            database = (work / "server" / "database_bot.go").read_text(encoding="utf-8")
            connections = (work / "server" / "connections.go").read_text(encoding="utf-8")
            self.assertIn(EXTENSION_MARKER, extension)
            self.assertIn('json:"traffic_operations,omitempty"', database)
            self.assertIn('json:"main_down_bytes,omitempty"', database)
            self.assertIn("applyPasswordRestrictionsLocked", database)
            self.assertIn("DENIED:traffic_limit", connections)


if __name__ == "__main__":
    unittest.main()
