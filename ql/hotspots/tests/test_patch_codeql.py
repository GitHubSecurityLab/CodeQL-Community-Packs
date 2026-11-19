import json
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


class RenamePacksTest(unittest.TestCase):
    def test_model_pack_references(self):
        with patch.object(sys, "argv", ["patch-codeql.py", "--hotspots", ".", "--ql", ".", "--dest", "."]):
            with patch.object(sys, "path", [str(SCRIPTS), *sys.path]):
                patcher = runpy.run_path(str(SCRIPTS / "patch-codeql.py"))

        with tempfile.TemporaryDirectory() as directory:
            for language in patcher["LANGUAGES"]:
                lib = Path(directory) / language / "ql" / "lib"
                lib.mkdir(parents=True)
                src = lib.parent / "src"
                src.mkdir()
                (lib / "qlpack.yml").write_text(f"name: codeql/{language}-all\n")
                (lib / "model.yml").write_text(
                    f"pack: codeql/{language}-all\npack: codeql/threat-models\n"
                )
                for pack in (lib, src):
                    (pack / "model.json").write_text(
                        json.dumps(
                            {
                                "extensions": [
                                    {"addsTo": {"pack": f"codeql/{language}-all"}},
                                    {"addsTo": {"pack": "codeql/threat-models"}},
                                    {"data": [f"codeql/{language}-all"]},
                                ]
                            }
                        ).replace('"pack":', '"pack" :  ', 1)
                    )
                (src / "model.yml").write_text(f"pack: codeql/{language}-all\n")

            patcher["rename_ql_packs"](directory)

            for language in patcher["LANGUAGES"]:
                lib = Path(directory) / language / "ql" / "lib"
                renamed = f"githubsecuritylab/hotspots-{language}-all"
                self.assertEqual((lib / "qlpack.yml").read_text(), f"name: {renamed}\n")
                self.assertEqual(
                    (lib / "model.yml").read_text(),
                    f"pack: {renamed}\npack: codeql/threat-models\n",
                )
                src = lib.parent / "src"
                self.assertEqual((src / "model.yml").read_text(), f"pack: {renamed}\n")
                for pack in (lib, src):
                    extensions = json.loads((pack / "model.json").read_text())["extensions"]
                    self.assertEqual(extensions[0]["addsTo"]["pack"], renamed)
                    self.assertEqual(extensions[1]["addsTo"]["pack"], "codeql/threat-models")
                    self.assertEqual(extensions[2]["data"], [f"codeql/{language}-all"])


if __name__ == "__main__":
    unittest.main()
