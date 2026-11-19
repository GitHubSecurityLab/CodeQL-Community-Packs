import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "build-query-suite-table.sh"


class QuerySuiteTableTests(unittest.TestCase):
    def run_table(self, response):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("cpp", "cpp-audit"):
                suite = root / "cpp" / "src" / "suites" / f"{name}.qls"
                suite.parent.mkdir(parents=True, exist_ok=True)
                suite.touch()
            binary = root / "bin" / "codeql"
            binary.parent.mkdir()
            binary.write_text("#!/usr/bin/env bash\n" + response)
            binary.chmod(0o755)
            env = dict(os.environ, PATH=f"{binary.parent}:{os.environ['PATH']}",
                       GITHUB_REPOSITORY="example/packs", GITHUB_SHA="abc123")
            return subprocess.run(
                ["bash", str(SCRIPT), "upstream"],
                cwd=root, env=env, text=True, capture_output=True,
            )

    def test_counts_and_commit_links(self):
        result = self.run_table(
            '[[ "$*" == "resolve queries --format=json --additional-packs=. '
            '--search-path=upstream cpp/src/suites/"* ]] || exit 2\n'
            'case "${@: -1}" in\n'
            '  *-audit.qls) echo \'[]\' ;;\n'
            '  *) echo \'["first.ql", "second.ql"]\' ;;\n'
            'esac\n'
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("<details>\n<summary>Query suites and query counts</summary>", result.stdout)
        self.assertIn(
            "| C++ | [`cpp-audit`](https://github.com/example/packs/blob/"
            "abc123/cpp/src/suites/cpp-audit.qls) | 0 |", result.stdout,
        )
        self.assertIn(
            "| C++ | [`cpp`](https://github.com/example/packs/blob/"
            "abc123/cpp/src/suites/cpp.qls) | 2 |", result.stdout,
        )
        self.assertTrue(result.stdout.endswith("</details>\n"))

    def test_resolution_failure_does_not_skip_later_suites(self):
        result = self.run_table(
            'case "${@: -1}" in\n'
            '  *-audit.qls) echo "resolver error" >&2; exit 1 ;;\n'
            '  *) echo \'["query.ql"]\' ;;\n'
            'esac\n'
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("::error::Could not count queries for cpp/src/suites/cpp-audit.qls",
                      result.stderr)
        self.assertIn("| Resolution failed |", result.stdout)
        self.assertIn("abc123/cpp/src/suites/cpp.qls) | 1 |", result.stdout)

    def test_invalid_resolver_output_is_not_a_count(self):
        result = self.run_table('echo \'{"error": "not a query array"}\'\n')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.count("| Resolution failed |"), 2)


if __name__ == "__main__":
    unittest.main()
