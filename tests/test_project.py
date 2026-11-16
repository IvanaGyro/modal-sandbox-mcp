"""Tests that run without Modal credentials or installed Modal dependencies."""
import ast
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ProjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse((ROOT / "modal_mcp.py").read_text(encoding="utf-8"))

    def test_six_tools_declared(self):
        nested = [n.name for n in ast.walk(self.tree) if isinstance(n, ast.FunctionDef)]
        for name in ("create_sandbox", "exec_command", "read_file", "write_file", "sandbox_status", "terminate_sandbox"):
            self.assertIn(name, nested)

    def test_authentication_fail_closed(self):
        src = (ROOT / "modal_mcp.py").read_text()
        self.assertIn("unauthenticated mode is forbidden", src)
        self.assertIn("RemoteAuthProvider", src)
        self.assertIn("stateless_http=True", src)

    def test_workflows_exist(self):
        self.assertTrue((ROOT / ".github/workflows/check.yml").exists())
        self.assertTrue((ROOT / ".github/workflows/deploy.yml").exists())


if __name__ == "__main__":
    unittest.main()
