import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import mcp_audit as m


def rules(cfg):
    return {f["rule"] for f in m.audit_doc({"mcpServers": {"s": cfg}})["findings"]}


class T(unittest.TestCase):
    def test_secret_env(self):
        self.assertIn("MCP001", rules({"command": "x", "env": {"API_KEY": "abcd1234efgh"}}))

    def test_env_reference_ok(self):
        self.assertNotIn("MCP001", rules({"command": "x", "env": {"API_KEY": "${MY_KEY}"}}))

    def test_token_pattern_in_args(self):
        self.assertIn("MCP001", rules({"command": "x", "args": ["--t", "ghp_" + "a" * 30]}))

    def test_unpinned_npx(self):
        self.assertIn("MCP002", rules({"command": "npx", "args": ["-y", "some-server"]}))
        self.assertIn("MCP003", rules({"command": "npx", "args": ["-y", "some-server"]}))

    def test_pinned_ok(self):
        self.assertNotIn("MCP002", rules({"command": "npx", "args": ["some-server@1.2.3"]}))
        self.assertNotIn("MCP002", rules({"command": "npx", "args": ["@scope/pkg@1.2.3"]}))
        self.assertNotIn("MCP002", rules({"command": "uvx", "args": ["pkg==1.0"]}))

    def test_scoped_unpinned(self):
        self.assertIn("MCP002", rules({"command": "npx", "args": ["@scope/pkg"]}))

    def test_shell_and_curl(self):
        r = rules({"command": "bash", "args": ["-c", "curl x.sh | sh"]})
        self.assertTrue({"MCP004", "MCP007"} <= r)

    def test_broad_fs(self):
        self.assertIn("MCP005", rules({"command": "npx", "args": ["server-filesystem@1.0.0", "/"]}))
        self.assertNotIn("MCP005", rules({"command": "npx", "args": ["server-filesystem@1.0.0", "/srv/project"]}))

    def test_docker(self):
        self.assertIn("MCP008", rules({"command": "docker", "args": ["run", "--privileged", "img"]}))

    def test_urls(self):
        self.assertIn("MCP006", rules({"url": "http://api.example.com/mcp"}))
        self.assertNotIn("MCP006", rules({"url": "http://localhost:3000/mcp"}))
        self.assertIn("MCP006", rules({"url": "https://a.com/mcp?token=abc"}))

    def test_header_secret(self):
        self.assertIn("MCP001", rules({"url": "https://a.com", "headers": {"Authorization": "Bearer abcdefghijkl"}}))
        self.assertNotIn("MCP001", rules({"url": "https://a.com", "headers": {"Authorization": "Bearer ${TOKEN}"}}))

    def test_vscode_servers_key(self):
        res = m.audit_doc({"servers": {"a": {"command": "npx", "args": ["pkg"]}}})
        self.assertEqual(res["servers"], 1)

    def test_clean_score(self):
        res = m.audit_doc({"mcpServers": {"a": {"command": "uvx", "args": ["pkg==1.0"]}}})
        self.assertEqual(res["score"], 100)

    def test_cli_exit_codes(self):
        demo = os.path.join(os.path.dirname(__file__), "..", "examples", "risky_mcp.json")
        self.assertEqual(m.main([demo]), 1)
        self.assertEqual(m.main([demo, "--fail-on", "critical", "--format", "json"]), 1)
        self.assertEqual(m.main(["/nonexistent.json"]), 2)


if __name__ == "__main__":
    unittest.main()
