from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

PACK_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACK_ROOT))

# Attune's local test runner does not install runtime dependencies. Unit tests
# inject every HTTP session, so a minimal import shim is sufficient there.
try:
    import requests  # noqa: F401
except ImportError:
    requests_module = ModuleType("requests")
    requests_module.RequestException = type("RequestException", (Exception,), {})
    requests_module.JSONDecodeError = type("JSONDecodeError", (ValueError,), {})
    requests_module.Session = lambda: None
    sys.modules["requests"] = requests_module

from lib import gitlab_client


EXPECTED_ACTIONS = {
    "cancel_job", "cancel_pipeline", "get_issue", "get_job", "get_merge_request",
    "get_pipeline", "get_project", "list_issues", "list_jobs",
    "list_merge_requests", "list_pipelines", "list_projects", "retry_job",
    "retry_pipeline", "trigger_pipeline",
}


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Response:
    def __init__(self, data, status=200, headers=None, next_url=None):
        self.data = data
        self.status_code = status
        self.headers = headers or {}
        self.links = {"next": {"url": next_url}} if next_url else {}

    def json(self):
        if isinstance(self.data, Exception):
            raise self.data
        return self.data


class Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def config(**overrides):
    return {
        "base_url": "https://gitlab.example.invalid",
        "token": "synthetic-token",
        **overrides,
    }


class PackTests(unittest.TestCase):
    def test_action_contracts_are_flat_and_key_backed(self):
        documents = [(path, path.read_text()) for path in sorted((PACK_ROOT / "actions").glob("*.yaml"))]
        refs = {
            next(line for line in text.splitlines() if line.startswith("ref: ")).split(".", 1)[1]
            for _, text in documents
        }
        self.assertEqual(refs, EXPECTED_ACTIONS)
        for path, text in documents:
            self.assertIn("runner_type: python\n", text, str(path))
            self.assertIn("entry_point: gitlab_action.py\n", text, str(path))
            self.assertIn("parameter_delivery: stdin\n", text, str(path))
            self.assertIn("parameter_format: json\n", text, str(path))
            self.assertIn("output_format: json\n", text, str(path))
            self.assertIn("default_execution_permission_set_refs: [standard]\n", text, str(path))
            self.assertIn('default: "pack.gitlab.credentials", key_ref: true', text, str(path))
            self.assertIn("  operation: {type: string, required: true}\n", text, str(path))
            self.assertIn("  result: {type: object, required: true}\n", text, str(path))
            self.assertNotIn("\n  token:", text, str(path))
            self.assertNotIn("\n  url:", text, str(path))

    def test_client_auth_tls_timeout_and_https_defaults(self):
        private = gitlab_client.GitLabClient(config(), session=Session([]))
        oauth = gitlab_client.GitLabClient(
            config(auth_type="oauth", verify_tls=False, connect_timeout_seconds=4, read_timeout_seconds=12),
            session=Session([]),
        )
        self.assertEqual(private.headers["PRIVATE-TOKEN"], "synthetic-token")
        self.assertEqual(oauth.headers["Authorization"], "Bearer synthetic-token")
        self.assertFalse(oauth.verify)
        self.assertEqual(oauth.timeout, (4.0, 12.0))
        invalid = [
            {},
            {"base_url": "http://gitlab.example.invalid", "token": "x"},
            config(base_url="https://user:pass@gitlab.example.invalid"),
            config(auth_type="basic"),
            config(verify_tls="false"),
            config(connect_timeout_seconds=0),
            config(max_get_rate_limit_retries=6),
            config(ca_bundle="relative.pem"),
            config(base_url="https://gitlab.example.invalid:invalid"),
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(gitlab_client.GitLabPackError):
                gitlab_client.GitLabClient(value, session=Session([]))

    def test_project_path_is_encoded_and_response_is_structured(self):
        session = Session([Response({"id": 42, "path_with_namespace": "group/sub/project"})])
        client = gitlab_client.GitLabClient(config(), session=session)
        result = client.request("GET", "/projects/group%2Fsub%2Fproject")
        self.assertEqual(result["id"], 42)
        method, url, kwargs = session.calls[0]
        self.assertEqual(method, "GET")
        self.assertEqual(url, "https://gitlab.example.invalid/api/v4/projects/group%2Fsub%2Fproject")
        self.assertEqual(kwargs["timeout"], (10.0, 30.0))
        self.assertTrue(kwargs["verify"])
        self.assertFalse(kwargs["allow_redirects"])

    def test_pagination_follows_same_api_links_and_is_bounded(self):
        page_2 = "https://gitlab.example.invalid/api/v4/projects?page=2&per_page=2"
        page_3 = "https://gitlab.example.invalid/api/v4/projects?page=3&per_page=2"
        session = Session([
            Response([{"id": 1}, {"id": 2}], next_url=page_2),
            Response([{"id": 3}, {"id": 4}], next_url=page_3),
        ])
        client = gitlab_client.GitLabClient(config(), session=session)
        result = client.paginate("/projects", {"membership": True}, per_page=2, max_pages=2)
        self.assertEqual(result, {"items": [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}], "count": 4, "pages_fetched": 2, "truncated": True})
        self.assertEqual(session.calls[0][2]["params"], {"membership": True, "per_page": 2})
        self.assertIsNone(session.calls[1][2]["params"])

        hostile = Session([Response([], next_url="https://attacker.invalid/api/v4/projects?page=2")])
        with self.assertRaisesRegex(gitlab_client.GitLabPackError, "escaped"):
            gitlab_client.GitLabClient(config(), session=hostile).paginate("/projects", {}, per_page=100, max_pages=2)

    def test_get_rate_limit_retry_is_capped_and_mutations_are_not_retried(self):
        sleeps = []
        session = Session([
            Response({"message": "limit and synthetic-token"}, status=429, headers={"Retry-After": "999"}),
            Response({"id": 1}),
        ])
        client = gitlab_client.GitLabClient(config(), session=session, sleep=sleeps.append)
        self.assertEqual(client.request("GET", "/projects/1"), {"id": 1})
        self.assertEqual(sleeps, [60.0])
        self.assertEqual(len(session.calls), 2)

        mutation = Session([Response({"message": "synthetic-token SECRET_BODY"}, status=429, headers={"Retry-After": "8", "X-Request-Id": "req-1"})])
        with self.assertRaises(gitlab_client.GitLabPackError) as raised:
            gitlab_client.GitLabClient(config(), session=mutation).request("POST", "/projects/1/pipelines/2/retry")
        message = str(raised.exception)
        self.assertIn("status 429", message)
        self.assertIn("retry_after=8", message)
        self.assertIn("request_id=req-1", message)
        self.assertNotIn("SECRET_BODY", message)
        self.assertNotIn("synthetic-token", message)
        self.assertEqual(len(mutation.calls), 1)

    def test_redirects_and_invalid_json_fail_without_response_content(self):
        redirect = Session([Response("https://contains-synthetic-token.invalid", status=302, headers={"Location": "https://attacker.invalid"})])
        with self.assertRaisesRegex(gitlab_client.GitLabPackError, "redirect status 302") as raised:
            gitlab_client.GitLabClient(config(), session=redirect).request("GET", "/projects/1")
        self.assertNotIn("attacker", str(raised.exception))

        invalid = Session([Response(ValueError("synthetic-token invalid response"))])
        with self.assertRaisesRegex(gitlab_client.GitLabPackError, "invalid JSON") as raised:
            gitlab_client.GitLabClient(config(), session=invalid).request("GET", "/projects/1")
        self.assertNotIn("synthetic-token", str(raised.exception))

    def test_secret_like_response_fields_and_url_userinfo_are_masked(self):
        session = Session([Response({
            "id": 1,
            "runners_token": "server-secret",
            "ci_job_token_scope_enabled": True,
            "import_url": "https://user:password@example.invalid/repo.git",
            "description": "synthetic-token appears here",
        })])
        result = gitlab_client.GitLabClient(config(), session=session).request("GET", "/projects/1")
        self.assertEqual(result["runners_token"], "REDACTED")
        self.assertTrue(result["ci_job_token_scope_enabled"])
        self.assertEqual(result["import_url"], "https://example.invalid/repo.git")
        self.assertEqual(result["description"], "REDACTED appears here")

    def test_transport_os_errors_are_wrapped_without_details(self):
        class BrokenSession:
            def request(self, *args, **kwargs):
                raise OSError("/sensitive/ca/path")

        with self.assertRaises(gitlab_client.GitLabPackError) as raised:
            gitlab_client.GitLabClient(config(), session=BrokenSession()).request("GET", "/projects/1")
        self.assertIn("transport failed", str(raised.exception))
        self.assertNotIn("sensitive", str(raised.exception))

    def test_source_operations_use_current_endpoints_and_json_body(self):
        sessions = []

        def credentials(_ref):
            return config()

        def make_client(value):
            session = Session([Response(value)])
            sessions.append(session)
            return gitlab_client.GitLabClient(config(), session=session)

        with patch.object(gitlab_client, "_fetch_key", side_effect=credentials), patch.object(
            gitlab_client, "GitLabClient", side_effect=[
                make_client({"id": 1}),
                make_client({"id": 2}),
                make_client({"id": 3}),
            ],
        ):
            gitlab_client.execute_action("get_project", {"project": "group/sub/project"})
            gitlab_client.execute_action("get_issue", {"project": "group/sub/project", "issue_iid": 7})
            result = gitlab_client.execute_action("trigger_pipeline", {
                "project": "group/sub/project",
                "ref": "main",
                "variables": {"DEPLOY": "true"},
                "inputs": {"environment": "test"},
            })
        self.assertEqual(result, {"id": 3})
        self.assertTrue(sessions[0].calls[0][1].endswith("/projects/group%2Fsub%2Fproject"))
        self.assertTrue(sessions[1].calls[0][1].endswith("/projects/group%2Fsub%2Fproject/issues/7"))
        method, url, kwargs = sessions[2].calls[0]
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/projects/group%2Fsub%2Fproject/pipeline"))
        self.assertEqual(kwargs["json"], {
            "ref": "main",
            "variables": [{"key": "DEPLOY", "value": "true"}],
            "inputs": {"environment": "test"},
        })

    def test_job_list_and_all_current_mutation_routes(self):
        sessions = []

        def client_for(data):
            session = Session([Response(data)])
            sessions.append(session)
            return gitlab_client.GitLabClient(config(), session=session)

        clients = [client_for([])] + [client_for({"status": "pending"}) for _ in range(4)]
        with patch.object(gitlab_client, "_fetch_key", return_value=config()), patch.object(gitlab_client, "GitLabClient", side_effect=clients):
            listed = gitlab_client.execute_action("list_jobs", {"project": "g/p", "pipeline_id": 9, "scopes": ["failed"], "include_retried": True})
            gitlab_client.execute_action("cancel_pipeline", {"project": "g/p", "pipeline_id": 9})
            gitlab_client.execute_action("retry_pipeline", {"project": "g/p", "pipeline_id": 9})
            gitlab_client.execute_action("cancel_job", {"project": "g/p", "job_id": 10})
            gitlab_client.execute_action("retry_job", {"project": "g/p", "job_id": 10})
        self.assertEqual(listed["count"], 0)
        self.assertEqual(sessions[0].calls[0][2]["params"], {"scope[]": ["failed"], "include_retried": True, "per_page": 100})
        suffixes = [session.calls[0][1].split("/api/v4", 1)[1] for session in sessions[1:]]
        self.assertEqual(suffixes, [
            "/projects/g%2Fp/pipelines/9/cancel",
            "/projects/g%2Fp/pipelines/9/retry",
            "/projects/g%2Fp/jobs/10/cancel",
            "/projects/g%2Fp/jobs/10/retry",
        ])
        self.assertTrue(all(session.calls[0][0] == "POST" for session in sessions[1:]))

        project_jobs = client_for([])
        with patch.object(gitlab_client, "_fetch_key", return_value=config()), patch.object(gitlab_client, "GitLabClient", return_value=project_jobs):
            gitlab_client.execute_action("list_jobs", {"project": "g/p"})
        self.assertEqual(project_jobs.session.calls[0][2]["params"], {
            "pagination": "keyset", "order_by": "id", "sort": "desc", "per_page": 100,
        })

    def test_parameter_validation_rejects_ambiguous_ids_and_variables(self):
        cases = [
            ("get_issue", {"project": "g/p", "issue_iid": True}),
            ("get_pipeline", {"project": "g/p", "pipeline_id": 0}),
            ("trigger_pipeline", {"project": "g/p", "ref": "main", "variables": {"A": 1}}),
            ("list_jobs", {"project": "g/p", "scopes": []}),
            ("list_jobs", {"project": "g/p", "scopes": ["unknown"]}),
            ("list_jobs", {"project": "g/p", "include_retried": True}),
        ]
        with patch.object(gitlab_client, "_fetch_key", return_value=config()):
            for operation, params in cases:
                with self.subTest(operation=operation), self.assertRaises(gitlab_client.GitLabPackError):
                    gitlab_client.execute_action(operation, params)

    def test_key_lookup_uses_current_sdk_signature(self):
        calls = {}
        get_key = ModuleType("attune.api_client.api.secrets.get_key")
        get_key.sync_detailed = lambda ref, *, client: calls.update(ref=ref, client=client) or SimpleNamespace(
            status_code=200,
            parsed=SimpleNamespace(data=SimpleNamespace(value={"base_url": "https://gitlab.example.invalid", "token": "synthetic"})),
        )
        secrets = ModuleType("attune.api_client.api.secrets")
        secrets.get_key = get_key
        attune = ModuleType("attune")
        attune.context = SimpleNamespace(client="execution-client")
        modules = {
            "attune": attune,
            "attune.api_client": ModuleType("attune.api_client"),
            "attune.api_client.api": ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": secrets,
        }
        with patch.dict(sys.modules, modules):
            gitlab_client._fetch_key("pack.gitlab.credentials")
        self.assertEqual(calls, {"ref": "pack.gitlab.credentials", "client": "execution-client"})

    def test_entrypoint_rejects_malformed_json_without_echoing_it(self):
        module = load_module("gitlab_action_test", PACK_ROOT / "actions" / "gitlab_action.py")
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "stdin", SimpleNamespace(read=lambda: '{"token":"DO_NOT_PRINT"')), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(module.main(), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("DO_NOT_PRINT", stderr.getvalue())

    def test_source_metadata_and_no_secret_fixtures(self):
        source = (PACK_ROOT / "SOURCE.md").read_text()
        self.assertIn("77b62e6db46d6ba8e0ccbcaddef9818cdffb257e", source)
        self.assertIn("Apache-2.0", source)
        forbidden = ["glpat" + "-live", "PRIVATE-TOKEN" + ": production", "Bearer" + " production"]
        for path in PACK_ROOT.rglob("*"):
            if path.is_file() and path.suffix in {".py", ".yaml", ".md", ".txt"}:
                text = path.read_text(encoding="utf-8")
                self.assertFalse(any(value in text for value in forbidden), str(path))


if __name__ == "__main__":
    unittest.main()
