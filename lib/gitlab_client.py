"""Bounded GitLab REST API v4 client adapted from stackstorm-gitlab 1.0.1."""

from __future__ import annotations

import json
import math
import time
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import requests


class GitLabPackError(RuntimeError):
    """Safe operator-facing GitLab pack error."""


_SECRET_FIELDS = {
    "access_token", "api_token", "private_token", "refresh_token", "runner_token",
    "runners_token", "secret", "token", "trigger_token", "password",
}

_JOB_STATUSES = {
    "canceled", "canceling", "created", "failed", "manual", "pending",
    "preparing", "running", "scheduled", "skipped", "success",
    "waiting_for_callback", "waiting_for_resource",
}


def _fetch_key(ref: str) -> Dict[str, Any]:
    if not isinstance(ref, str) or not ref:
        raise GitLabPackError("credential_key must be a non-empty string")
    try:
        import attune
        from attune.api_client.api.secrets import get_key
    except ImportError as exc:
        raise GitLabPackError("attune-sdk is required to resolve credential_key") from exc
    try:
        response = get_key.sync_detailed(ref, client=attune.context.client)
    except Exception as exc:
        raise GitLabPackError(f"unable to read credential Key {ref!r}") from exc
    status = int(response.status_code)
    if status == 404:
        raise GitLabPackError(f"credential Key {ref!r} was not found")
    if status >= 400 or not response.parsed:
        raise GitLabPackError(f"credential Key lookup failed with status {status}")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise GitLabPackError("credential Key must contain a JSON object") from exc
    if not isinstance(value, dict):
        raise GitLabPackError("credential Key must contain an object")
    return value


def _number(config: Mapping[str, Any], name: str, default: float, low: float, high: float) -> float:
    value = config.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GitLabPackError(f"{name} must be a number")
    result = float(value)
    if not math.isfinite(result) or result < low or result > high:
        raise GitLabPackError(f"{name} must be between {low:g} and {high:g}")
    return result


def _integer(value: Any, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < low or value > high:
        raise GitLabPackError(f"{name} must be an integer between {low} and {high}")
    return value


def _positive_id(value: Any, name: str) -> int:
    return _integer(value, name, 1, 2**63 - 1)


def _project(value: Any) -> str:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise GitLabPackError("project must be a non-empty string or integer")
    text = str(value)
    if not text or any(ord(character) < 32 for character in text):
        raise GitLabPackError("project must be a non-empty string or integer")
    return quote(text, safe="")


def _clean_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        if not parts.username and not parts.password:
            return value
        host = parts.hostname or ""
        if parts.port is not None:
            host = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
    except ValueError:
        return "REDACTED_URL"


def _redact(value: Any, secrets: Iterable[str] = ()) -> Any:
    secret_values = tuple(item for item in secrets if item)
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            normalized = str(key).lower()
            sensitive = normalized in _SECRET_FIELDS or normalized.endswith(("_password", "_secret", "_token"))
            result[key] = "REDACTED" if sensitive else _redact(item, secret_values)
        return result
    if isinstance(value, list):
        return [_redact(item, secret_values) for item in value]
    if isinstance(value, str):
        result = _clean_url(value) if "://" in value else value
        for secret in secret_values:
            result = result.replace(secret, "REDACTED")
        return result
    return value


class GitLabClient:
    def __init__(self, config: Mapping[str, Any], *, session: Any = None, sleep: Any = time.sleep):
        base_url = config.get("base_url") or config.get("url")
        if not isinstance(base_url, str) or not base_url:
            raise GitLabPackError("credential Key requires base_url")
        if base_url != base_url.strip() or any(ord(character) < 32 for character in base_url):
            raise GitLabPackError("base_url must not contain whitespace or control characters")
        try:
            parts = urlsplit(base_url.rstrip("/"))
            hostname = parts.hostname
            parts.port
        except ValueError as exc:
            raise GitLabPackError("base_url is not a valid URL") from exc
        allow_http = config.get("allow_insecure_http", False)
        if not isinstance(allow_http, bool):
            raise GitLabPackError("allow_insecure_http must be a boolean")
        if parts.scheme not in {"http", "https"} or not parts.netloc or not hostname or parts.username or parts.password:
            raise GitLabPackError("base_url must be an HTTP(S) URL without credentials")
        if parts.query or parts.fragment:
            raise GitLabPackError("base_url must not contain a query or fragment")
        if parts.scheme != "https" and not allow_http:
            raise GitLabPackError("base_url must use HTTPS unless allow_insecure_http is true")

        token = config.get("token") or config.get("access_token")
        if not isinstance(token, str) or not token:
            raise GitLabPackError("credential Key requires token")
        auth_type = config.get("auth_type", "private_token")
        if auth_type not in {"private_token", "oauth"}:
            raise GitLabPackError("auth_type must be private_token or oauth")
        verify_tls = config.get("verify_tls", True)
        if not isinstance(verify_tls, bool):
            raise GitLabPackError("verify_tls must be a boolean")
        ca_bundle = config.get("ca_bundle")
        if ca_bundle is not None:
            if not isinstance(ca_bundle, str) or not Path(ca_bundle).is_absolute():
                raise GitLabPackError("ca_bundle must be an absolute path")
            if not verify_tls:
                raise GitLabPackError("ca_bundle cannot be used when verify_tls is false")

        self.api_root = f"{base_url.rstrip('/')}/api/v4"
        self._api_parts = urlsplit(self.api_root)
        self.headers = {"Accept": "application/json"}
        self.headers["PRIVATE-TOKEN" if auth_type == "private_token" else "Authorization"] = (
            token if auth_type == "private_token" else f"Bearer {token}"
        )
        self.verify = ca_bundle or verify_tls
        self.timeout = (
            _number(config, "connect_timeout_seconds", 10, 1, 120),
            _number(config, "read_timeout_seconds", 30, 1, 300),
        )
        retries = config.get("max_get_rate_limit_retries", 2)
        self.max_get_rate_limit_retries = _integer(retries, "max_get_rate_limit_retries", 0, 5)
        self.session = session or requests.Session()
        self.sleep = sleep
        self._token = token

    def _api_url(self, endpoint: str) -> str:
        if not endpoint.startswith("/") or endpoint.startswith("//"):
            raise GitLabPackError("invalid internal GitLab API endpoint")
        return f"{self.api_root}{endpoint}"

    def _same_api(self, url: str) -> bool:
        parts = urlsplit(url)
        root_path = self._api_parts.path.rstrip("/")
        return (
            parts.scheme == self._api_parts.scheme
            and parts.netloc == self._api_parts.netloc
            and (parts.path == root_path or parts.path.startswith(f"{root_path}/"))
            and not parts.fragment
        )

    @staticmethod
    def _retry_after(response: Any) -> float:
        raw = response.headers.get("Retry-After", "")
        try:
            return min(60.0, max(0.0, float(raw)))
        except (TypeError, ValueError):
            try:
                delay = parsedate_to_datetime(raw).timestamp() - time.time()
                return min(60.0, max(0.0, delay))
            except (TypeError, ValueError, OverflowError, IndexError):
                return 1.0

    def _send(self, method: str, url: str, *, params: Mapping[str, Any] | None = None, body: Any = None) -> Any:
        if not self._same_api(url):
            raise GitLabPackError("GitLab pagination link escaped the configured API origin")
        attempts = self.max_get_rate_limit_retries + 1 if method == "GET" else 1
        for attempt in range(attempts):
            kwargs: Dict[str, Any] = {
                "headers": self.headers,
                "params": params,
                "timeout": self.timeout,
                "verify": self.verify,
                "allow_redirects": False,
            }
            if body is not None:
                kwargs["json"] = body
            try:
                response = self.session.request(method, url, **kwargs)
            except (requests.RequestException, OSError) as exc:
                raise GitLabPackError(f"GitLab API {method} transport failed ({type(exc).__name__})") from exc
            if response.status_code == 429 and method == "GET" and attempt + 1 < attempts:
                self.sleep(self._retry_after(response))
                continue
            break

        status = int(response.status_code)
        if 300 <= status < 400:
            raise GitLabPackError(f"GitLab API {method} refused HTTP redirect status {status}")
        if status >= 400:
            details = []
            request_id = response.headers.get("X-Request-Id")
            retry_after = response.headers.get("Retry-After")
            if request_id and len(request_id) <= 128 and request_id.isprintable():
                details.append(f"request_id={request_id.replace(self._token, 'REDACTED')}")
            if status == 429 and retry_after and len(retry_after) <= 64 and retry_after.isprintable():
                details.append(f"retry_after={retry_after.replace(self._token, 'REDACTED')}")
            suffix = f" ({', '.join(details)})" if details else ""
            raise GitLabPackError(f"GitLab API {method} failed with HTTP status {status}{suffix}")
        return response

    def _decode(self, response: Any) -> Any:
        if int(response.status_code) == 204:
            return None
        try:
            data = response.json()
        except (ValueError, requests.JSONDecodeError) as exc:
            raise GitLabPackError("GitLab API returned invalid JSON") from exc
        return _redact(data, (self._token,))

    def request(self, method: str, endpoint: str, *, params: Mapping[str, Any] | None = None, body: Any = None) -> Any:
        return self._decode(self._send(method, self._api_url(endpoint), params=params, body=body))

    def paginate(self, endpoint: str, params: Mapping[str, Any], *, per_page: int, max_pages: int) -> Dict[str, Any]:
        per_page = _integer(per_page, "per_page", 1, 100)
        max_pages = _integer(max_pages, "max_pages", 1, 100)
        url = self._api_url(endpoint)
        first_params = {**params, "per_page": per_page}
        items = []
        next_url = None
        pages = 0
        while pages < max_pages:
            response = self._send("GET", url, params=first_params if pages == 0 else None)
            data = self._decode(response)
            if not isinstance(data, list):
                raise GitLabPackError("GitLab list endpoint returned a non-array response")
            items.extend(data)
            pages += 1
            next_link = (getattr(response, "links", {}) or {}).get("next", {}).get("url")
            if next_link is not None and not isinstance(next_link, str):
                raise GitLabPackError("GitLab API returned an invalid pagination link")
            next_url = urljoin(url, next_link) if next_link else None
            if not next_url:
                break
            if not self._same_api(next_url):
                raise GitLabPackError("GitLab pagination link escaped the configured API origin")
            url = next_url
        return {"items": items, "count": len(items), "pages_fetched": pages, "truncated": bool(next_url)}


def _client(params: Mapping[str, Any]) -> GitLabClient:
    ref = params.get("credential_key", "pack.gitlab.credentials")
    return GitLabClient(_fetch_key(ref))


def _query(params: Mapping[str, Any], names: Iterable[str]) -> Dict[str, Any]:
    return {name: params[name] for name in names if params.get(name) is not None}


def _list(client: GitLabClient, endpoint: str, params: Mapping[str, Any], filters: Iterable[str]) -> Dict[str, Any]:
    return client.paginate(
        endpoint,
        _query(params, filters),
        per_page=params.get("per_page", 100),
        max_pages=params.get("max_pages", 10),
    )


def list_projects(params: Mapping[str, Any]) -> Dict[str, Any]:
    return _list(_client(params), "/projects", params, ("archived", "membership", "order_by", "owned", "search", "simple", "sort", "visibility"))


def get_project(params: Mapping[str, Any]) -> Dict[str, Any]:
    result = _client(params).request("GET", f"/projects/{_project(params.get('project'))}", params=_query(params, ("license", "statistics")))
    if not isinstance(result, dict):
        raise GitLabPackError("GitLab project endpoint returned a non-object response")
    return result


def list_issues(params: Mapping[str, Any]) -> Dict[str, Any]:
    endpoint = f"/projects/{_project(params.get('project'))}/issues"
    filters = ("assignee_id", "author_id", "confidential", "labels", "order_by", "scope", "search", "sort", "state", "updated_after", "updated_before")
    return _list(_client(params), endpoint, params, filters)


def get_issue(params: Mapping[str, Any]) -> Dict[str, Any]:
    endpoint = f"/projects/{_project(params.get('project'))}/issues/{_positive_id(params.get('issue_iid'), 'issue_iid')}"
    result = _client(params).request("GET", endpoint)
    if not isinstance(result, dict):
        raise GitLabPackError("GitLab issue endpoint returned a non-object response")
    return result


def list_merge_requests(params: Mapping[str, Any]) -> Dict[str, Any]:
    endpoint = f"/projects/{_project(params.get('project'))}/merge_requests"
    filters = ("author_id", "draft", "labels", "order_by", "reviewer_id", "scope", "search", "sort", "source_branch", "state", "target_branch", "updated_after", "updated_before")
    return _list(_client(params), endpoint, params, filters)


def get_merge_request(params: Mapping[str, Any]) -> Dict[str, Any]:
    endpoint = f"/projects/{_project(params.get('project'))}/merge_requests/{_positive_id(params.get('merge_request_iid'), 'merge_request_iid')}"
    result = _client(params).request("GET", endpoint)
    if not isinstance(result, dict):
        raise GitLabPackError("GitLab merge request endpoint returned a non-object response")
    return result


def list_pipelines(params: Mapping[str, Any]) -> Dict[str, Any]:
    endpoint = f"/projects/{_project(params.get('project'))}/pipelines"
    filters = ("order_by", "ref", "scope", "sha", "sort", "source", "status", "updated_after", "updated_before")
    return _list(_client(params), endpoint, params, filters)


def get_pipeline(params: Mapping[str, Any]) -> Dict[str, Any]:
    endpoint = f"/projects/{_project(params.get('project'))}/pipelines/{_positive_id(params.get('pipeline_id'), 'pipeline_id')}"
    result = _client(params).request("GET", endpoint)
    if not isinstance(result, dict):
        raise GitLabPackError("GitLab pipeline endpoint returned a non-object response")
    return result


def trigger_pipeline(params: Mapping[str, Any]) -> Dict[str, Any]:
    ref = params.get("ref")
    if not isinstance(ref, str) or not ref:
        raise GitLabPackError("ref must be a non-empty string")
    variables = params.get("variables", {})
    if not isinstance(variables, dict) or not all(isinstance(key, str) and key and isinstance(value, str) for key, value in variables.items()):
        raise GitLabPackError("variables must map non-empty string keys to string values")
    body: Dict[str, Any] = {"ref": ref}
    if variables:
        body["variables"] = [{"key": key, "value": value} for key, value in variables.items()]
    inputs = params.get("inputs")
    if inputs is not None:
        if not isinstance(inputs, dict):
            raise GitLabPackError("inputs must be an object")
        body["inputs"] = inputs
    endpoint = f"/projects/{_project(params.get('project'))}/pipeline"
    result = _client(params).request("POST", endpoint, body=body)
    if not isinstance(result, dict):
        raise GitLabPackError("GitLab pipeline trigger returned a non-object response")
    return result


def list_jobs(params: Mapping[str, Any]) -> Dict[str, Any]:
    project = _project(params.get("project"))
    pipeline_id = params.get("pipeline_id")
    query: Dict[str, Any] = {}
    scopes = params.get("scopes")
    if scopes is not None:
        if not isinstance(scopes, list) or not scopes or not all(item in _JOB_STATUSES for item in scopes):
            raise GitLabPackError("scopes must contain current GitLab job status values")
        query["scope[]"] = scopes
    if pipeline_id is None:
        endpoint = f"/projects/{project}/jobs"
        if params.get("include_retried") is not None:
            raise GitLabPackError("include_retried requires pipeline_id")
        query.update({"pagination": "keyset", "order_by": "id", "sort": "desc"})
    else:
        endpoint = f"/projects/{project}/pipelines/{_positive_id(pipeline_id, 'pipeline_id')}/jobs"
        if params.get("include_retried") is not None:
            if not isinstance(params["include_retried"], bool):
                raise GitLabPackError("include_retried must be a boolean")
            query["include_retried"] = params["include_retried"]
    return _client(params).paginate(endpoint, query, per_page=params.get("per_page", 100), max_pages=params.get("max_pages", 10))


def get_job(params: Mapping[str, Any]) -> Dict[str, Any]:
    endpoint = f"/projects/{_project(params.get('project'))}/jobs/{_positive_id(params.get('job_id'), 'job_id')}"
    result = _client(params).request("GET", endpoint)
    if not isinstance(result, dict):
        raise GitLabPackError("GitLab job endpoint returned a non-object response")
    return result


def _pipeline_mutation(params: Mapping[str, Any], operation: str) -> Dict[str, Any]:
    endpoint = f"/projects/{_project(params.get('project'))}/pipelines/{_positive_id(params.get('pipeline_id'), 'pipeline_id')}/{operation}"
    result = _client(params).request("POST", endpoint)
    if not isinstance(result, dict):
        raise GitLabPackError(f"GitLab pipeline {operation} returned a non-object response")
    return result


def _job_mutation(params: Mapping[str, Any], operation: str) -> Dict[str, Any]:
    endpoint = f"/projects/{_project(params.get('project'))}/jobs/{_positive_id(params.get('job_id'), 'job_id')}/{operation}"
    result = _client(params).request("POST", endpoint)
    if not isinstance(result, dict):
        raise GitLabPackError(f"GitLab job {operation} returned a non-object response")
    return result


OPERATIONS = {
    "list_projects": list_projects,
    "get_project": get_project,
    "list_issues": list_issues,
    "get_issue": get_issue,
    "list_merge_requests": list_merge_requests,
    "get_merge_request": get_merge_request,
    "list_pipelines": list_pipelines,
    "get_pipeline": get_pipeline,
    "trigger_pipeline": trigger_pipeline,
    "list_jobs": list_jobs,
    "get_job": get_job,
    "cancel_pipeline": lambda params: _pipeline_mutation(params, "cancel"),
    "retry_pipeline": lambda params: _pipeline_mutation(params, "retry"),
    "cancel_job": lambda params: _job_mutation(params, "cancel"),
    "retry_job": lambda params: _job_mutation(params, "retry"),
}


def execute_action(operation: str, params: Mapping[str, Any]) -> Dict[str, Any]:
    handler = OPERATIONS.get(operation)
    if handler is None:
        raise GitLabPackError(f"unsupported GitLab operation {operation!r}")
    return handler(params)
