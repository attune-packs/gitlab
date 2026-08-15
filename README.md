# GitLab Attune Pack

GitLab hosting API actions for Attune. This is an Apache-2.0 adaptation of
[`StackStorm-Exchange/stackstorm-gitlab`](https://github.com/StackStorm-Exchange/stackstorm-gitlab)
version 1.0.1 (`77b62e6db46d6ba8e0ccbcaddef9818cdffb257e`). It targets the
current GitLab REST API v4 and intentionally does not duplicate local Git
checkout, commit, branch, or push operations from the `git` pack.

## Setup

Create an encrypted, pack-owned Key named `gitlab.credentials`:

```json
{
  "base_url": "https://gitlab.example.com",
  "auth_type": "private_token",
  "token": "REDACTED",
  "verify_tls": true,
  "connect_timeout_seconds": 10,
  "read_timeout_seconds": 30,
  "max_get_rate_limit_retries": 2
}
```

`auth_type` is `private_token` for personal, project, or group access tokens,
sent in the recommended `PRIVATE-TOKEN` header. Set it to `oauth` for an OAuth
2.0 access token sent as a bearer token. OAuth token acquisition and refresh
are outside this pack. Deploy tokens and CI job tokens are not accepted because
they do not consistently authorize this action set.

TLS verification is enabled by default. `ca_bundle` can name an absolute CA
bundle path available on the worker. `verify_tls: false` is supported only for
controlled self-managed installations and is not recommended. Plain HTTP is
rejected unless `allow_insecure_http: true` is explicitly stored in the Key.
The URL must identify the GitLab installation root, not `/api/v4`, and cannot
contain credentials, a query, or a fragment.

Use the least-privileged token scopes and project role that satisfy each action.
Read actions generally need `read_api`; creating, canceling, or retrying CI
resources requires `api` and sufficient project permissions. Every action uses
Attune's reserved `standard` permission set only to decrypt its pack-owned Key.

## Actions

| Action | Behavior |
|---|---|
| `gitlab.list_projects` | List visible projects with current project filters. |
| `gitlab.get_project` | Get a project by numeric ID or namespaced path. |
| `gitlab.list_issues` | List project issues. |
| `gitlab.get_issue` | Get a project issue by project-scoped IID. |
| `gitlab.list_merge_requests` | List project merge requests. |
| `gitlab.get_merge_request` | Get a merge request by project-scoped IID. |
| `gitlab.list_pipelines` | List project pipelines. |
| `gitlab.get_pipeline` | Get a pipeline by global pipeline ID. |
| `gitlab.trigger_pipeline` | Create a branch or tag pipeline with variables and optional typed inputs. |
| `gitlab.list_jobs` | List all project jobs or jobs in one pipeline. |
| `gitlab.get_job` | Get a job by global job ID. |
| `gitlab.cancel_pipeline` | Cancel all cancelable jobs in a pipeline. |
| `gitlab.retry_pipeline` | Retry failed or canceled jobs in a pipeline. |
| `gitlab.cancel_job` | Cancel one job without the newer force-cancel option. |
| `gitlab.retry_job` | Retry one failed or canceled job. |

Examples:

```bash
attune action execute gitlab.get_project \
  --params-json '{"project":"group/project"}' --watch

attune action execute gitlab.list_merge_requests \
  --params-json '{"project":"group/project","state":"opened","max_pages":5}' --watch

attune action execute gitlab.trigger_pipeline \
  --params-json '{"project":"group/project","ref":"main","variables":{"DEPLOY":"true"}}' --watch
```

Inputs are delivered as one flat stdin JSON object. Outputs use
`{"operation":"get_project","result":{...}}`. List results contain `items`,
`count`, `pages_fetched`, and `truncated`.

## HTTP Semantics

- Namespaced project paths are encoded as one path segment, including `/` as `%2F`.
- List actions request up to 100 items per page and follow GitLab's `Link` next relation.
- Project-wide job listing uses GitLab's recommended ID-descending keyset pagination.
- Pagination links must remain on the configured origin and below its `/api/v4` root.
- `max_pages` defaults to 10 and is bounded to 100; `truncated` reports a remaining page.
- Connect/read timeouts default to 10/30 seconds and are bounded.
- Only GET requests retry HTTP 429, up to two times by default. `Retry-After` is honored but capped at 60 seconds.
- POST mutations are never automatically retried because a lost response could hide an accepted side effect.
- Redirects are rejected to prevent credential forwarding to an unexpected location.
- Error response bodies are not emitted. Safe errors may include status, request ID, and `Retry-After`.
- Credential-like response fields, embedded configured tokens, and URL userinfo are masked in action output.

GitLab pipeline cancellation returns success even if the pipeline cannot change
state. Pipeline retry has no effect when no failed or canceled jobs exist. Job
retry can create a new job. Attune cancellation can stop the local process but
cannot retract a request already accepted by GitLab.

`trigger_pipeline` uses authenticated `POST /projects/:id/pipeline`, not the
source pack's project trigger-token endpoint. This removes a second secret from
action input and supports current variable arrays. Optional `inputs` requires
GitLab 18.1 or newer; omit it for older API v4 installations.

## Source Fidelity

| Source behavior | Attune target | Fidelity and differences |
|---|---|---|
| `project.info` | `gitlab.get_project` | Preserved; adds strict URL encoding, status handling, timeout, TLS verification, and secret masking. |
| `issue.info` | `gitlab.get_issue` | Preserved; validates that the supplied value is the project IID. |
| `pipeline.list` | `gitlab.list_pipelines` | Preserved; adds filters and bounded pagination. |
| `pipeline.trigger` | `gitlab.trigger_pipeline` | Adapted to the authenticated current pipeline endpoint; trigger secrets no longer enter action parameters. |
| Shared `requests` wrapper | `lib/gitlab_client.py` | Replaced; upstream treated every nonzero status as success, disabled TLS warnings, had no timeout, and did not paginate. |
| Pack config and action token overrides | Attune Key | Replaced; URL and credentials cannot be overridden by action input. |
| No merge request/job/get-pipeline actions | Explicit current actions | Added as a concise hosting and CI quick-win surface. |
| No cancellation/retry actions | Four explicit mutations | Added only for documented current pipeline/job endpoints; destructive erase/delete and force-cancel are omitted. |

No source sensors, triggers, workflows, rules, aliases, schedules, queues, or
compensation logic existed. This initial pack adds none. Webhooks and polling
sensors are intentionally deferred until durable delivery and checkpointing
requirements are defined.

## Validation

```bash
python -m unittest -v tests/test_pack.py
attune --output json pack check .
attune pack test . --detailed
```

Tests are deterministic and mocked; they make no GitLab calls. Validation does
not prove token scopes, project permissions, self-managed version compatibility,
custom CA availability, proxy behavior, or live rate-limit semantics. Perform a
read-only smoke test and separately authorized CI mutation tests against each
target GitLab installation before production rollout.

## Upstream And License

Source revision and API verification metadata are recorded in
[`SOURCE.md`](SOURCE.md). The upstream Apache-2.0 license is included in
[`LICENSE`](LICENSE), with attribution in [`NOTICE`](NOTICE).
