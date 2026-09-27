import io
import json
import sys
import os
import urllib.error

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import fetch_scm_checks  # noqa: E402


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def make_urlopen(total_checks=230, frameworks_status=200):
    calls = []

    def urlopen(req, timeout=None):
        url = req.full_url
        calls.append((req.get_method(), url, dict(req.header_items())))
        if url == fetch_scm_checks.TOKEN_URL:
            return FakeResp(json.dumps({"access_token": "tok"}).encode())
        assert req.get_header("Authorization") == "Bearer tok"
        if fetch_scm_checks.CHECKS_PATH in url:
            q = dict(p.split("=") for p in url.split("?")[1].split("&"))
            offset, limit = int(q["offset"]), int(q["limit"])
            data = [{"id": str(i), "name": f"check {i}", "type": "predefined", "management_type": "ngfw",
                     "object_type": "security_rule", "severity": "High"}
                    for i in range(offset, min(offset + limit, total_checks))]
            return FakeResp(json.dumps({"data": data, "total": total_checks}).encode())
        if fetch_scm_checks.FRAMEWORKS_PATH in url:
            if frameworks_status != 200:
                raise urllib.error.HTTPError(url, frameworks_status, "Forbidden", {}, io.BytesIO(b"{}"))
            return FakeResp(json.dumps({"data": [{"id": "cis"}], "total": 1}).encode())
        raise AssertionError(url)

    return urlopen, calls


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("SCM_CLIENT_ID", "cid")
    monkeypatch.setenv("SCM_CLIENT_SECRET", "secret")
    monkeypatch.setenv("SCM_TSG_ID", "1234")


def test_fetches_every_page_and_writes_no_credentials(env, monkeypatch, tmp_path):
    urlopen, calls = make_urlopen()
    monkeypatch.setattr(fetch_scm_checks.urllib.request, "urlopen", urlopen)
    out = tmp_path / "checks.json"
    assert fetch_scm_checks.main(["-o", str(out)]) == 0
    result = json.loads(out.read_text())
    assert len(result["checks"]) == 230           # 3 pages of 100
    assert result["compliance_frameworks"] == [{"id": "cis"}]
    text = out.read_text()
    assert "secret" not in text and "tok" not in text
    # Token request is scoped to the tenant, and only GETs hit the API
    token_call = calls[0]
    assert token_call[0] == "POST"
    assert all(method == "GET" for method, url, _ in calls[1:])


def test_missing_frameworks_access_is_not_fatal(env, monkeypatch, tmp_path):
    urlopen, _ = make_urlopen(total_checks=5, frameworks_status=403)
    monkeypatch.setattr(fetch_scm_checks.urllib.request, "urlopen", urlopen)
    out = tmp_path / "checks.json"
    assert fetch_scm_checks.main(["-o", str(out)]) == 0
    assert json.loads(out.read_text())["compliance_frameworks"] == []


def test_requires_ids(monkeypatch):
    monkeypatch.delenv("SCM_CLIENT_ID", raising=False)
    monkeypatch.delenv("SCM_TSG_ID", raising=False)
    assert fetch_scm_checks.main([]) == 2
