"""Tests for scan router helpers."""

from types import SimpleNamespace

from app.routers.scan import _public_scan_error, _request_context


class TestScanRouterHelpers:
    def test_request_context_uses_forwarded_for(self):
        request = SimpleNamespace(
            headers={
                "x-request-id": "req-123",
                "x-forwarded-for": "203.0.113.10, 10.0.0.1",
                "user-agent": "EnterpriseScanner/1.0",
            },
            client=SimpleNamespace(host="127.0.0.1"),
        )

        context = _request_context(request)

        assert context["request_id"] == "req-123"
        assert context["client_ip"] == "203.0.113.10"
        assert context["user_agent"] == "EnterpriseScanner/1.0"

    def test_request_context_falls_back_to_client_host(self):
        request = SimpleNamespace(headers={}, client=SimpleNamespace(host="127.0.0.1"))

        context = _request_context(request)

        assert context["client_ip"] == "127.0.0.1"
        assert context["request_id"]

    def test_public_scan_error_is_generic(self):
        message = _public_scan_error("req-456")

        assert "req-456" in message
        assert "Traceback" not in message