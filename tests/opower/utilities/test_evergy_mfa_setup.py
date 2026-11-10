"""Tests for the Evergy "set up multifactor authentication?" login step."""

import json
import unittest
from typing import Any
from unittest.mock import AsyncMock, patch

from opower.exceptions import CannotConnect
from opower.utilities.evergy import MFA_SETUP_FIELD, EvergyLoginHandler

CUSTOM_HTML_TEMPLATE = "customHTMLTemplate"

# Shapes recorded from a live login on 2026-11-10, cut down to the fields the handler reads.
MFA_SETUP_SCREEN: dict[str, Any] = {
    "id": "id-question",
    "connectionId": "connection-1",
    "capabilityName": CUSTOM_HTML_TEMPLATE,
    "screen": {
        "properties": {
            "customHTML": {
                "value": (
                    '<form id="secureForm">'
                    '<input type="radio" name="secure-account-option" value="Yes" required checked>'
                    '<input type="radio" name="secure-account-option" value="No">'
                    '<button data-skbuttontype="form-submit" data-skbuttonvalue="Next">Continue</button>'
                    "</form>"
                )
            }
        }
    },
}

TOKEN_RESPONSE: dict[str, Any] = {
    "id": "id-token",
    "connectionId": "connection-2",
    "capabilityName": "returnSuccessResponseWidget",
    "access_token": "token-after-answer",
}


class _MockResponse:
    """Minimal stand-in for aiohttp.ClientResponse."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    async def json(self, **kwargs: Any) -> dict[str, Any]:
        return self._payload

    async def __aenter__(self) -> "_MockResponse":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None


class _MockSession:
    """Returns the queued payloads in order and records each request."""

    def __init__(self, payloads: list[dict[str, Any]]) -> None:
        self._payloads = list(payloads)
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def post(self, url: str, **kwargs: Any) -> _MockResponse:
        self.requests.append((url.rsplit("/", 1)[1], json.loads(kwargs["data"])))
        return _MockResponse(self._payloads.pop(0))


class TestEvergyMfaSetupQuestion(unittest.IsolatedAsyncioTestCase):
    """Test the login steps that follow the login form."""

    async def _login(self, payloads: list[dict[str, Any]]) -> tuple[EvergyLoginHandler, _MockSession]:
        session = _MockSession(payloads)
        handler = EvergyLoginHandler(session)  # type: ignore[arg-type]
        handler.auth_data = {"api_root": "https://auth.example.com", "company_id": "company"}
        handler.connectionId = "connection-1"
        handler.id = "id-1"
        # login() calls each step on the class, so the patches go on the class.
        with (
            patch.object(EvergyLoginHandler, "get_auth_data", AsyncMock()),
            patch.object(EvergyLoginHandler, "get_sdktoken", AsyncMock()),
            patch.object(EvergyLoginHandler, "start_flow", AsyncMock()),
            patch.object(EvergyLoginHandler, "get_login_form", AsyncMock()),
            patch.object(EvergyLoginHandler, "submit_login_form", AsyncMock()),
            patch.object(EvergyLoginHandler, "postprocessing_api", AsyncMock()),
        ):
            await handler.login("user", "pw")
        return handler, session

    async def test_answers_no_and_takes_the_token(self) -> None:
        """The question gets the answer No, and the token comes from that response."""
        handler, session = await self._login([MFA_SETUP_SCREEN, TOKEN_RESPONSE])

        self.assertEqual([CUSTOM_HTML_TEMPLATE, CUSTOM_HTML_TEMPLATE], [name for name, _ in session.requests])
        answer = session.requests[1][1]
        self.assertEqual("id-question", answer["id"])
        self.assertEqual(
            {"buttonType": "form-submit", "buttonValue": "Next", MFA_SETUP_FIELD: "No"},
            answer["parameters"],
        )
        self.assertEqual("token-after-answer", handler.access_token)
        self.assertEqual("connection-2", handler.connectionId)

    async def test_no_question_sends_no_answer(self) -> None:
        """A login without the question makes one request after the login form."""
        handler, session = await self._login([TOKEN_RESPONSE])

        self.assertEqual(1, len(session.requests))
        self.assertEqual("token-after-answer", handler.access_token)

    async def test_question_again_after_the_answer_fails(self) -> None:
        """The login stops if Evergy shows the question again after the answer."""
        with self.assertRaises(CannotConnect):
            await self._login([MFA_SETUP_SCREEN, MFA_SETUP_SCREEN])
