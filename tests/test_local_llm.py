from __future__ import annotations

import json
import unittest

from appsec_scan_router.local_llm import (
    LocalInventoryAssistant,
    LocalLlmConfig,
    normalize_base_url,
)


class FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.content = json.dumps(payload).encode()

    def raise_for_status(self) -> None:
        return

    def json(self) -> dict[str, object]:
        return self.payload


class FakeSession:
    def __init__(self) -> None:
        self.trust_env = True
        self.posts: list[dict[str, object]] = []

    def get(self, url: str, timeout: tuple[float, float]) -> FakeResponse:
        return FakeResponse({"models": [{"name": "llama3.1:latest"}]})

    def post(
        self, url: str, json: dict[str, object], timeout: tuple[float, float]
    ) -> FakeResponse:
        self.posts.append(json)
        return FakeResponse(
            {
                "message": {
                    "content": (
                        '{"action":"export","export_format":"xlsx",'
                        '"application_types":["web_app","unsupported"],'
                        '"updated_within_days":90,"has_domain":false,'
                        '"sql":"DROP TABLE inventory"}'
                    )
                }
            }
        )


class LocalInventoryAssistantTests(unittest.TestCase):
    def test_rejects_remote_model_hosts_by_default(self) -> None:
        with self.assertRaises(ValueError):
            normalize_base_url("https://models.example.test")

        self.assertEqual(
            normalize_base_url("http://127.0.0.1:11434"), "http://127.0.0.1:11434"
        )

    def test_status_and_interpretation_use_only_allowlisted_fields(self) -> None:
        session = FakeSession()
        assistant = LocalInventoryAssistant(LocalLlmConfig(), session=session)

        self.assertTrue(assistant.status()["available"])
        plan = assistant.interpret("Export recent web apps without domains")

        self.assertEqual(plan.action, "export")
        self.assertEqual(plan.export_format, "xlsx")
        self.assertEqual(plan.criteria.application_types, ("web_app",))
        self.assertEqual(plan.criteria.updated_within_days, 90)
        self.assertFalse(plan.criteria.has_domain)
        self.assertNotIn("sql", plan.criteria.as_dict())
        self.assertFalse(session.trust_env)
        messages = session.posts[0]["messages"]
        self.assertEqual(
            messages[1]["content"], "Export recent web apps without domains"
        )


if __name__ == "__main__":
    unittest.main()
