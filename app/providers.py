import httpx

from app.config import settings


async def complete_chat(payload: dict) -> dict:
    if not settings.upstream_base_url:
        user_messages = [
            item["content"] for item in payload["messages"] if item["role"] == "user"
        ]
        answer = (
            "Demo response: "
            + (user_messages[-1] if user_messages else "No user message provided.")
        )
        return {
            "id": "demo-response",
            "object": "chat.completion",
            "created": 0,
            "model": payload["model"],
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": answer},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

    headers = {"Content-Type": "application/json"}
    if settings.upstream_api_key:
        headers["Authorization"] = f"Bearer {settings.upstream_api_key}"
    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        response = await client.post(
            f"{settings.upstream_base_url}/chat/completions",
            json=payload,
            headers=headers,
        )
        response.raise_for_status()
        return response.json()
