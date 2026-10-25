
import requests

OLLAMA_URL = "http://localhost:11434/api/chat"


def main():
    payload = {
        "model": "qwen2.5:3b",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Explain RAG in two simple sentences."
                ),
            }
        ],
        "stream": False,
    }

    response = requests.post(
        OLLAMA_URL,
        json=payload,
        timeout=180,
    )
    response.raise_for_status()

    data = response.json()
    print("Model:", data.get("model"))
    print("Response:")
    print(data["message"]["content"])


if __name__ == "__main__":
    main()

