"""Configuration for the automotive cybersecurity copilot."""
import os
from dotenv import load_dotenv

load_dotenv()

# LLM: OpenAI-compatible API (VLLM, LMStudio, or OpenAI/Claude/Gemini proxy)
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://localhost:8000/v1")
LLM_API_KEY = os.getenv("LLM_API_KEY", "dummy")
LLM_MODEL = os.getenv("LLM_MODEL", "meta-llama/Llama-2-7b-chat-hf")  # Model name on the server

# Judge LLM: separate model for evaluation (LLM-as-judge). Falls back to copilot LLM if not set.
JUDGE_LLM_BASE_URL = os.getenv("JUDGE_LLM_BASE_URL", os.getenv("LLM_BASE_URL", "http://localhost:8000/v1"))
JUDGE_LLM_API_KEY = os.getenv("JUDGE_LLM_API_KEY", os.getenv("LLM_API_KEY", "dummy"))
JUDGE_LLM_MODEL = os.getenv("JUDGE_LLM_MODEL", os.getenv("LLM_MODEL", "meta-llama/Llama-2-7b-chat-hf"))

# Embeddings: for Weaviate RAG (VLLM embedding endpoint or OpenAI)
EMBED_BASE_URL = os.getenv("EMBED_BASE_URL", os.getenv("LLM_BASE_URL", "http://localhost:8000/v1"))
EMBED_API_KEY = os.getenv("EMBED_API_KEY", os.getenv("LLM_API_KEY", "dummy"))
EMBED_MODEL = os.getenv("EMBED_MODEL", "bge-m3")  # Common embedding model

# Weaviate: local (Docker) or Weaviate Cloud. WEAVIATE_URL is required.
WEAVIATE_URL = (os.getenv("WEAVIATE_URL") or "").strip() or None
WEAVIATE_API_KEY = os.getenv("WEAVIATE_API_KEY", None)  # For Weaviate Cloud
WEAVIATE_COLLECTION = "ResolvedTicket"
