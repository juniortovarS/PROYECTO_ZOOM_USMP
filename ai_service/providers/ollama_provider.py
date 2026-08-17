import os
import json
import httpx
from typing import List, Dict, Any, Optional
from .base import BaseAIProvider

class OllamaProvider(BaseAIProvider):
    """
    Proveedor de IA Local impulsado por Ollama.
    Compatible con modelos como qwen2.5-coder, qwen2.5, llama3.1, deepseek-r1, etc.
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None
    ):
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")

    async def check_health(self) -> Dict[str, Any]:
        """
        Verifica la disponibilidad de Ollama y el listado de modelos instalados.
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(f"{self.base_url}/api/tags")
                if res.status_code == 200:
                    data = res.json()
                    models = [m.get("name") for m in data.get("models", [])]
                    model_available = any(self.model in m or m in self.model for m in models)
                    return {
                        "status": "online",
                        "base_url": self.base_url,
                        "selected_model": self.model,
                        "available_models": models,
                        "model_ready": model_available or len(models) > 0
                    }
        except Exception as e:
            pass
            
        return {
            "status": "offline",
            "base_url": self.base_url,
            "selected_model": self.model,
            "available_models": [],
            "model_ready": False,
            "message": f"Ollama no se encuentra activo en {self.base_url}. Asegúrate de ejecutar 'ollama run {self.model}'."
        }

    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2
    ) -> Dict[str, Any]:
        
        # Preparar mensajes incluyendo System Prompt
        formatted_messages = []
        if system_prompt:
            formatted_messages.append({"role": "system", "content": system_prompt})
            
        for msg in messages:
            formatted_messages.append({
                "role": msg.get("role", "user"),
                "content": msg.get("content", ""),
                **({"tool_calls": msg["tool_calls"]} if "tool_calls" in msg else {}),
                **({"name": msg["name"]} if "name" in msg else {})
            })

        payload = {
            "model": self.model,
            "messages": formatted_messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "top_p": 0.9
            }
        }

        if tools:
            payload["tools"] = tools

        url = f"{self.base_url}/api/chat"
        
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                res = await client.post(url, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    message = data.get("message", {})
                    content = message.get("content", "")
                    raw_tool_calls = message.get("tool_calls", [])
                    
                    parsed_tool_calls = []
                    for idx, tc in enumerate(raw_tool_calls):
                        fn = tc.get("function", {})
                        args = fn.get("arguments", {})
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except Exception:
                                args = {}
                        parsed_tool_calls.append({
                            "id": f"call_{idx}_{fn.get('name', 'tool')}",
                            "name": fn.get("name"),
                            "arguments": args
                        })
                    
                    return {
                        "content": content,
                        "tool_calls": parsed_tool_calls,
                        "finish_reason": "tool_calls" if parsed_tool_calls else "stop",
                        "model": self.model
                    }
                else:
                    return {
                        "content": f"⚠️ Error del servicio local de IA (HTTP {res.status_code}): {res.text}",
                        "tool_calls": [],
                        "finish_reason": "error",
                        "model": self.model
                    }
        except Exception as exc:
            # Fallback en caso de que Ollama no esté iniciado
            return {
                "content": (
                    f"🤖 **Modo de Diagnóstico Local**\n\n"
                    f"El servicio Ollama local no está respondiendo en `{self.base_url}`.\n"
                    f"*Detalle del error:* `{str(exc)}`\n\n"
                    f"**Para activar la IA local en tu máquina:**\n"
                    f"1. Abre una terminal y ejecuta: `ollama run {self.model}`\n"
                    f"2. Reintenta tu consulta desde esta misma ventana."
                ),
                "tool_calls": [],
                "finish_reason": "offline_fallback",
                "model": self.model
            }
