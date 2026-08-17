from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class BaseAIProvider(ABC):
    """
    Abstracción base para proveedores de Inteligencia Artificial (Ollama, LocalAI, Mock, etc.)
    Permite intercambiar el motor de IA sin tocar la lógica del negocio ni las herramientas.
    """
    
    @abstractmethod
    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2
    ) -> Dict[str, Any]:
        """
        Envía un conjunto de mensajes y herramientas opcionales al LLM.
        Devuelve un diccionario estructurado:
        {
            "content": str,
            "tool_calls": List[Dict[str, Any]], # [{"name": str, "arguments": dict, "id": str}]
            "finish_reason": str,
            "model": str
        }
        """
        pass

    @abstractmethod
    async def check_health(self) -> Dict[str, Any]:
        """
        Verifica el estado y conectividad del proveedor local.
        """
        pass
