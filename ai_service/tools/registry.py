from typing import Dict, Any, Callable, List, Optional
import inspect

class Tool:
    def __init__(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        func: Callable,
        required_role: str = "user", # "user", "group_admin", "super_admin"
        requires_confirmation: bool = False,
        confirmation_message: Optional[str] = None
    ):
        self.name = name
        self.description = description
        self.parameters = parameters
        self.func = func
        self.required_role = required_role
        self.requires_confirmation = requires_confirmation
        self.confirmation_message = confirmation_message

    def to_ollama_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters
            }
        }

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Tool] = {}

    def register(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        required_role: str = "user",
        requires_confirmation: bool = False,
        confirmation_message: Optional[str] = None
    ):
        def decorator(func: Callable):
            tool = Tool(
                name=name,
                description=description,
                parameters=parameters,
                func=func,
                required_role=required_role,
                requires_confirmation=requires_confirmation,
                confirmation_message=confirmation_message
            )
            self._tools[name] = tool
            return func
        return decorator

    def get_tool(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def get_schemas_for_user(self, is_super_admin: bool, user_role: str) -> List[Dict[str, Any]]:
        schemas = []
        for name, tool in self._tools.items():
            # Control de permisos según el rol del usuario autenticado
            if tool.required_role == "super_admin" and not is_super_admin:
                continue
            schemas.append(tool.to_ollama_schema())
        return schemas

registry = ToolRegistry()
