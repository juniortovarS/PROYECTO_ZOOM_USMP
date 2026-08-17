import time
import uuid
from typing import Dict, Any, List, Optional
from .providers.ollama_provider import OllamaProvider
from .tools.registry import registry
from .tools import system_tools, zoom_tools, code_tools
from .memory.store import memory_store
from .rag.engine import rag_engine
from .security.audit import ai_audit_logger

# Almacenamiento temporal en memoria para acciones pendientes de confirmación (HITL)
PENDING_CONFIRMATIONS: Dict[str, Dict[str, Any]] = {}

class AgentOrchestrator:
    """
    Orquestador Central del Agente de Inteligencia Artificial Local de la USMP.
    Maneja la ejecución controlada, el flujo de Function Calling, el scoping RBAC,
    las solicitudes de confirmación HITL y el registro de auditoría.
    """
    
    def __init__(self, provider: Optional[OllamaProvider] = None):
        self.provider = provider or OllamaProvider()

    def _build_system_prompt(self, user_email: str, is_super_admin: bool, assigned_group: Optional[str]) -> str:
        memories_str = memory_store.get_formatted_memories(user_email)
        
        role_desc = "Super Administrador Global" if is_super_admin else f"Administrador de Facultad ('{assigned_group}')"
        scoping_rule = "Tienes acceso global a todas las facultades." if is_super_admin else f"SOLO puedes acceder y gestionar datos de la facultad '{assigned_group}'."

        return f"""Eres el Asistente Inteligente de Gestión de Zoom de la Universidad de San Martín de Porres (USMP).
Funcionas como un AGENTE CONTROLADO de administración dentro del sistema web.

DATOS DE LA SESIÓN DEL USUARIO:
- Usuario: {user_email}
- Rol: {role_desc}
- Ámbito de Facultad: {scoping_rule}

REGLAS FUNDAMENTALES DE COMPORTAMIENTO:
1. Responde siempre en español, de forma profesional, clara, precisa y amable.
2. Si el usuario te pide datos del sistema, invoca la herramienta correspondiente (ej. get_statistics, get_faculties, get_users, detect_anomalies, get_audit_logs).
3. NUNCA inventes datos ni procedimientos. Si no tienes la información, utiliza RAG o indica amablemente qué herramienta consultaste.
4. Respeta estrictamente los permisos del usuario. Si un usuario de facultad intenta ver otra facultad, la herramienta limitará los datos automáticamente.
5. PREFERENCIAS GUARDADAS DE ESTE USUARIO:
{memories_str}

REPORTE DE FORMATO:
- Si el usuario te pide un reporte o resumen, estructúralo limpiamente en tablas Markdown o listas legibles.
"""

    async def process_user_message(
        self,
        user_email: str,
        is_super_admin: bool,
        assigned_group: Optional[str],
        message: str
    ) -> Dict[str, Any]:
        start_time = time.time()
        
        # Contexto del usuario
        user_context = {
            "user_email": user_email,
            "is_super_admin": is_super_admin,
            "assigned_group": assigned_group
        }
        
        # 1. Guardar mensaje del usuario en el historial aislado
        conversation_id = f"conv_{user_email}"
        memory_store.save_chat_message(conversation_id, user_email, "user", message)

        # 2. Cargar historial reciente y obtener contexto RAG
        history = memory_store.get_chat_history(user_email, limit=10)
        messages_payload = [{"role": h["role"], "content": h["content"]} for h in history]

        # 3. Obtener esquemas de herramientas seguras disponibles para su rol
        user_role_str = "super_admin" if is_super_admin else "user"
        available_tools = registry.get_schemas_for_user(is_super_admin, user_role_str)

        system_prompt = self._build_system_prompt(user_email, is_super_admin, assigned_group)
        
        # Inyectar contexto RAG relevante
        rag_context = rag_engine.get_context_str(message)
        if rag_context and "No se encontró" not in rag_context:
            system_prompt += f"\n\nCONOCIMIENTO DE DOCUMENTACIÓN INTERNA DE LA USMP/ZOOM:\n{rag_context}"

        # 4. Consultar al proveedor de IA local
        response = await self.provider.chat_completion(
            messages=messages_payload,
            tools=available_tools,
            system_prompt=system_prompt
        )

        tool_calls = response.get("tool_calls", [])
        content = response.get("content", "")
        tools_executed = []

        # 5. Si la IA decidió llamar a una herramienta (Tool Call)
        if tool_calls:
            for tc in tool_calls:
                tool_name = tc.get("name")
                tool_args = tc.get("arguments", {})
                
                tool = registry.get_tool(tool_name)
                if not tool:
                    continue

                # A) Si la herramienta requiere confirmación explícita (HITL)
                if tool.requires_confirmation:
                    action_id = str(uuid.uuid4())[:8]
                    conf_msg = tool.confirmation_message or f"¿Confirmas ejecutar la acción {tool_name} con parámetros {tool_args}?"
                    for k, v in tool_args.items():
                        conf_msg = conf_msg.replace(f"{{{k}}}", str(v))

                    PENDING_CONFIRMATIONS[action_id] = {
                        "tool_name": tool_name,
                        "tool_args": tool_args,
                        "user_context": user_context,
                        "user_email": user_email,
                        "created_at": time.time()
                    }

                    ai_audit_logger.log_action(
                        user_email=user_email,
                        user_role=user_role_str,
                        assigned_group=assigned_group,
                        action_prompt=message,
                        tool_name=tool_name,
                        tool_parameters=tool_args,
                        status="CONFIRMATION_REQUIRED"
                    )

                    prompt_resp = f"⚠️ **Confirmación requerida**\n\n{conf_msg}"
                    memory_store.save_chat_message(conversation_id, user_email, "assistant", prompt_resp, metadata={"confirmation_required": True, "action_id": action_id})
                    
                    return {
                        "status": "confirmation_required",
                        "action_id": action_id,
                        "message": prompt_resp,
                        "confirmation_message": conf_msg,
                        "tool_name": tool_name,
                        "tool_args": tool_args
                    }

                # B) Herramienta de Solo Lectura o Segura -> Ejecutar de inmediato
                t_start = time.time()
                try:
                    tool_res = await tool.func(user_context, **tool_args)
                    t_ms = int((time.time() - t_start) * 1000)
                    
                    ai_audit_logger.log_action(
                        user_email=user_email,
                        user_role=user_role_str,
                        assigned_group=assigned_group,
                        action_prompt=message,
                        tool_name=tool_name,
                        tool_parameters=tool_args,
                        tool_result=tool_res,
                        status="SUCCESS",
                        execution_time_ms=t_ms
                    )

                    tools_executed.append({
                        "name": tool_name,
                        "result": tool_res
                    })

                    # Sintetizar respuesta final con el resultado de la herramienta
                    synthesis_messages = messages_payload + [
                        {"role": "assistant", "content": "", "tool_calls": [{"id": tc["id"], "type": "function", "function": {"name": tool_name, "arguments": str(tool_args)}}]},
                        {"role": "tool", "name": tool_name, "content": str(tool_res)}
                    ]
                    
                    synth_resp = await self.provider.chat_completion(
                        messages=synthesis_messages,
                        system_prompt=system_prompt
                    )
                    content = synth_resp.get("content") or f"Consulta ejecutada con éxito. Resultado de {tool_name}: {tool_res}"
                except Exception as exc:
                    content = f"Error al ejecutar la herramienta '{tool_name}': {str(exc)}"

        # 6. Guardar respuesta final en historial
        memory_store.save_chat_message(conversation_id, user_email, "assistant", content, metadata={"tools_executed": [t["name"] for t in tools_executed]})

        exec_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "success",
            "message": content,
            "tools_executed": tools_executed,
            "execution_time_ms": exec_ms
        }

    async def execute_confirmed_action(
        self,
        action_id: str,
        user_email: str,
        confirmed: bool
    ) -> Dict[str, Any]:
        pending = PENDING_CONFIRMATIONS.pop(action_id, None)
        if not pending:
            return {"status": "error", "message": "La acción ya expiró o no existe."}

        if pending["user_email"] != user_email:
            return {"status": "error", "message": "Acceso denegado: No tienes autorización para confirmar esta acción."}

        tool_name = pending["tool_name"]
        tool_args = pending["tool_args"]
        user_context = pending["user_context"]

        if not confirmed:
            ai_audit_logger.log_action(
                user_email=user_email,
                user_role="user",
                assigned_group=user_context.get("assigned_group"),
                action_prompt=f"Acción {tool_name} cancelada por el usuario",
                tool_name=tool_name,
                tool_parameters=tool_args,
                status="CANCELLED"
            )
            resp_msg = f"❌ Operación '{tool_name}' cancelada por el usuario."
            memory_store.save_chat_message(f"conv_{user_email}", user_email, "assistant", resp_msg)
            return {"status": "cancelled", "message": resp_msg}

        tool = registry.get_tool(tool_name)
        if not tool:
            return {"status": "error", "message": f"Herramienta '{tool_name}' no encontrada."}

        t_start = time.time()
        try:
            res = await tool.func(user_context, **tool_args)
            t_ms = int((time.time() - t_start) * 1000)

            ai_audit_logger.log_action(
                user_email=user_email,
                user_role="user",
                assigned_group=user_context.get("assigned_group"),
                action_prompt=f"Acción confirmada: {tool_name}",
                tool_name=tool_name,
                tool_parameters=tool_args,
                tool_result=res,
                status="CONFIRMED_SUCCESS",
                execution_time_ms=t_ms
            )

            resp_msg = f"✅ **Operación ejecutada con éxito**\n\nHerramienta: `{tool_name}`\nResultado: `{res}`"
            memory_store.save_chat_message(f"conv_{user_email}", user_email, "assistant", resp_msg)
            
            return {
                "status": "success",
                "message": resp_msg,
                "result": res
            }
        except Exception as e:
            return {"status": "error", "message": f"Error al ejecutar la acción confirmada: {str(e)}"}

agent_orchestrator = AgentOrchestrator()
