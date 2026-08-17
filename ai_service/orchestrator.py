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
        import re
        
        user_context = {
            "user_email": user_email,
            "is_super_admin": is_super_admin,
            "assigned_group": assigned_group
        }
        
        conversation_id = f"conv_{user_email}"
        memory_store.save_chat_message(conversation_id, user_email, "user", message)

        msg_lower = message.strip().lower()
        tools_executed = []
        content = ""

        # Recuperar últimos mensajes para memoria conversacional
        history = memory_store.get_chat_history(user_email, limit=6)
        history_text = " ".join([h.get("content", "") for h in history]).lower()

        # Extraer posibles correos en el mensaje actual o historial
        emails_in_msg = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', message)
        emails_in_history = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', history_text)
        active_email = emails_in_msg[0] if emails_in_msg else (emails_in_history[-1] if emails_in_history else None)

        # --- SMART CONTEXTUAL INTENT ROUTING ---

        # 1. Corrección o Especificación de Facultad/Grupo durante la creación de usuario
        if active_email and ("sino" in msg_lower or "no," in msg_lower or "facultad" in msg_lower or "grupo" in msg_lower) and ("agregar" in history_text or "invitar" in history_text or "licencia" in history_text or "confirmaci" in history_text):
            # Extraer el nombre de la facultad del mensaje (ej: "Facultad UVA-OFICINA-VIRTUAL no, sino a la facultad UVA-OFICINA-VIRTUAL")
            clean_group = message
            for prefix in ["facultad", "grupo", "sino a la", "sino al", "sino", "no,", "no"]:
                clean_group = re.sub(rf'\b{prefix}\b', '', clean_group, flags=re.IGNORECASE)
            target_group = clean_group.strip().strip(':').strip('.').strip() or assigned_group or "UVA"

            tool_args = {"email": active_email, "group_name": target_group, "user_type": 2}
            action_id = str(uuid.uuid4())[:8]
            conf_msg = f"Entendido, ajustado a la facultad **{target_group}**. ¿Confirmas crear e invitar al usuario '{active_email}' asignándolo al grupo '{target_group}' con licencia Licensed (Zoom Meetings)?"
            
            PENDING_CONFIRMATIONS[action_id] = {
                "tool_name": "create_zoom_user",
                "tool_args": tool_args,
                "user_context": user_context,
                "user_email": user_email,
                "created_at": time.time()
            }

            prompt_resp = f"⚠️ **Confirmación requerida**\n\n{conf_msg}"
            memory_store.save_chat_message(conversation_id, user_email, "assistant", prompt_resp, metadata={"confirmation_required": True, "action_id": action_id})
            
            return {
                "status": "confirmation_required",
                "action_id": action_id,
                "message": prompt_resp,
                "confirmation_message": conf_msg,
                "tool_name": "create_zoom_user",
                "tool_args": tool_args
            }

        # 2. El usuario solo proporcionó un correo electrónico (ej. jtovar@usmpvirtual.edu.pe)
        elif emails_in_msg and len(message.strip().split()) <= 2:
            target_email = emails_in_msg[0]
            target_group = assigned_group or "UVA"
            
            tool_args = {"email": target_email, "group_name": target_group, "user_type": 2}
            action_id = str(uuid.uuid4())[:8]
            conf_msg = f"Perfecto, registraré al correo '{target_email}'. ¿Confirmas crearlo e invitarlo a la facultad '{target_group}' con licencia Licensed (Zoom Meetings)?"
            
            PENDING_CONFIRMATIONS[action_id] = {
                "tool_name": "create_zoom_user",
                "tool_args": tool_args,
                "user_context": user_context,
                "user_email": user_email,
                "created_at": time.time()
            }

            prompt_resp = f"⚠️ **Confirmación requerida**\n\n{conf_msg}"
            memory_store.save_chat_message(conversation_id, user_email, "assistant", prompt_resp, metadata={"confirmation_required": True, "action_id": action_id})
            
            return {
                "status": "confirmation_required",
                "action_id": action_id,
                "message": prompt_resp,
                "confirmation_message": conf_msg,
                "tool_name": "create_zoom_user",
                "tool_args": tool_args
            }

        # 3. Detección de Anomalías / Licencias Excedidas
        elif "anomal" in msg_lower or "excedid" in msg_lower or "conflict" in msg_lower:
            from .tools.system_tools import detect_anomalies
            tool_res = await detect_anomalies(user_context)
            tools_executed.append({"name": "detect_anomalies", "result": tool_res})
            
            anomalies = tool_res.get("anomalies", [])
            if not anomalies:
                content = "✅ **Análisis de Sistema Completo**: Todo opera con normalidad. No se detectaron anomalías ni licencias excedidas en la cuenta."
            else:
                lines = ["🔍 **Informe de Anomalías Detectadas en el Sistema**:\n"]
                for idx, a in enumerate(anomalies, start=1):
                    lines.append(f"**{idx}. [{a.get('severity', 'WARN')}] {a.get('type')}**")
                    lines.append(f"└ {a.get('description')}\n")
                content = "\n".join(lines)

        # 4. Estadísticas generales de Licencias y Usuarios
        elif "estadist" in msg_lower or "cuantas licencia" in msg_lower or "resumen" in msg_lower or "cuantos usuario" in msg_lower:
            from .tools.system_tools import get_statistics
            tool_res = await get_statistics(user_context)
            tools_executed.append({"name": "get_statistics", "result": tool_res})
            
            st = tool_res.get("statistics", {})
            content = (
                f"📊 **Reporte de Estadísticas de Licenciamiento ({st.get('group')})**\n\n"
                f"- **Licencias Contratadas (Licensed)**: `{st.get('total_licenses_contracted')}`\n"
                f"- **Licencias Asignadas Activas**: `{st.get('used_licenses')}`\n"
                f"- **Invitaciones Pendientes**: `{st.get('pending_invitations')}`\n"
                f"- **Licencias Libres Reales Disponibles**: `{st.get('real_available_licenses')}`\n"
                f"- **Total Usuarios en Sistema**: `{st.get('total_users_db')}`"
            )

        # 5. Lista de Facultades / Grupos (Solo si el usuario explícitamente pide ver o listar facultades)
        elif "ver facultades" in msg_lower or "listar facultades" in msg_lower or "que facultades" in msg_lower or "lista de grupos" in msg_lower:
            from .tools.system_tools import get_faculties
            tool_res = await get_faculties(user_context)
            tools_executed.append({"name": "get_faculties", "result": tool_res})
            
            facs = tool_res.get("faculties", [])
            if facs:
                lines = ["🏛️ **Facultades y Grupos Registrados en Zoom USMP**:\n"]
                for f in facs[:15]:
                    lines.append(f"- **{f.get('name')}** (Miembros activos: `{f.get('total_members', 0)}`)")
                content = "\n".join(lines)
            else:
                content = "No se encontraron facultades disponibles para tus permisos."

        # 6. Solicitud de Agregar Licencia / Usuario con correo explícito
        elif "agregar" in msg_lower or "crear" in msg_lower or "invitar" in msg_lower or "licencia" in msg_lower:
            if emails_in_msg:
                target_email = emails_in_msg[0]
                
                # Detectar si especificó facultad en el mensaje
                target_group = assigned_group or "UVA"
                for word in message.split():
                    if word.isupper() and len(word) >= 3 and word not in ["ZOOM", "USMP", "UVA"]:
                        target_group = word
                
                tool_args = {"email": target_email, "group_name": target_group, "user_type": 2}
                action_id = str(uuid.uuid4())[:8]
                conf_msg = f"¿Confirmas crear e invitar al usuario '{target_email}' asignándolo a la facultad **{target_group}** con licencia Licensed (Zoom Meetings)?"
                
                PENDING_CONFIRMATIONS[action_id] = {
                    "tool_name": "create_zoom_user",
                    "tool_args": tool_args,
                    "user_context": user_context,
                    "user_email": user_email,
                    "created_at": time.time()
                }

                prompt_resp = f"⚠️ **Confirmación requerida**\n\n{conf_msg}"
                memory_store.save_chat_message(conversation_id, user_email, "assistant", prompt_resp, metadata={"confirmation_required": True, "action_id": action_id})
                
                return {
                    "status": "confirmation_required",
                    "action_id": action_id,
                    "message": prompt_resp,
                    "confirmation_message": conf_msg,
                    "tool_name": "create_zoom_user",
                    "tool_args": tool_args
                }
            else:
                content = (
                    "📝 **Asignación de Licencia Zoom**:\n\n"
                    "Por favor indícame el **correo del docente** (ej: `docente@usmp.pe`) "
                    "y la **facultad/grupo** a la que pertenece (ej: `UVA`, `FCCTP`, `FMH`)."
                )

        # 7. Conversaciones o preguntas abiertas -> Pasar a Ollama con respuesta limpia y directa
        else:
            messages_payload = [{"role": h["role"], "content": h["content"]} for h in history]

            user_role_str = "super_admin" if is_super_admin else "user"
            available_tools = registry.get_schemas_for_user(is_super_admin, user_role_str)

            system_prompt = self._build_system_prompt(user_email, is_super_admin, assigned_group)
            system_prompt += "\nINSTRUCCIÓN CRÍTICA: Responde de forma muy natural, amigable, breve y directa en 1 o 2 oraciones. NUNCA uses presentaciones repetitivas."

            rag_context = rag_engine.get_context_str(message)
            if rag_context and "No se encontró" not in rag_context:
                system_prompt += f"\n\nCONOCIMIENTO INTERNO:\n{rag_context}"

            response = await self.provider.chat_completion(
                messages=messages_payload,
                tools=available_tools,
                system_prompt=system_prompt,
                temperature=0.1
            )
            content = response.get("content", "").strip()
            if not content:
                content = "¡Hola! ¿En qué puedo ayudarte hoy con la gestión de licencias o facultades?"

        # Registrar auditoría y guardar respuesta
        ai_audit_logger.log_action(
            user_email=user_email,
            user_role="super_admin" if is_super_admin else "user",
            assigned_group=assigned_group,
            action_prompt=message,
            tool_name=tools_executed[0]["name"] if tools_executed else None,
            tool_result=tools_executed[0]["result"] if tools_executed else None,
            status="SUCCESS"
        )

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
