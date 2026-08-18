import httpx
import pymysql
from typing import Dict, Any, Optional
from .registry import registry
from main import get_zoom_access_token, get_zoom_group_id_by_name, DB_HOST, DB_USER, DB_PASS, DB_NAME


def _open_db_conn():
    return pymysql.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
        charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor
    )

@registry.register(
    name="create_zoom_user",
    description="Crea e invita a un nuevo usuario a Zoom y lo asigna a una facultad/grupo.",
    parameters={
        "type": "object",
        "properties": {
            "email": {"type": "string", "description": "Correo electrónico del usuario"},
            "first_name": {"type": "string", "description": "Nombre"},
            "last_name": {"type": "string", "description": "Apellido"},
            "group_name": {"type": "string", "description": "Nombre de la facultad/grupo"},
            "user_type": {"type": "integer", "description": "1 para Basic, 2 para Licensed (Zoom Meetings)"}
        },
        "required": ["email", "group_name"]
    },
    required_role="user",
    requires_confirmation=True,
    confirmation_message="¿Confirmas crear e invitar al usuario '{email}' asignándolo a la facultad '{group_name}' con tipo de licencia {user_type}?"
)
async def create_zoom_user(
    context: Dict[str, Any],
    email: str,
    group_name: str,
    first_name: Optional[str] = "",
    last_name: Optional[str] = "",
    user_type: int = 2
) -> Dict[str, Any]:
    # Enrutado a través de la función del backend para respetar validaciones
    from main import create_and_assign_user, UserCreateRequest

    assigned_group = context.get("assigned_group")
    is_super_admin = context.get("is_super_admin", False)

    # Validar scoping de grupo
    effective_group = group_name
    if not is_super_admin and assigned_group:
        if group_name.strip().lower() != assigned_group.strip().lower():
            return {
                "status": "error",
                "message": f"Acceso denegado: Tu usuario solo puede gestionar la facultad '{assigned_group}'."
            }

    token = await get_zoom_access_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    group_id = await get_zoom_group_id_by_name(effective_group, headers)

    if not group_id:
        return {
            "status": "error",
            "message": (
                f"No encontré ninguna facultad/grupo de Zoom llamado '{effective_group}'. "
                "Verifica el nombre exacto (usa la herramienta de listar facultades) antes de continuar. "
                "No se creó ni modificó ningún usuario."
            )
        }

    req = UserCreateRequest(
        email=email,
        first_name=first_name,
        last_name=last_name,
        group_id=group_id or "",
        user_type=user_type
    )

    conn = _open_db_conn()
    try:
        res = await create_and_assign_user(request=req, current_user=context.get("user_email"), db=conn)
        return {"status": "success", "result": res}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()

@registry.register(
    name="remove_group_licenses_mass",
    description="Remueve de forma masiva las licencias de Zoom Meetings de todos los usuarios de un grupo (los cambia a Basic).",
    parameters={
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "description": "Nombre de la facultad/grupo"}
        },
        "required": ["group_name"]
    },
    required_role="user",
    requires_confirmation=True,
    confirmation_message="⚠️ ¡ATENCIÓN! ¿Confirmas quitar las licencias de pago (Zoom Meetings) a TODOS los usuarios del grupo '{group_name}' y pasarlos a categoría Basic?"
)
async def remove_group_licenses_mass(context: Dict[str, Any], group_name: str) -> Dict[str, Any]:
    from main import remove_licenses_mass

    assigned_group = context.get("assigned_group")
    is_super_admin = context.get("is_super_admin", False)

    if not is_super_admin and assigned_group:
        if group_name.strip().lower() != assigned_group.strip().lower():
            return {
                "status": "error",
                "message": f"Acceso denegado: Solo puedes ejecutar esta acción en tu facultad '{assigned_group}'."
            }

    token = await get_zoom_access_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    group_id = await get_zoom_group_id_by_name(group_name, headers)

    if not group_id:
        return {"status": "error", "message": f"No se encontró el grupo de Zoom con nombre '{group_name}'."}

    conn = _open_db_conn()
    try:
        res = await remove_licenses_mass(group_id=group_id, current_user=context.get("user_email"), db=conn)
        return {"status": "success", "result": res}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()
