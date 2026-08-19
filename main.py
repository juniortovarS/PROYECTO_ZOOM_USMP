import os
import time
import asyncio
import hashlib
import binascii
import hmac
import base64
import pymysql
from fastapi import FastAPI, HTTPException, Query, Request, Depends, Response, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from dotenv import load_dotenv
import httpx
from pydantic import BaseModel, EmailStr
from typing import Optional, List

# Cargar variables de entorno
load_dotenv()

ZOOM_ACCOUNT_ID = os.getenv("ZOOM_ACCOUNT_ID")
ZOOM_CLIENT_ID = os.getenv("ZOOM_CLIENT_ID")
ZOOM_CLIENT_SECRET = os.getenv("ZOOM_CLIENT_SECRET")

# Configuración de Base de Datos
DB_HOST = os.getenv("DB_HOST", "34.127.27.235")
DB_USER = os.getenv("DB_USER", "udbSistemas")
DB_PASS = os.getenv("DB_PASS", "S1sT3m@Pwd20")
DB_NAME = os.getenv("DB_NAME", "db_sigav")
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", "usmp-zoom-secret-key-92837192873")

app = FastAPI(title="Zoom & USMP License Automation Dashboard")

class UserCreateRequest(BaseModel):
    email: EmailStr
    first_name: Optional[str] = ""
    last_name: Optional[str] = ""
    group_id: Optional[str] = ""
    user_type: Optional[int] = 2  # 1 para Basic, 2 para Licensed (Zoom Meetings)

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: Optional[str] = ""
    last_name: Optional[str] = ""

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str

# Helpers de Firma de Cookie (Seguridad de Sesión)
def sign_value(val: str) -> str:
    # Usar hexdigest() para evitar caracteres especiales propensos a comillas en cookies
    sig = hmac.new(SESSION_SECRET_KEY.encode(), val.encode(), hashlib.sha256).hexdigest()
    return f"{val}.{sig}"

def verify_value(signed_val: str) -> Optional[str]:
    try:
        # Remover comillas si el navegador las incluyó
        if signed_val.startswith('"') and signed_val.endswith('"'):
            signed_val = signed_val[1:-1]
        # Usar rsplit desde la derecha para admitir emails que contienen puntos (.)
        val, sig = signed_val.rsplit(".", 1)
        expected_sig = hmac.new(SESSION_SECRET_KEY.encode(), val.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected_sig):
            return val
    except Exception:
        pass
    return None

def encode_cursor(zoom_token: str, skip: int) -> str:
    import json
    import base64
    data = {
        "t": zoom_token or "",
        "s": skip
    }
    json_str = json.dumps(data)
    return base64.b64encode(json_str.encode('utf-8')).decode('utf-8')

def decode_cursor(cursor_str: str) -> tuple:
    if not cursor_str:
        return "", 0
    import json
    import base64
    try:
        decoded_bytes = base64.b64decode(cursor_str.encode('utf-8'), validate=True)
        data = json.loads(decoded_bytes.decode('utf-8'))
        return data.get("t", ""), data.get("s", 0)
    except Exception:
        return cursor_str, 0

# Hashing de contraseña seguro (Deshabilitado: texto plano por solicitud del usuario)
def hash_password(password: str) -> str:
    return password

# Dependency para conexión de Base de Datos
def get_db_conn():
    conn = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        yield conn
    finally:
        conn.close()

# Inyección para verificar la sesión
def verify_session(request: Request):
    session_token = request.cookies.get("session_token")
    email = None
    if session_token:
        email = verify_value(session_token)
    if not email:
        raise HTTPException(status_code=401, detail="Acceso denegado: Inicie sesión.")
    return email

def get_user_by_email(email: str, db) -> Optional[dict]:
    with db.cursor() as cursor:
        cursor.execute("SELECT id, email, role, assigned_group FROM login_zoom WHERE email = %s", (email,))
        return cursor.fetchone()

# Inyección para verificar que la sesión pertenece a un administrador
def verify_admin(request: Request, db=Depends(get_db_conn)):
    email = verify_session(request)
    user = get_user_by_email(email, db)
    is_jtovar = user and "jtovar" in user.get("email", "").lower()
    if not user or (user.get("role") != "admin" and not is_jtovar):
        raise HTTPException(status_code=403, detail="Acceso denegado: Se requieren permisos de administrador.")
    return email

# Servir el Frontend Protegido
@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    session_token = request.cookies.get("session_token")
    email = None
    if session_token:
        email = verify_value(session_token)
        
    if not email:
        return RedirectResponse(url="/login")
        
    try:
        with open("templates/index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Plantilla index.html no encontrada</h1>", status_code=404)

# Servir página de Login
@app.get("/login", response_class=HTMLResponse)
def get_login_page(request: Request):
    session_token = request.cookies.get("session_token")
    email = None
    if session_token:
        email = verify_value(session_token)
        
    if email:
        return RedirectResponse(url="/")
        
    try:
        with open("templates/login.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Plantilla login.html no encontrada</h1>", status_code=404)

async def get_zoom_access_token() -> str:
    """
    Obtiene un Access Token de Zoom usando el flujo Server-to-Server OAuth de forma asíncrona.
    """
    if not all([ZOOM_ACCOUNT_ID, ZOOM_CLIENT_ID, ZOOM_CLIENT_SECRET]):
        raise HTTPException(
            status_code=500,
            detail="Faltan credenciales de Zoom en las variables de entorno (.env)"
        )
    
    url = "https://zoom.us/oauth/token"
    params = {
        "grant_type": "account_credentials",
        "account_id": ZOOM_ACCOUNT_ID
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.post(
                url,
                params=params,
                auth=(ZOOM_CLIENT_ID, ZOOM_CLIENT_SECRET),
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            if response.status_code != 200:
                error_detail = response.json() if response.headers.get("content-type") == "application/json" else response.text
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Error de autenticación con Zoom: {error_detail}"
                )
            return response.json().get("access_token")
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Error de red al conectar con Zoom: {str(exc)}"
            )

def _normalize_group_name(name: str) -> str:
    """Colapsa guiones/guiones bajos/espacios para comparar nombres de forma tolerante
    (ej: 'UVA-OFICINA-VIRTUAL' debe reconocer 'UVA-OFICINA VIRTUAL')."""
    import re as _re
    return _re.sub(r'[\s\-_]+', ' ', name.strip().lower()).strip()

async def get_zoom_group_id_by_name(group_name: str, headers: dict) -> Optional[str]:
    """
    Busca el ID de un grupo de Zoom a partir de su nombre. Primero intenta coincidencia
    exacta y, si falla, una coincidencia tolerante a diferencias de guion/espacio.
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get("https://api.zoom.us/v2/groups", headers=headers)
        if response.status_code == 200:
            groups = response.json().get("groups", [])
            target_exact = group_name.strip().lower()
            for g in groups:
                if g.get("name", "").strip().lower() == target_exact:
                    return g.get("id")

            target_norm = _normalize_group_name(group_name)
            for g in groups:
                if _normalize_group_name(g.get("name", "")) == target_norm:
                    return g.get("id")
    return None

async def get_zoom_group_name_by_id(group_id: str, headers: dict) -> Optional[str]:
    """
    Busca el nombre de un grupo de Zoom a partir de su ID. Devuelve None si no hay
    group_id o no se pudo resolver (nunca debe inventar un nombre de grupo).
    """
    if not group_id:
        return None
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(f"https://api.zoom.us/v2/groups/{group_id}", headers=headers)
        if response.status_code == 200:
            return response.json().get("name", group_id)
    return group_id

async def check_available_licenses(client: httpx.AsyncClient, headers: dict) -> bool:
    """
    Verifica si hay licencias base de Zoom Meetings (Licensed) disponibles,
    teniendo en cuenta las invitaciones pendientes que reservan cupo.
    """
    try:
        plans_task = client.get("https://api.zoom.us/v2/accounts/me/plans/usage", headers=headers)
        pending_task = client.get("https://api.zoom.us/v2/users?status=pending&page_size=1", headers=headers)
        plans_res, pending_res = await asyncio.gather(plans_task, pending_task)
        
        if plans_res.status_code == 200:
            plans_data = plans_res.json()
            plan_base = plans_data.get("plan_base", {})
            hosts = plan_base.get("hosts", 0)
            usage = plan_base.get("usage", 0)
            
            total_pending = 0
            if pending_res.status_code == 200:
                total_pending = pending_res.json().get("total_records", 0)
                
            return (hosts - usage - total_pending) > 0
    except Exception:
        pass
    return True

_ACTIVE_USERS_CACHE = {"users": None, "fetched_at": 0.0}
_ACTIVE_USERS_CACHE_TTL = 180  # segundos
_active_users_lock = asyncio.Lock()

async def fetch_active_users(client: httpx.AsyncClient, headers: dict, max_pages: int = 40) -> list:
    """
    Obtiene usuarios ACTIVOS de Zoom (paginado). Zoom no soporta búsqueda por nombre en su API,
    así que para encontrar un usuario activo por nombre hay que recorrer el listado completo
    (~30s para 8000+ usuarios). Se cachea en memoria por unos minutos para que búsquedas
    consecutivas no repitan el recorrido completo.
    """
    now = time.time()
    if _ACTIVE_USERS_CACHE["users"] is not None and (now - _ACTIVE_USERS_CACHE["fetched_at"]) < _ACTIVE_USERS_CACHE_TTL:
        return _ACTIVE_USERS_CACHE["users"]

    async with _active_users_lock:
        # Puede que otra tarea ya haya refrescado el caché mientras esperábamos el lock
        now = time.time()
        if _ACTIVE_USERS_CACHE["users"] is not None and (now - _ACTIVE_USERS_CACHE["fetched_at"]) < _ACTIVE_USERS_CACHE_TTL:
            return _ACTIVE_USERS_CACHE["users"]

        users = []
        next_page_token = ""
        pages = 0
        while pages < max_pages:
            url = "https://api.zoom.us/v2/users?status=active&page_size=300"
            if next_page_token:
                url += f"&next_page_token={next_page_token}"

            res = await client.get(url, headers=headers)
            if res.status_code != 200:
                break

            data = res.json()
            users.extend(data.get("users", []))
            pages += 1
            next_page_token = data.get("next_page_token")
            if not next_page_token:
                break

        _ACTIVE_USERS_CACHE["users"] = users
        _ACTIVE_USERS_CACHE["fetched_at"] = time.time()
        return users

async def fetch_pending_users_with_groups(client: httpx.AsyncClient, headers: dict) -> list:
    """
    Obtiene todos los usuarios en estado 'pending' de Zoom y recupera sus detalles
    (grupos, fecha de invitación y tipo de licencia) combinando la API de Zoom 
    con los logs de la base de datos local para máxima precisión.
    """
    pending_users = []
    next_page_token = ""
    while True:
        url = "https://api.zoom.us/v2/users?status=pending&page_size=300"
        if next_page_token:
            url += f"&next_page_token={next_page_token}"
            
        res = await client.get(url, headers=headers)
        if res.status_code != 200:
            break
            
        data = res.json()
        users_page = data.get("users", [])
        
        # Preservar la fecha de invitación del listado (ej: 07 Aug 2026) antes de consultar detalles
        for u in users_page:
            u["_list_created_at"] = u.get("user_created_at") or u.get("created_at")
            
        pending_users.extend(users_page)
        
        next_page_token = data.get("next_page_token")
        if not next_page_token or not users_page:
            break
            
    if not pending_users:
        return []

    # 1. Consultar base de datos local para obtener logs de invitación
    emails = [u.get("email").lower().strip() for u in pending_users if u.get("email")]
    email_to_log = {}
    
    if emails:
        try:
            conn = pymysql.connect(
                host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor
            )
            with conn.cursor() as cursor:
                sql = """
                    SELECT l.target_email, l.details, l.operator_email, DATE_FORMAT(l.created_at, '%%d %%b %%Y') as date
                    FROM zoom_activity_logs l
                    INNER JOIN (
                        SELECT target_email, MAX(created_at) as max_date
                        FROM zoom_activity_logs
                        WHERE target_email IN %s
                        GROUP BY target_email
                    ) sub ON l.target_email = sub.target_email AND l.created_at = sub.max_date
                """
                cursor.execute(sql, (tuple(emails),))
                rows = cursor.fetchall()
                for r in rows:
                    email_key = r["target_email"].lower().strip()
                    details = r["details"] or ""
                    
                    group_name = ""
                    if "Agregado al grupo:" in details:
                        parts = details.split("Agregado al grupo:")
                        if len(parts) > 1:
                            group_name = parts[1].replace(".", "").strip()
                    elif "en el grupo:" in details:
                        parts = details.split("en el grupo:")
                        if len(parts) > 1:
                            group_name = parts[1].replace(".", "").strip()
                            
                    if not group_name and r["operator_email"]:
                        op = r["operator_email"].split("@")[0].upper()
                        if op not in ("ADMIN", "JTOVAR"):
                            group_name = op
                            
                    email_to_log[email_key] = {
                        "group_name": group_name,
                        "date": r["date"]
                    }
            conn.close()
        except Exception as e:
            print("Error al consultar logs de pendientes en BD:", str(e))

    # 2. Consultar detalles individuales en paralelo desde Zoom
    async def fetch_details(user_obj):
        email = user_obj.get("email")
        if not email:
            return
        try:
            detail_res = await client.get(f"https://api.zoom.us/v2/users/{email}", headers=headers)
            if detail_res.status_code == 200:
                detail = detail_res.json()
                email_key = email.lower().strip()
                
                # Priorizar datos de la base de datos si existen, de lo contrario usar los de Zoom
                log_info = email_to_log.get(email_key, {})
                
                # Asignar grupos
                zoom_groups = detail.get("group_ids", [])
                db_group = log_info.get("group_name")
                if db_group:
                    user_obj["groups"] = [db_group]
                else:
                    user_obj["groups"] = zoom_groups
                
                # Asignar tipo
                user_obj["type"] = detail.get("type", user_obj.get("type", 1))
                
                # Formatear fecha de creación (priorizando BD, luego listado de Zoom, luego detalle de Zoom)
                date_str = log_info.get("date")
                if not date_str:
                    user_created_at = user_obj.get("_list_created_at") or detail.get("user_created_at")
                    if user_created_at:
                        try:
                            from datetime import datetime
                            dt = datetime.strptime(user_created_at.split("T")[0], "%Y-%m-%d")
                            date_str = dt.strftime("%d %b %Y")
                        except Exception:
                            date_str = user_created_at.split("T")[0]
                            
                user_obj["creation_date"] = date_str
        except Exception as e:
            print(f"Error al obtener detalles del pendiente {email}:", str(e))

    await asyncio.gather(*(fetch_details(u) for u in pending_users))
    
    # Asignar valores por defecto a quienes fallaron
    for u in pending_users:
        if "groups" not in u:
            u["groups"] = []
        if "creation_date" not in u:
            u["creation_date"] = ""
        u["status"] = "pending"
        
    return pending_users

# ----------------- API DE NEGOCIO -----------------


async def fetch_group_members_map(headers: dict) -> dict:
    """
    Obtiene todos los grupos de la cuenta de Zoom y mapea los correos de sus miembros
    a una lista de nombres de grupos. Retorna un diccionario: {email: [group_names]}
    """
    groups_url = "https://api.zoom.us/v2/groups"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(groups_url, headers=headers)
        if response.status_code != 200:
            return {}
        groups = response.json().get("groups", [])
        
        email_to_groups = {}
        sem = asyncio.Semaphore(5)  # Limitar a 5 peticiones simultáneas
        
        async def fetch_members(group):
            group_id = group.get("id")
            group_name = group.get("name")
            next_page_token = ""
            async with sem:
                try:
                    while True:
                        url = f"https://api.zoom.us/v2/groups/{group_id}/members?page_size=300"
                        if next_page_token:
                            url += f"&next_page_token={next_page_token}"
                            
                        res = await client.get(url, headers=headers)
                        if res.status_code == 200:
                            data = res.json()
                            members = data.get("members", [])
                            for m in members:
                                email = m.get("email")
                                if email:
                                    email_clean = email.lower().strip()
                                    if email_clean not in email_to_groups:
                                        email_to_groups[email_clean] = []
                                    if group_name not in email_to_groups[email_clean]:
                                        email_to_groups[email_clean].append(group_name)
                            next_page_token = data.get("next_page_token")
                            if not next_page_token:
                                break
                        else:
                            break
                except Exception:
                    pass
                
        await asyncio.gather(*(fetch_members(g) for g in groups))
        return email_to_groups

async def get_or_create_default_group_id(headers: dict) -> str:
    """
    Busca el ID del grupo 'FCCTP'. Si no existe, lo crea automáticamente.
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get("https://api.zoom.us/v2/groups", headers=headers)
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Error de Zoom al listar grupos: {response.json().get('message', response.text)}"
            )
        
        groups = response.json().get("groups", [])
        for g in groups:
            if g.get("name") == "FCCTP":
                return g.get("id")
        
        create_res = await client.post(
            "https://api.zoom.us/v2/groups",
            headers=headers,
            json={"name": "FCCTP"}
        )
        if create_res.status_code != 201:
            raise HTTPException(
                status_code=create_res.status_code,
                detail=f"No se pudo crear el grupo 'FCCTP': {create_res.json().get('message', create_res.text)}"
            )
        
        return create_res.json().get("id")

@app.get("/api/groups")
async def list_zoom_groups(
    current_user: str = Depends(verify_session),
    db=Depends(get_db_conn)
):
    """
    Obtiene y retorna el listado de todos los grupos de Zoom con la cantidad de miembros licenciados.
    """
    try:
        user_record = get_user_by_email(current_user, db)
        assigned_group = user_record.get("assigned_group") if user_record else None

        token = await get_zoom_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get("https://api.zoom.us/v2/groups", headers=headers)
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Error de Zoom al listar grupos: {response.json().get('message', response.text)}"
                )
            groups = response.json().get("groups", [])
            
            # Filtrar si tiene un grupo asignado
            if assigned_group:
                groups = [g for g in groups if g.get("name", "").strip().lower() == assigned_group.strip().lower()]
            
            # Obtener miembros de cada grupo en paralelo para contar licenciados (soportando paginación y limitando concurrencia)
            sem = asyncio.Semaphore(5)
            
            async def get_licensed_count(group):
                group_id = group.get("id")
                licensed_count = 0
                next_page_token = ""
                async with sem:
                    try:
                        while True:
                            url = f"https://api.zoom.us/v2/groups/{group_id}/members?page_size=300"
                            if next_page_token:
                                url += f"&next_page_token={next_page_token}"
                                
                            res = await client.get(url, headers=headers)
                            if res.status_code == 200:
                                data = res.json()
                                members = data.get("members", [])
                                licensed_count += sum(1 for m in members if m.get("type") == 2)
                                next_page_token = data.get("next_page_token")
                                if not next_page_token:
                                    break
                            else:
                                break
                        group["licensed_count"] = licensed_count
                    except Exception:
                        group["licensed_count"] = licensed_count
            
            await asyncio.gather(*(get_licensed_count(g) for g in groups))
            return {"status": "success", "groups": groups}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@app.get("/api/groups/{group_id}/members")
async def list_group_members(
    group_id: str,
    page_size: int = 50,
    next_page_token: Optional[str] = None,
    user_type: Optional[int] = None,
    current_user: str = Depends(verify_session),
    db=Depends(get_db_conn)
):
    """
    Obtiene los miembros de un grupo de Zoom específico de forma paginada y les asocia sus grupos.
    Si se especifica user_type, acumula hasta completar el page_size con usuarios de ese tipo.
    """
    try:
        user_record = get_user_by_email(current_user, db)
        assigned_group = user_record.get("assigned_group") if user_record else None

        token = await get_zoom_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        
        # Validar restricción de grupo si existe
        if assigned_group:
            restricted_group_id = await get_zoom_group_id_by_name(assigned_group, headers)
            if group_id != restricted_group_id:
                raise HTTPException(
                    status_code=403,
                    detail="Acceso denegado: No tiene permisos para acceder a este grupo."
                )
        
        # 1. Obtener mapeo de grupos en paralelo
        group_members_task = fetch_group_members_map(headers)
        
        # 2. Consultar listado de miembros y acumular hasta tener page_size
        zoom_token, skip = decode_cursor(next_page_token)
        accumulated_members = []
        current_token = zoom_token
        total_records = 0
        total_skipped = 0
        next_token = ""
        next_skip = 0
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Obtener pendientes del grupo para esta consulta
            group_name_clean = assigned_group.strip().lower() if assigned_group else ""
            if not group_name_clean:
                group_res = await client.get(f"https://api.zoom.us/v2/groups/{group_id}", headers=headers)
                if group_res.status_code == 200:
                    group_name_clean = group_res.json().get("name", "").strip().lower()
            
            pending_in_group = []
            if group_name_clean:
                all_pending = await fetch_pending_users_with_groups(client, headers)
                pending_in_group = [
                    u for u in all_pending
                    if u.get("groups") and u.get("groups")[0].strip().lower() == group_name_clean
                ]
                if user_type:
                    pending_in_group = [u for u in pending_in_group if u.get("type") == user_type]

            while len(accumulated_members) < page_size:
                fetch_size = 300 if user_type else page_size
                params = {
                    "page_size": fetch_size
                }
                if current_token:
                    params["next_page_token"] = current_token

                response = await client.get(
                    f"https://api.zoom.us/v2/groups/{group_id}/members",
                    headers=headers,
                    params=params
                )
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=response.status_code,
                        detail=f"Error de Zoom al listar miembros del grupo: {response.json().get('message', response.text)}"
                    )
                
                data = response.json()
                members_page = data.get("members", [])
                total_records = data.get("total_records", 0)
                
                if user_type:
                    filtered_page = [m for m in members_page if m.get("type") == user_type]
                else:
                    filtered_page = members_page

                # Aplicar skip
                if total_skipped < skip:
                    to_skip = min(len(filtered_page), skip - total_skipped)
                    filtered_page = filtered_page[to_skip:]
                    total_skipped += to_skip

                accumulated_members.extend(filtered_page)
                
                if len(accumulated_members) >= page_size:
                    consumed = page_size - (len(accumulated_members) - len(filtered_page))
                    next_skip = skip + consumed
                    if next_skip >= (skip + len(filtered_page)):
                        next_token = data.get("next_page_token", "")
                        next_skip = 0
                    else:
                        next_token = current_token
                    break
                else:
                    current_token = data.get("next_page_token", "")
                    skip = 0
                    total_skipped = 0
                
                if not current_token or not members_page:
                    break

        email_to_groups = await group_members_task
        final_members = accumulated_members[:page_size]
        
        # Adjuntar grupos a los miembros activos
        for m in final_members:
            m_email = m.get("email")
            m["groups"] = email_to_groups.get(m_email, [])
            
        # Combinar con pendientes en la primera página
        if not zoom_token:
            all_merged_members = pending_in_group + final_members
        else:
            all_merged_members = final_members

        # Calcular el cursor de respuesta
        res_token = ""
        if next_token or next_skip > 0:
            res_token = encode_cursor(next_token, next_skip)

        return {
            "status": "success",
            "users": all_merged_members[:page_size],
            "total_records": total_records + len(pending_in_group),
            "total_pending": len(pending_in_group),
            "next_page_token": res_token
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@app.get("/api/users")
async def list_zoom_users(
    page_size: int = 50,
    next_page_token: Optional[str] = None,
    status: str = "active",
    user_type: Optional[int] = None,
    current_user: str = Depends(verify_session),
    db=Depends(get_db_conn)
):
    """
    Obtiene y retorna el listado paginado de usuarios mapeando concurrentemente sus grupos de Zoom
    y obteniendo la cantidad total de invitaciones pendientes del sistema.
    Si se especifica user_type, acumula hasta completar el page_size con usuarios de ese tipo.
    """
    try:
        user_record = get_user_by_email(current_user, db)
        assigned_group = user_record.get("assigned_group") if user_record else None

        token = await get_zoom_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        
        # Si el usuario tiene restricción de grupo, forzar a que devuelva los miembros de su grupo
        if assigned_group:
            restricted_group_id = await get_zoom_group_id_by_name(assigned_group, headers)
            if restricted_group_id:
                return await list_group_members(
                    group_id=restricted_group_id,
                    page_size=page_size,
                    next_page_token=next_page_token,
                    user_type=user_type,
                    current_user=current_user,
                    db=db
                )
            else:
                return {"status": "success", "users": [], "total_records": 0, "total_pending": 0}
        
        # 1. Obtener mapeo de grupos a correos y total de pendientes de la cuenta completa en paralelo
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Peticiones paralelas
            group_members_task = fetch_group_members_map(headers)
            pending_users_task = fetch_pending_users_with_groups(client, headers)
            
            email_to_groups, all_pending = await asyncio.gather(group_members_task, pending_users_task)
            total_pending = len(all_pending)

        # 2. Obtener usuarios locales de la base de datos
        db_users = []
        try:
            conn = pymysql.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASS,
                database=DB_NAME,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            with conn.cursor() as cursor:
                cursor.execute("SELECT email, first_name, last_name, role FROM login_zoom")
                db_users = cursor.fetchall()
            conn.close()
        except Exception as e:
            print("Error al obtener usuarios de la BD local:", str(e))

        # 3. Consultar listado de usuarios y acumular hasta tener page_size que coincidan con el tipo de licencia
        zoom_token, skip = decode_cursor(next_page_token)
        accumulated_users = []
        current_token = zoom_token
        total_zoom_records = 0
        total_skipped = 0
        next_token = ""
        next_skip = 0

        async with httpx.AsyncClient(timeout=30.0) as client:
            while len(accumulated_users) < page_size:
                fetch_size = 300 if user_type else page_size
                params = {
                    "page_size": fetch_size,
                    "status": status
                }
                if current_token:
                    params["next_page_token"] = current_token

                response = await client.get("https://api.zoom.us/v2/users", headers=headers, params=params)
                
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=response.status_code,
                        detail=f"Error de Zoom al listar usuarios: {response.json().get('message', response.text)}"
                    )
                
                data = response.json()
                users_page = data.get("users", [])
                total_zoom_records = data.get("total_records", 0)

                # Adjuntar los grupos a cada usuario
                for u in users_page:
                    u_email = u.get("email")
                    u["groups"] = email_to_groups.get(u_email, [])

                # Agregar usuarios locales en la primera consulta
                if not zoom_token:
                    zoom_emails = {u.get("email").lower().strip() for u in users_page if u.get("email")}
                    for db_u in db_users:
                        db_email = db_u.get("email").lower().strip()
                        if db_email not in zoom_emails:
                            users_page.append({
                                "id": "",
                                "first_name": db_u.get("first_name", ""),
                                "last_name": db_u.get("last_name", ""),
                                "email": db_u.get("email"),
                                "type": 0,
                                "status": "not_created",
                                "groups": [],
                                "not_in_zoom": True
                            })

                # Filtrar según tipo de licencia
                if user_type:
                    filtered_page = [u for u in users_page if u.get("type") == user_type and not u.get("not_in_zoom")]
                else:
                    filtered_page = users_page

                # Aplicar skip
                if total_skipped < skip:
                    to_skip = min(len(filtered_page), skip - total_skipped)
                    filtered_page = filtered_page[to_skip:]
                    total_skipped += to_skip

                accumulated_users.extend(filtered_page)
                
                if len(accumulated_users) >= page_size:
                    consumed = page_size - (len(accumulated_users) - len(filtered_page))
                    next_skip = skip + consumed
                    if next_skip >= (skip + len(filtered_page)):
                        next_token = data.get("next_page_token", "")
                        next_skip = 0
                    else:
                        next_token = current_token
                    break
                else:
                    current_token = data.get("next_page_token", "")
                    skip = 0
                    total_skipped = 0
                
                if not current_token or not users_page:
                    break

        final_users = accumulated_users[:page_size]

        # Combinar con pendientes de la cuenta completa en la primera página
        pending_to_merge = []
        if not zoom_token:
            pending_to_merge = all_pending
            if user_type:
                pending_to_merge = [u for u in pending_to_merge if u.get("type") == user_type]
            all_merged_users = pending_to_merge + final_users
        else:
            all_merged_users = final_users

        res_token = ""
        if next_token or next_skip > 0:
            res_token = encode_cursor(next_token, next_skip)

        return {
            "status": "success",
            "users": all_merged_users[:page_size],
            "total_records": total_zoom_records + len(db_users) + len(pending_to_merge),
            "total_pending": total_pending,
            "next_page_token": res_token
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@app.get("/api/users/export")
async def export_users_csv(
    group_id: Optional[str] = None,
    q: Optional[str] = None,
    current_user: str = Depends(verify_session)
):
    """
    Exporta la lista de usuarios (búsqueda, grupo o todos) a un archivo CSV compatible con Excel.
    """
    try:
        token = await get_zoom_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        
        # 1. Obtener mapeo completo de grupos a correos
        email_to_groups = await fetch_group_members_map(headers)
        
        users_to_export = []
        
        # A. Si es búsqueda por palabra clave / correo (q)
        if q:
            query = q.strip()
            # Búsqueda exacta si contiene @
            if "@" in query:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(f"https://api.zoom.us/v2/users/{query}", headers=headers)
                    if response.status_code == 200:
                        u_data = response.json()
                        u_data["groups"] = email_to_groups.get(query.lower().strip(), [])
                        users_to_export.append(u_data)
                    elif response.status_code == 404:
                        # Buscar en BD
                        db_user = None
                        try:
                            conn = pymysql.connect(
                                host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                                charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor
                            )
                            with conn.cursor() as cursor:
                                cursor.execute(
                                    "SELECT email, first_name, last_name FROM login_zoom WHERE email = %s",
                                    (query.lower().strip(),)
                                )
                                db_user = cursor.fetchone()
                            conn.close()
                        except Exception as e:
                            print("Error BD export:", str(e))
                        
                        if db_user:
                            users_to_export.append({
                                "first_name": db_user.get("first_name", ""),
                                "last_name": db_user.get("last_name", ""),
                                "email": db_user.get("email"),
                                "type": 0,
                                "groups": [],
                                "not_in_zoom": True
                            })
            else:
                # Búsqueda general
                zoom_users = []
                clean_q = query.lower().strip()
                candidates = []
                if " " not in clean_q:
                    candidates.append(f"{clean_q}@usmp.pe")
                    candidates.append(f"{clean_q}@usmpvirtual.edu.pe")

                async with httpx.AsyncClient(timeout=30.0) as client:
                    async def check_candidate(email_cand):
                        try:
                            res = await client.get(f"https://api.zoom.us/v2/users/{email_cand}", headers=headers)
                            if res.status_code == 200:
                                u_data = res.json()
                                u_data["groups"] = email_to_groups.get(email_cand, [])
                                return u_data
                        except Exception:
                            pass
                        return None

                    candidate_results = []
                    if candidates:
                        candidate_results = await asyncio.gather(*(check_candidate(c) for c in candidates))
                        candidate_results = [u for u in candidate_results if u is not None]

                    zoom_res = await client.get(
                        "https://api.zoom.us/v2/users",
                        headers=headers,
                        params={"status": "active", "keyword": query, "page_size": 100}
                    )
                    if zoom_res.status_code == 200:
                        raw_zoom_users = zoom_res.json().get("users", [])
                        for u in raw_zoom_users:
                            email_val = u.get("email", "").lower()
                            first_val = u.get("first_name", "").lower()
                            last_val = u.get("last_name", "").lower()
                            if clean_q in email_val or clean_q in first_val or clean_q in last_val:
                                u_email = u.get("email")
                                if u_email:
                                    u["groups"] = email_to_groups.get(u_email.lower().strip(), [])
                                zoom_users.append(u)

                zoom_emails = {u.get("email", "").lower().strip() for u in zoom_users}
                for cand_u in candidate_results:
                    cand_email = cand_u.get("email", "").lower().strip()
                    if cand_email not in zoom_emails:
                        zoom_users.append(cand_u)
                        zoom_emails.add(cand_email)

                db_users = []
                try:
                    conn = pymysql.connect(
                        host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                        charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor
                    )
                    with conn.cursor() as cursor:
                        tokens = query.strip().split()
                        if tokens:
                            clauses = []
                            params = []
                            for token in tokens:
                                clauses.append("(email LIKE %s OR first_name LIKE %s OR last_name LIKE %s)")
                                like_tok = f"%{token}%"
                                params.extend([like_tok, like_tok, like_tok])
                            sql_where = " AND ".join(clauses)
                            sql = f"SELECT email, first_name, last_name FROM login_zoom WHERE {sql_where}"
                            cursor.execute(sql, tuple(params))
                            db_users = cursor.fetchall()
                    conn.close()
                except Exception as e:
                    print("Error BD export LIKE:", str(e))

                merged = {}
                for u in zoom_users:
                    email_key = u.get("email", "").lower().strip()
                    if email_key:
                        merged[email_key] = u

                for db_u in db_users:
                    email_key = db_u.get("email", "").lower().strip()
                    if email_key not in merged:
                        merged[email_key] = {
                            "first_name": db_u.get("first_name", ""),
                            "last_name": db_u.get("last_name", ""),
                            "email": db_u.get("email"),
                            "type": 0,
                            "groups": [],
                            "not_in_zoom": True
                        }
                users_to_export = list(merged.values())

        # B. Si es filtro por grupo (group_id)
        elif group_id:
            sem = asyncio.Semaphore(5)
            members = []
            next_page_token = ""
            async with httpx.AsyncClient(timeout=30.0) as client:
                while True:
                    url = f"https://api.zoom.us/v2/groups/{group_id}/members?page_size=300"
                    if next_page_token:
                        url += f"&next_page_token={next_page_token}"
                    
                    async with sem:
                        response = await client.get(url, headers=headers)
                        
                    if response.status_code != 200:
                        break
                    data = response.json()
                    members.extend(data.get("members", []))
                    next_page_token = data.get("next_page_token")
                    if not next_page_token:
                        break
            
            for m in members:
                m_email = m.get("email")
                if m_email:
                    m["groups"] = email_to_groups.get(m_email.lower().strip(), [])
            users_to_export = members

        # C. Si es exportación general (todos los usuarios)
        else:
            sem = asyncio.Semaphore(5)
            zoom_users = []
            next_page_token = ""
            async with httpx.AsyncClient(timeout=30.0) as client:
                while True:
                    url = "https://api.zoom.us/v2/users?page_size=300&status=active"
                    if next_page_token:
                        url += f"&next_page_token={next_page_token}"
                    
                    async with sem:
                        response = await client.get(url, headers=headers)
                        
                    if response.status_code != 200:
                        break
                    data = response.json()
                    zoom_users.extend(data.get("users", []))
                    next_page_token = data.get("next_page_token")
                    if not next_page_token:
                        break

            for u in zoom_users:
                u_email = u.get("email")
                if u_email:
                    u["groups"] = email_to_groups.get(u_email.lower().strip(), [])

            db_users = []
            try:
                conn = pymysql.connect(
                    host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                    charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor
                )
                with conn.cursor() as cursor:
                    cursor.execute("SELECT email, first_name, last_name FROM login_zoom")
                    db_users = cursor.fetchall()
                conn.close()
            except Exception as e:
                print("Error BD export total:", str(e))

            zoom_emails = {u.get("email", "").lower().strip() for u in zoom_users if u.get("email")}
            for db_u in db_users:
                db_email = db_u.get("email", "").lower().strip()
                if db_email not in zoom_emails:
                    zoom_users.append({
                        "first_name": db_u.get("first_name", ""),
                        "last_name": db_u.get("last_name", ""),
                        "email": db_u.get("email"),
                        "type": 0,
                        "groups": [],
                        "not_in_zoom": True
                    })
            users_to_export = zoom_users

        # 2. Generar contenido CSV
        csv_lines = ["Grupo;Usuario;Correo;Licencia"]
        
        for user in users_to_export:
            name = f"{user.get('first_name') or ''} {user.get('last_name') or ''}".strip() or "Sin Nombre"
            email = user.get("email") or ""
            
            if user.get("not_in_zoom"):
                license_str = "Sin cuenta Zoom"
            elif user.get("type") == 2:
                license_str = "Zoom Meetings"
            else:
                license_str = "Basic"
                
            if user.get("not_in_zoom"):
                group_str = "No aplica"
            elif user.get("groups"):
                group_str = ", ".join(user.get("groups"))
            else:
                group_str = "Sin grupo"
                
            def escape(val):
                return f'"{str(val).replace(chr(34), chr(34)+chr(34))}"'
                
            row = f"{escape(group_str)};{escape(name)};{escape(email)};{escape(license_str)}"
            csv_lines.append(row)
            
        csv_content = "\r\n".join(csv_lines) + "\r\n"
        bom_csv = "\uFEFF" + csv_content
        
        return Response(
            content=bom_csv.encode('utf-8'),
            media_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=usuarios_export.csv"
            }
        )
        
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al exportar: {str(e)}")

@app.post("/api/groups/{group_id}/remove-licenses-mass")
async def remove_licenses_mass(
    group_id: str,
    current_user: str = Depends(verify_admin)
):
    """
    Remueve masivamente las licencias de Zoom (Tipo 2 -> Tipo 1) de todos los usuarios
    dentro del grupo seleccionado.
    """
    try:
        token = await get_zoom_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        
        # 1. Obtener todos los miembros del grupo
        members = []
        next_page_token = ""
        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                url = f"https://api.zoom.us/v2/groups/{group_id}/members?page_size=300"
                if next_page_token:
                    url += f"&next_page_token={next_page_token}"
                
                response = await client.get(url, headers=headers)
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=response.status_code,
                        detail=f"Error de Zoom al listar miembros para remover licencias: {response.json().get('message', response.text)}"
                    )
                data = response.json()
                members.extend(data.get("members", []))
                next_page_token = data.get("next_page_token")
                if not next_page_token:
                    break
        
        # 2. Filtrar los miembros que tengan tipo 2 (Licensed)
        licensed_members = [m for m in members if m.get("type") == 2]
        
        if not licensed_members:
            return {
                "status": "success",
                "removed_count": 0,
                "message": "No hay usuarios con licencia asignada en este grupo."
            }

        # 3. Remover las licencias de forma concurrente con Semaphore
        sem = asyncio.Semaphore(5)
        removed_count = 0
        errors = []

        async def downgrade_user(client, user):
            nonlocal removed_count
            user_id = user.get("id")
            email = user.get("email")
            async with sem:
                patch_res = await client.patch(
                    f"https://api.zoom.us/v2/users/{user_id}",
                    headers=headers,
                    json={"type": 1} # Downgrade to Basic
                )
                if patch_res.status_code in (200, 204):
                    removed_count += 1
                    group_name = await get_zoom_group_name_by_id(group_id, headers)
                    details_str = f"Removida licencia de Zoom Meetings masivamente (Cambio a tipo Basic) del usuario {email} en el grupo: {group_name}."
                    
                    def log_db(op_email, target_email, dt):
                        try:
                            conn = pymysql.connect(
                                host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                                charset='utf8mb4'
                            )
                            with conn.cursor() as cursor:
                                cursor.execute(
                                    "INSERT INTO zoom_activity_logs (operator_email, action_type, target_email, details) VALUES (%s, %s, %s, %s)",
                                    (op_email, "QUITAR_LICENCIA_MASIVA", target_email, dt)
                                )
                                conn.commit()
                            conn.close()
                        except Exception as e:
                            print("Error al insertar log de auditoría:", str(e))
                            
                    await asyncio.to_thread(log_db, current_user, email, details_str)
                else:
                    errors.append(f"Error con {email}: {patch_res.text}")

        async with httpx.AsyncClient(timeout=30.0) as client:
            await asyncio.gather(*(downgrade_user(client, m) for m in licensed_members))

        return {
            "status": "success",
            "removed_count": removed_count,
            "total_licensed_found": len(licensed_members),
            "errors": errors,
            "message": f"Se quitó la licencia exitosamente a {removed_count} de {len(licensed_members)} usuarios en el grupo."
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno al quitar licencias masivamente: {str(e)}")

@app.post("/api/users/import-csv")
async def import_users_csv(
    file: UploadFile = File(...),
    group_id: Optional[str] = Query(None),
    current_user: str = Depends(verify_admin),
    db=Depends(get_db_conn)
):
    """
    Importa una lista de usuarios a partir de un archivo CSV que contiene 3 columnas:
    'Nombres y Apellidos', 'Correo' y 'Licencia Zoom Meetings'.
    Si cumple las validaciones de dominio y datos, los crea o actualiza y los une al grupo especificado.
    """
    try:
        content = await file.read()
        try:
            decoded = content.decode('utf-8-sig')
        except UnicodeDecodeError:
            try:
                decoded = content.decode('latin-1')
            except Exception:
                raise HTTPException(status_code=400, detail="Codificación de archivo no soportada (use UTF-8 o Latin-1)")

        lines = [line.strip() for line in decoded.splitlines() if line.strip()]
        if not lines:
            raise HTTPException(status_code=400, detail="El archivo está vacío.")

        # Determinar delimitador (punto y coma o coma)
        first_line = lines[0]
        delimiter = ';' if ';' in first_line else ','
        
        import csv
        import io
        f = io.StringIO(decoded)
        reader = csv.reader(f, delimiter=delimiter)
        
        # Leer cabecera
        header = next(reader, None)
        if not header:
            raise HTTPException(status_code=400, detail="No se encontró la cabecera en el archivo.")

        # Detectar columnas por posición o nombre
        name_idx, email_idx, license_idx = 0, 1, 2
        for idx, col in enumerate(header):
            col_lower = col.lower()
            if "nombre" in col_lower or "apellido" in col_lower:
                name_idx = idx
            elif "correo" in col_lower or "email" in col_lower:
                email_idx = idx
            elif "licencia" in col_lower or "zoom" in col_lower:
                license_idx = idx

        user_record = get_user_by_email(current_user, db)
        assigned_group = user_record.get("assigned_group") if user_record else None

        token = await get_zoom_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        
        # Si el usuario tiene restricción de grupo, forzar el group_id al de su grupo
        if assigned_group:
            restricted_group_id = await get_zoom_group_id_by_name(assigned_group, headers)
            if restricted_group_id:
                group_id = restricted_group_id

        # Si no hay group_id, obtener o crear el por defecto
        target_group_id = group_id.strip() if group_id else None
        if not target_group_id:
            target_group_id = await get_or_create_default_group_id(headers)

        success_count = 0
        error_details = []

        async with httpx.AsyncClient(timeout=30.0) as client:
            for row_num, row in enumerate(reader, start=2):
                if not row or len(row) <= max(name_idx, email_idx, license_idx):
                    continue
                
                raw_name = row[name_idx].strip()
                raw_email = row[email_idx].strip().lower()
                raw_license = row[license_idx].strip().lower()

                if not raw_email or not raw_name:
                    error_details.append(f"Fila {row_num}: Nombre o correo vacíos.")
                    continue

                # Validar dominio de correo
                if not (raw_email.endswith("@usmp.pe") or raw_email.endswith("@usmpvirtual.edu.pe")):
                    error_details.append(f"Fila {row_num}: Correo '{raw_email}' no pertenece a dominios USMP.")
                    continue

                # Determinar tipo de licencia (2 = Licensed, 1 = Basic)
                is_licensed = any(val in raw_license for val in ["si", "sí", "yes", "licensed", "2", "zoom", "true", "activo", "activa"])
                user_type = 2 if is_licensed else 1

                # Parsear nombres y apellidos (primer término es first_name, el resto last_name)
                name_parts = raw_name.split()
                first_name = name_parts[0] if name_parts else ""
                last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else ""

                try:
                    # Crear o actualizar en Zoom
                    check_res = await client.get(f"https://api.zoom.us/v2/users/{raw_email}", headers=headers)
                    already_exists = False
                    user_id = None
                    existing_group_ids = []

                    if check_res.status_code == 200:
                        already_exists = True
                        user_data = check_res.json()
                        user_id = user_data.get("id")
                        current_type = user_data.get("type")
                        existing_group_ids = user_data.get("group_ids", [])
                        
                        if current_type != user_type:
                            if user_type == 2:
                                has_lic = await check_available_licenses(client, headers)
                                if not has_lic:
                                    error_details.append(f"Fila {row_num}: Error al actualizar licencia. No hay licencias de Zoom Meetings (Licensed) disponibles.")
                                    continue
                            patch_res = await client.patch(
                                f"https://api.zoom.us/v2/users/{user_id}",
                                headers=headers,
                                json={"type": user_type}
                            )
                            if patch_res.status_code not in (200, 204):
                                error_details.append(f"Fila {row_num}: Error al actualizar licencia en Zoom.")
                                continue
                    elif check_res.status_code == 404:
                        if user_type == 2:
                            has_lic = await check_available_licenses(client, headers)
                            if not has_lic:
                                error_details.append(f"Fila {row_num}: Error al invitar. No hay licencias de Zoom Meetings (Licensed) disponibles.")
                                continue
                        # Crear/Invitar
                        create_res = await client.post(
                            "https://api.zoom.us/v2/users",
                            headers=headers,
                            json={
                                "action": "create",
                                "user_info": {
                                    "email": raw_email,
                                    "type": user_type,
                                    "first_name": first_name,
                                    "last_name": last_name
                                }
                            }
                        )
                        if create_res.status_code != 201:
                            invite_res = await client.post(
                                "https://api.zoom.us/v2/users",
                                headers=headers,
                                json={
                                    "action": "invite",
                                    "user_info": {
                                        "email": raw_email,
                                        "type": user_type,
                                        "first_name": first_name,
                                        "last_name": last_name
                                    }
                                }
                            )
                            if invite_res.status_code != 201:
                                error_details.append(f"Fila {row_num}: Error al crear/invitar en Zoom.")
                                continue
                    else:
                        error_details.append(f"Fila {row_num}: Error al verificar usuario en Zoom.")
                        continue

                    # Remover de otros grupos de Zoom para asegurar transferencia limpia
                    if already_exists and user_id:
                        for old_g_id in existing_group_ids:
                            if old_g_id and old_g_id != target_group_id:
                                await client.delete(
                                    f"https://api.zoom.us/v2/groups/{old_g_id}/members/{user_id}",
                                    headers=headers
                                )

                    # Añadir al grupo
                    await client.post(
                        f"https://api.zoom.us/v2/groups/{target_group_id}/members",
                        headers=headers,
                        json={"members": [{"email": raw_email}]}
                    )
                    
                    group_name = await get_zoom_group_name_by_id(target_group_id, headers)
                    details_str = f"Importado vía CSV. Licencia: {license_name}. Agregado al grupo: {group_name}."
                    
                    def log_db(op_email, target_email, dt):
                        try:
                            conn = pymysql.connect(
                                host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                                charset='utf8mb4'
                            )
                            with conn.cursor() as cursor:
                                cursor.execute(
                                    "INSERT INTO zoom_activity_logs (operator_email, action_type, target_email, details) VALUES (%s, %s, %s, %s)",
                                    (op_email, "IMPORTAR_CSV", target_email, dt)
                                )
                                conn.commit()
                            conn.close()
                        except Exception as e:
                            print("Error al insertar log de auditoría:", str(e))

                    await asyncio.to_thread(log_db, current_user, raw_email, details_str)
                    success_count += 1
                except Exception as e:
                    error_details.append(f"Fila {row_num}: {str(e)}")

        return {
            "status": "success",
            "imported_count": success_count,
            "failed_count": len(error_details),
            "errors": error_details,
            "message": f"Importación finalizada. {success_count} usuarios importados con éxito, {len(error_details)} fallidos."
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno al importar archivo CSV: {str(e)}")

@app.get("/api/users/pending")
async def list_pending_users(
    current_user: str = Depends(verify_session),
    db=Depends(get_db_conn)
):
    """
    Lista completa de usuarios con invitación PENDIENTE (aún no aceptada) en Zoom,
    junto con la facultad/grupo a la que fueron invitados. Respeta el scoping por
    facultad de los administradores no-globales.
    """
    try:
        user_record = get_user_by_email(current_user, db)
        assigned_group = user_record.get("assigned_group") if user_record else None

        token = await get_zoom_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        async with httpx.AsyncClient(timeout=30.0) as client:
            all_pending = await fetch_pending_users_with_groups(client, headers)

        if assigned_group:
            all_pending = [
                u for u in all_pending
                if u.get("groups") and u.get("groups")[0].strip().lower() == assigned_group.strip().lower()
            ]

        return {"status": "success", "pending_users": all_pending, "total_pending": len(all_pending)}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al listar usuarios pendientes: {str(e)}")

@app.get("/api/users/search")
async def search_zoom_user(
    q: Optional[str] = Query(None),
    email: Optional[str] = Query(None),
    group_id: Optional[str] = Query(None),
    current_user: str = Depends(verify_session),
    db=Depends(get_db_conn)
):
    """
    Busca usuarios en Zoom por palabra clave o correo, y los fusiona con la base de datos local.
    """
    query = q or email
    if not query:
        raise HTTPException(
            status_code=400,
            detail="Se requiere el parámetro 'q' o 'email' para realizar la búsqueda."
        )
    query = query.strip()

    try:
        user_record = get_user_by_email(current_user, db)
        assigned_group = user_record.get("assigned_group") if user_record else None

        token = await get_zoom_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        
        # Si el usuario tiene restricción de grupo, forzar a buscar dentro de su grupo
        if assigned_group:
            restricted_group_id = await get_zoom_group_id_by_name(assigned_group, headers)
            group_id = restricted_group_id
        
        # SI SE ESPECIFICÓ UN GROUP_ID, HACEMOS BÚSQUEDA EXCLUSIVA Y GLOBAL DENTRO DE ESE GRUPO EN ZOOM (PAGINANDO DE 300 EN 300)
        if group_id:
            all_group_members = []
            current_token = ""
            group_name = None
            async with httpx.AsyncClient(timeout=30.0) as client:
                # A. Obtener el nombre del grupo
                groups_res = await client.get("https://api.zoom.us/v2/groups", headers=headers)
                if groups_res.status_code == 200:
                    for g in groups_res.json().get("groups", []):
                        if g.get("id") == group_id:
                            group_name = g.get("name")
                            break

                # B. Descargar todos los miembros del grupo
                while True:
                    params = {"page_size": 300}
                    if current_token:
                        params["next_page_token"] = current_token
                    
                    response = await client.get(
                        f"https://api.zoom.us/v2/groups/{group_id}/members",
                        headers=headers,
                        params=params
                    )
                    if response.status_code != 200:
                        break
                    
                    data = response.json()
                    members = data.get("members", [])
                    all_group_members.extend(members)
                    
                    current_token = data.get("next_page_token")
                    if not current_token or not members:
                        break

            # C. Filtrar localmente por los tokens del query (búsqueda inteligente multitérmino)
            clean_q_tokens = query.lower().strip().split()
            filtered_members = []
            for m in all_group_members:
                m_email = m.get("email", "").lower().strip()
                m_first = m.get("first_name", "").lower().strip()
                m_last = m.get("last_name", "").lower().strip()
                m_full = f"{m_first} {m_last}"
                
                # Todos los tokens del query deben coincidir en correo, nombre o apellido
                match = True
                for tok in clean_q_tokens:
                    if tok not in m_email and tok not in m_first and tok not in m_last and tok not in m_full:
                        match = False
                        break
                if match:
                    m["groups"] = [group_name] if group_name else []
                    filtered_members.append(m)

            single_user = filtered_members[0] if filtered_members else None
            return {"status": "success", "user": single_user, "users": filtered_members}

        email_to_groups = await fetch_group_members_map(headers)

        # 1. Si la consulta contiene '@', hacemos una búsqueda exacta primero en Zoom, luego en la BD
        if "@" in query:
            user_list = []
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(f"https://api.zoom.us/v2/users/{query}", headers=headers)
                if response.status_code == 200:
                    user_data = response.json()
                    user_data["groups"] = email_to_groups.get(query.lower().strip(), [])
                    user_list.append(user_data)
                elif response.status_code == 404:
                    # Buscar en la base de datos local
                    db_user = None
                    try:
                        conn = pymysql.connect(
                            host=DB_HOST,
                            user=DB_USER,
                            password=DB_PASS,
                            database=DB_NAME,
                            charset='utf8mb4',
                            cursorclass=pymysql.cursors.DictCursor
                        )
                        with conn.cursor() as cursor:
                            cursor.execute(
                                "SELECT email, first_name, last_name, role FROM login_zoom WHERE email = %s",
                                (query.lower().strip(),)
                            )
                            db_user = cursor.fetchone()
                        conn.close()
                    except Exception as e:
                        print("Error al buscar en BD local:", str(e))
                    
                    if db_user:
                        user_list.append({
                            "id": "",
                            "first_name": db_user.get("first_name", ""),
                            "last_name": db_user.get("last_name", ""),
                            "email": db_user.get("email"),
                            "type": 0,
                            "status": "not_created",
                            "groups": [],
                            "not_in_zoom": True
                        })
            
            single_user = user_list[0] if user_list else None
            return {"status": "success", "user": single_user, "users": user_list}
            
        # 2. Si no contiene '@', hacemos una búsqueda por palabra clave tanto en Zoom como en BD
        else:
            zoom_users = []
            clean_q = query.lower().strip()
            
            # Generar correos candidatos para búsqueda directa por prefijo (flujo rápido)
            candidates = []
            if " " not in clean_q:
                candidates.append(f"{clean_q}@usmp.pe")
                candidates.append(f"{clean_q}@usmpvirtual.edu.pe")

            async with httpx.AsyncClient(timeout=30.0) as client:
                # A. Buscar candidatos directamente
                async def check_candidate(email_cand):
                    try:
                        res = await client.get(f"https://api.zoom.us/v2/users/{email_cand}", headers=headers)
                        if res.status_code == 200:
                            u_data = res.json()
                            u_data["groups"] = email_to_groups.get(email_cand, [])
                            return u_data
                    except Exception:
                        pass
                    return None

                candidate_results = []
                if candidates:
                    candidate_results = await asyncio.gather(*(check_candidate(c) for c in candidates))
                    candidate_results = [u for u in candidate_results if u is not None]

                # B. Búsqueda en listado de Zoom por si acaso (para coincidencias en nombre en primera página)
                zoom_res = await client.get(
                    "https://api.zoom.us/v2/users",
                    headers=headers,
                    params={"status": "active", "keyword": query, "page_size": 100}
                )
                if zoom_res.status_code == 200:
                    raw_zoom_users = zoom_res.json().get("users", [])
                    for u in raw_zoom_users:
                        email_val = u.get("email", "").lower()
                        first_val = u.get("first_name", "").lower()
                        last_val = u.get("last_name", "").lower()
                        if clean_q in email_val or clean_q in first_val or clean_q in last_val:
                            u_email = u.get("email")
                            if u_email:
                                u["groups"] = email_to_groups.get(u_email.lower().strip(), [])
                            zoom_users.append(u)

            # Combinar y eliminar duplicados
            zoom_emails = {u.get("email", "").lower().strip() for u in zoom_users}
            for cand_u in candidate_results:
                cand_email = cand_u.get("email", "").lower().strip()
                if cand_email not in zoom_emails:
                    zoom_users.append(cand_u)
                    zoom_emails.add(cand_email)
            
            db_users = []
            try:
                conn = pymysql.connect(
                    host=DB_HOST,
                    user=DB_USER,
                    password=DB_PASS,
                    database=DB_NAME,
                    charset='utf8mb4',
                    cursorclass=pymysql.cursors.DictCursor
                )
                with conn.cursor() as cursor:
                    tokens = query.strip().split()
                    if tokens:
                        clauses = []
                        params = []
                        for token in tokens:
                            clauses.append("(email LIKE %s OR first_name LIKE %s OR last_name LIKE %s)")
                            like_tok = f"%{token}%"
                            params.extend([like_tok, like_tok, like_tok])
                        sql_where = " AND ".join(clauses)
                        sql = f"SELECT email, first_name, last_name, role FROM login_zoom WHERE {sql_where}"
                        cursor.execute(sql, tuple(params))
                        db_users = cursor.fetchall()
                conn.close()
            except Exception as e:
                print("Error al buscar en BD local:", str(e))
                
            merged = {}
            for u in zoom_users:
                email_key = u.get("email", "").lower().strip()
                if email_key:
                    merged[email_key] = u
                    
            for db_u in db_users:
                email_key = db_u.get("email", "").lower().strip()
                if email_key not in merged:
                    merged[email_key] = {
                        "id": "",
                        "first_name": db_u.get("first_name", ""),
                        "last_name": db_u.get("last_name", ""),
                        "email": db_u.get("email"),
                        "type": 0,
                        "status": "not_created",
                        "groups": [],
                        "not_in_zoom": True
                    }
                    
            user_list = list(merged.values())
            
            # Si se pasó un filtro de grupo, filtrar localmente la lista de resultados
            if group_name:
                clean_group_name = group_name.strip().lower()
                filtered = []
                for u in user_list:
                    user_groups = u.get("groups", [])
                    if any(gname.strip().lower() == clean_group_name for gname in user_groups):
                        filtered.append(u)
                user_list = filtered

            single_user = user_list[0] if user_list else None
            return {"status": "success", "user": single_user, "users": user_list}
            
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@app.get("/api/licenses")
async def get_license_usage(current_user: str = Depends(verify_session)):
    """
    Obtiene el uso y disponibilidad de las licencias contratadas en Zoom.
    Requiere el scope 'billing:read:admin' en Zoom Marketplace.
    """
    try:
        token = await get_zoom_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            plans_task = client.get("https://api.zoom.us/v2/accounts/me/plans/usage", headers=headers)
            pending_task = client.get("https://api.zoom.us/v2/users?status=pending&page_size=1", headers=headers)
            
            plans_res, pending_res = await asyncio.gather(plans_task, pending_task)
            
            if plans_res.status_code == 200:
                data = plans_res.json()
                plan_base = data.get("plan_base", {})
                hosts = plan_base.get("hosts", 0)
                usage = plan_base.get("usage", 0)
                
                total_pending = 0
                if pending_res.status_code == 200:
                    total_pending = pending_res.json().get("total_records", 0)
                
                # Extract large meeting stats
                plan_large_meeting = data.get("plan_large_meeting", [])
                large_meeting_total = 0
                large_meeting_used = 0
                if isinstance(plan_large_meeting, list):
                    for p in plan_large_meeting:
                        large_meeting_total += p.get("hosts", 0)
                        large_meeting_used += p.get("usage", 0)
                elif isinstance(plan_large_meeting, dict):
                    large_meeting_total = plan_large_meeting.get("hosts", 0)
                    large_meeting_used = plan_large_meeting.get("usage", 0)
                    
                # Extract webinar stats
                plan_webinar = data.get("plan_webinar", [])
                webinar_total = 0
                webinar_used = 0
                if isinstance(plan_webinar, list):
                    for p in plan_webinar:
                        webinar_total += p.get("hosts", 0)
                        webinar_used += p.get("usage", 0)
                elif isinstance(plan_webinar, dict):
                    webinar_total = plan_webinar.get("hosts", 0)
                    webinar_used = plan_webinar.get("usage", 0)
                    
                # Extract zoom phone stats
                plan_zoom_phone = data.get("plan_zoom_phone", [])
                phone_total = 0
                phone_used = 0
                if isinstance(plan_zoom_phone, list):
                    for p in plan_zoom_phone:
                        phone_total += p.get("hosts", 0)
                        phone_used += p.get("usage", 0)
                elif isinstance(plan_zoom_phone, dict):
                    phone_total = plan_zoom_phone.get("hosts", 0)
                    phone_used = plan_zoom_phone.get("usage", 0)
                    
                return {
                    "status": "success",
                    "total_licenses": hosts,
                    "used_licenses": usage,
                    "available_licenses": max(0, hosts - usage - total_pending),
                    "large_meeting": {
                        "total": large_meeting_total,
                        "used": large_meeting_used,
                        "available": max(0, large_meeting_total - large_meeting_used)
                    },
                    "webinar": {
                        "total": webinar_total,
                        "used": webinar_used,
                        "available": max(0, webinar_total - webinar_used)
                    },
                    "zoom_phone": {
                        "total": phone_total,
                        "used": phone_used,
                        "available": max(0, phone_total - phone_used)
                    }
                }
            else:
                # Retorna código y respuesta para guiar sobre el scope de facturación
                return {
                    "status": "error",
                    "code": response.status_code,
                    "detail": "Falta el permiso 'billing:read:plan_usage:admin' (Ver el uso de un plan) en Zoom Marketplace (sección Commerce). Actívalo junto con 'billing:read:plan:admin' y reactiva tu aplicación."
                }
    except Exception as e:
        return {"status": "error", "detail": str(e)}

@app.post("/api/users")
async def create_and_assign_user(
    request: UserCreateRequest,
    current_user: str = Depends(verify_session),
    db=Depends(get_db_conn)
):
    """
    Lógica de negocio: Asignar licencia (Tipo 2 o Tipo 1) y añadir al grupo seleccionado.
    """
    token = await get_zoom_access_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    user_record = get_user_by_email(current_user, db)
    assigned_group = user_record.get("assigned_group") if user_record else None
    
    email = request.email.strip()
    first_name = request.first_name.strip()
    last_name = request.last_name.strip()
    selected_group_id = request.group_id.strip() if request.group_id else None
    user_type = request.user_type
    
    if assigned_group:
        restricted_group_id = await get_zoom_group_id_by_name(assigned_group, headers)
        if restricted_group_id:
            selected_group_id = restricted_group_id
    
    user_id = None
    already_exists = False
    licensed_assigned = False
    existing_group_ids = []
    pending_name_change_ignored = False

    async with httpx.AsyncClient(timeout=30.0) as client:
        check_response = await client.get(f"https://api.zoom.us/v2/users/{email}", headers=headers)

        create_fresh = False

        if check_response.status_code == 200:
            already_exists = True
            user_data = check_response.json()
            user_id = user_data.get("id")
            current_type = user_data.get("type")
            existing_group_ids = user_data.get("group_ids", [])

            needs_profile_patch = (current_type != user_type) or (
                (first_name and first_name != user_data.get("first_name", ""))
                or (last_name and last_name != user_data.get("last_name", ""))
            )

            if needs_profile_patch and user_data.get("status") == "pending":
                # Zoom no permite hacer PATCH al perfil de una invitación pendiente todavía no
                # aceptada (falla con "user does not exist" aunque el GET sí la encuentre).
                # En cambio, volver a invitar (acción "create"/"invite") a ese mismo correo SÍ
                # actualiza el tipo de licencia correctamente — sin necesidad de un DELETE previo,
                # que además choca con el límite de Zoom de "ya hay una solicitud de desasociar
                # a este usuario" si se reintenta. El nombre/apellido, en cambio, nunca se guarda
                # para una cuenta no verificada por más que se reintente: es una restricción de
                # Zoom (solo se completa cuando la persona acepta e inicia sesión), así que se
                # avisa en vez de prometer algo que la plataforma no permite.
                pending_name_change_ignored = bool(
                    (first_name and first_name != user_data.get("first_name", ""))
                    or (last_name and last_name != user_data.get("last_name", ""))
                )
                already_exists = False
                existing_group_ids = []
                create_fresh = True
            else:
                if current_type != user_type:
                    if user_type == 2:
                        has_lic = await check_available_licenses(client, headers)
                        if not has_lic:
                            raise HTTPException(
                                status_code=400,
                                detail="No hay licencias disponibles de Zoom Meetings (Licensed). Por favor compre más licencias."
                            )
                    patch_res = await client.patch(
                        f"https://api.zoom.us/v2/users/{user_id}",
                        headers=headers,
                        json={"type": user_type}
                    )
                    if patch_res.status_code not in (200, 204):
                        raise HTTPException(
                            status_code=patch_res.status_code,
                            detail=f"Error de Zoom al actualizar licencia a Tipo {user_type}: {patch_res.json().get('message', patch_res.text)}"
                        )
                licensed_assigned = True

                # Actualizar nombre/apellido si vienen datos nuevos (el formulario de edición los manda;
                # el flujo del asistente de IA normalmente no, así que no se pisa un nombre real con "").
                name_changed = (
                    (first_name and first_name != user_data.get("first_name", ""))
                    or (last_name and last_name != user_data.get("last_name", ""))
                )
                if name_changed:
                    name_payload = {}
                    if first_name:
                        name_payload["first_name"] = first_name
                    if last_name:
                        name_payload["last_name"] = last_name
                    name_patch_res = await client.patch(
                        f"https://api.zoom.us/v2/users/{user_id}",
                        headers=headers,
                        json=name_payload
                    )
                    if name_patch_res.status_code not in (200, 204):
                        raise HTTPException(
                            status_code=name_patch_res.status_code,
                            detail=f"Error de Zoom al actualizar nombre/apellido: {name_patch_res.json().get('message', name_patch_res.text)}"
                        )

        elif check_response.status_code == 404:
            create_fresh = True
        else:
            raise HTTPException(
                status_code=check_response.status_code,
                detail=f"Error de Zoom al verificar existencia del usuario: {check_response.json().get('message', check_response.text)}"
            )

        if create_fresh:
            if user_type == 2:
                has_lic = await check_available_licenses(client, headers)
                if not has_lic:
                    raise HTTPException(
                        status_code=400,
                        detail="No hay licencias disponibles de Zoom Meetings (Licensed) para invitar a este nuevo usuario."
                    )
            create_res = await client.post(
                "https://api.zoom.us/v2/users",
                headers=headers,
                json={
                    "action": "create",
                    "user_info": {
                        "email": email,
                        "type": user_type,
                        "first_name": first_name,
                        "last_name": last_name
                    }
                }
            )
            
            if create_res.status_code != 201:
                invite_res = await client.post(
                    "https://api.zoom.us/v2/users",
                    headers=headers,
                    json={
                        "action": "invite",
                        "user_info": {
                            "email": email,
                            "type": user_type,
                            "first_name": first_name,
                            "last_name": last_name
                        }
                    }
                )
                if invite_res.status_code != 201:
                    raise HTTPException(
                        status_code=invite_res.status_code,
                        detail=f"Error de Zoom al crear e invitar usuario: {invite_res.json().get('message', invite_res.text)}"
                    )
                user_id = invite_res.json().get("id")
            else:
                user_id = create_res.json().get("id")
            licensed_assigned = True

        if not selected_group_id:
            selected_group_id = await get_or_create_default_group_id(headers)
        
        # Remover de otros grupos de Zoom para asegurar transferencia limpia
        if already_exists and user_id:
            for old_g_id in existing_group_ids:
                if old_g_id and old_g_id != selected_group_id:
                    await client.delete(
                        f"https://api.zoom.us/v2/groups/{old_g_id}/members/{user_id}",
                        headers=headers
                    )

        group_res = await client.post(
            f"https://api.zoom.us/v2/groups/{selected_group_id}/members",
            headers=headers,
            json={"members": [{"email": email}]}
        )
        
        group_added = False
        if group_res.status_code in (200, 201):
            group_added = True
        elif group_res.status_code == 409 or "already" in group_res.text.lower():
            group_added = True
        else:
            raise HTTPException(
                status_code=group_res.status_code,
                detail=f"Usuario procesado, pero falló la asignación al grupo en Zoom: {group_res.json().get('message', group_res.text)}"
            )
            
    license_name = "Licensed (Zoom Meetings)" if user_type == 2 else "Basic (Sin licencia)"
    
    group_name = await get_zoom_group_name_by_id(selected_group_id, headers) or "(sin grupo)"
    action_type = "ACTUALIZAR" if already_exists else "CREAR"
    details_str = f"Asignada licencia: {license_name}. Agregado al grupo: {group_name}."
    
    def log_db(op_email, act_type, tgt_email, dt):
        try:
            conn = pymysql.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASS,
                database=DB_NAME,
                charset='utf8mb4'
            )
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO zoom_activity_logs (operator_email, action_type, target_email, details) VALUES (%s, %s, %s, %s)",
                    (op_email, act_type, tgt_email, dt)
                )
                conn.commit()
            conn.close()
        except Exception as e:
            print("Error al insertar log de auditoría:", str(e))
            
    await asyncio.to_thread(log_db, current_user, action_type, email, details_str)

    success_message = f"Usuario {'actualizado' if already_exists else 'invitado/creado'} con licencia {license_name} y asignado al grupo con éxito."
    if pending_name_change_ignored:
        success_message += (
            " Nota: el tipo de licencia y grupo sí se actualizaron, pero Zoom no permite guardar el "
            "nombre/apellido hasta que el usuario acepte su invitación e inicie sesión por primera vez."
        )

    return {
        "status": "success",
        "email": email,
        "already_exists": already_exists,
        "license_assigned": licensed_assigned,
        "group_assigned": group_added,
        "message": success_message
    }

# ----------------- ENDPOINTS DE AUTENTICACIÓN -----------------

@app.post("/api/register")
def register_user(req: RegisterRequest, db=Depends(get_db_conn)):
    email = req.email.lower().strip()
    
    # Validación estricta de dominios
    if not (email.endswith("@usmp.pe") or email.endswith("@usmpvirtual.edu.pe")):
        raise HTTPException(
            status_code=400,
            detail="Registro bloqueado: Solo se permiten correos @usmp.pe o @usmpvirtual.edu.pe"
        )
        
    with db.cursor() as cursor:
        # Verificar si el usuario ya existe
        cursor.execute("SELECT id FROM login_zoom WHERE email = %s", (email,))
        existing = cursor.fetchone()
        if existing:
            raise HTTPException(
                status_code=400,
                detail="El correo electrónico ya se encuentra registrado."
            )
            
        # Hashear contraseña e insertar
        hashed = hash_password(req.password)
        cursor.execute(
            "INSERT INTO login_zoom (email, password, first_name, last_name) VALUES (%s, %s, %s, %s)",
            (email, hashed, req.first_name.strip(), req.last_name.strip())
        )
        db.commit()
        
    return {"status": "success", "message": "Cuenta creada con éxito."}

@app.post("/api/login")
def login_user(req: LoginRequest, db=Depends(get_db_conn)):
    email = req.email.lower().strip()
    
    # Validación estricta de dominios
    if not (email.endswith("@usmp.pe") or email.endswith("@usmpvirtual.edu.pe")):
        raise HTTPException(
            status_code=400,
            detail="Acceso denegado: Solo se permiten correos @usmp.pe o @usmpvirtual.edu.pe"
        )
        
    with db.cursor() as cursor:
        cursor.execute("SELECT password, first_name, last_name FROM login_zoom WHERE email = %s", (email,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Correo o contraseña incorrectos."
            )
            
        # Verificar hash de contraseña
        hashed = hash_password(req.password)
        if user["password"] != hashed:
            raise HTTPException(
                status_code=401,
                detail="Correo o contraseña incorrectos."
            )
            
    # Crear cookie de sesión firmada
    signed_token = sign_value(email)
    response = JSONResponse(content={"status": "success", "message": "Inicio de sesión exitoso."})
    response.set_cookie(
        key="session_token",
        value=signed_token,
        httponly=True,
        max_age=86400 * 7, # 7 días
        samesite="lax",
        secure=False,  # Cambiar a True en producción si usa HTTPS
        path="/"
    )
    return response

@app.post("/api/logout")
def logout_user():
    response = JSONResponse(content={"status": "success", "message": "Cierre de sesión exitoso."})
    response.delete_cookie("session_token")
    return response

@app.get("/api/me")
def get_current_user(request: Request, db=Depends(get_db_conn)):
    session_token = request.cookies.get("session_token")
    email = None
    if session_token:
        email = verify_value(session_token)
        
    if not email:
        raise HTTPException(status_code=401, detail="No autenticado")
        
    with db.cursor() as cursor:
        cursor.execute("SELECT email, first_name, last_name, role, assigned_group FROM login_zoom WHERE email = %s", (email,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")
            
    return user

@app.get("/api/me/zoom")
async def get_current_user_zoom_status(current_user: str = Depends(verify_session)):
    """
    Obtiene el estado de Zoom del usuario autenticado (licencia y grupos).
    Cualquier usuario autenticado puede consultar su propio estado.
    """
    try:
        token = await get_zoom_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"https://api.zoom.us/v2/users/{current_user}", headers=headers)
            
            if response.status_code == 200:
                user_data = response.json()
                email_to_groups = await fetch_group_members_map(headers)
                user_data["groups"] = email_to_groups.get(current_user, [])
                return {"status": "success", "user": user_data}
            elif response.status_code == 404:
                return {"status": "success", "user": None}
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Error de Zoom al buscar información personal: {response.json().get('message', response.text)}"
                )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@app.post("/api/reset-password")
def reset_password(req: ResetPasswordRequest, db=Depends(get_db_conn)):
    email = req.email.lower().strip()
    
    # Validación de dominios
    if not (email.endswith("@usmp.pe") or email.endswith("@usmpvirtual.edu.pe")):
        raise HTTPException(
            status_code=400,
            detail="Restablecimiento bloqueado: Solo se permiten correos @usmp.pe o @usmpvirtual.edu.pe"
        )
        
    with db.cursor() as cursor:
        cursor.execute("SELECT id FROM login_zoom WHERE email = %s", (email,))
        existing = cursor.fetchone()
        if not existing:
            raise HTTPException(
                status_code=404,
                detail="El correo electrónico no se encuentra registrado en el sistema."
            )
            
        hashed = hash_password(req.new_password)
        cursor.execute(
            "UPDATE login_zoom SET password = %s WHERE email = %s",
            (hashed, email)
        )
        db.commit()
        
    return {"status": "success", "message": "Contraseña restablecida con éxito."}

@app.get("/api/logs")
async def list_activity_logs(current_user: str = Depends(verify_admin), db=Depends(get_db_conn)):
    email_lower = current_user.lower()
    if "admin" not in email_lower and "jtovar" not in email_lower:
        raise HTTPException(status_code=403, detail="Acceso denegado: Solo el administrador principal y jtovar pueden ver las operaciones.")
    try:
        user_record = get_user_by_email(current_user, db)
        assigned_group = user_record.get("assigned_group") if user_record else None

        if assigned_group:
            # Obtener miembros de Zoom en su grupo para poder filtrar por target_email
            token = await get_zoom_access_token()
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            
            group_emails = []
            restricted_group_id = await get_zoom_group_id_by_name(assigned_group, headers)
            if restricted_group_id:
                # Obtener los miembros del grupo paginados de 300 en 300
                next_page_token = ""
                async with httpx.AsyncClient(timeout=30.0) as client:
                    while True:
                        url = f"https://api.zoom.us/v2/groups/{restricted_group_id}/members?page_size=300"
                        if next_page_token:
                            url += f"&next_page_token={next_page_token}"
                        res = await client.get(url, headers=headers)
                        if res.status_code == 200:
                            data = res.json()
                            members = data.get("members", [])
                            for m in members:
                                if m.get("email"):
                                    group_emails.append(m.get("email").strip().lower())
                            next_page_token = data.get("next_page_token")
                            if not next_page_token:
                                break
                        else:
                            break

            # Consulta SQL filtrando por operator_email, target_email (si están en el grupo) o details que contengan el grupo
            with db.cursor() as cursor:
                # Si tenemos correos de grupo, los incluimos en la consulta
                if group_emails:
                    query = """
                        SELECT operator_email, action_type, target_email, details,
                               DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H:%%i:%%s') as date
                        FROM zoom_activity_logs
                        WHERE operator_email = %s
                           OR target_email IN %s
                           OR details LIKE %s
                        ORDER BY created_at DESC LIMIT 500
                    """
                    cursor.execute(query, (current_user, tuple(group_emails), f"%{assigned_group}%"))
                else:
                    query = """
                        SELECT operator_email, action_type, target_email, details,
                               DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H:%%i:%%s') as date
                        FROM zoom_activity_logs
                        WHERE operator_email = %s
                           OR details LIKE %s
                        ORDER BY created_at DESC LIMIT 500
                    """
                    cursor.execute(query, (current_user, f"%{assigned_group}%"))
                logs = cursor.fetchall()
        else:
            # Super Admin: Ver todos los registros
            with db.cursor() as cursor:
                cursor.execute(
                    "SELECT operator_email, action_type, target_email, details, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as date FROM zoom_activity_logs ORDER BY created_at DESC LIMIT 500"
                )
                logs = cursor.fetchall()
                
        return {"status": "success", "logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al listar logs: {str(e)}")

# ==============================================================================
#                      MÓDULO DE INTELIGENCIA ARTIFICIAL LOCAL
# ==============================================================================

class AIChatRequest(BaseModel):
    message: str

class AIConfirmRequest(BaseModel):
    action_id: str
    confirmed: bool

class AIMemoryRequest(BaseModel):
    key: str
    value: str
    memory_type: Optional[str] = "preference"

@app.get("/api/ai/health")
async def get_ai_health(current_user: str = Depends(verify_session)):
    """
    Verifica el estado del motor de IA local (Ollama) y el modelo seleccionado.
    """
    from ai_service.providers.ollama_provider import OllamaProvider
    provider = OllamaProvider()
    health = await provider.check_health()
    return {"status": "success", "health": health}

@app.post("/api/ai/chat")
async def ai_chat(
    req: AIChatRequest,
    current_user: str = Depends(verify_session),
    db=Depends(get_db_conn)
):
    """
    Endpoint principal para interactuar con el Agente de IA Local.
    Valida la sesión, determina el rol y scoping del usuario, y orquesta la consulta.
    """
    user_record = get_user_by_email(current_user, db)
    assigned_group = user_record.get("assigned_group") if user_record else None
    
    is_jtovar = "jtovar" in current_user.lower()
    is_super_admin = (user_record and user_record.get("role") == "admin") or is_jtovar or ("admin" in current_user.lower())

    from ai_service.orchestrator import agent_orchestrator
    result = await agent_orchestrator.process_user_message(
        user_email=current_user,
        is_super_admin=is_super_admin,
        assigned_group=assigned_group,
        message=req.message.strip()
    )
    return result

@app.post("/api/ai/confirm")
async def ai_confirm_action(
    req: AIConfirmRequest,
    current_user: str = Depends(verify_session)
):
    """
    Confirma o rechaza la ejecución de una acción crítica (Human-In-The-Loop).
    """
    from ai_service.orchestrator import agent_orchestrator
    result = await agent_orchestrator.execute_confirmed_action(
        action_id=req.action_id,
        user_email=current_user,
        confirmed=req.confirmed
    )
    return result

@app.get("/api/ai/history")
async def get_ai_chat_history(
    current_user: str = Depends(verify_session)
):
    """
    Retorna el historial de conversación aislado del usuario actual.
    """
    from ai_service.memory.store import memory_store
    history = memory_store.get_chat_history(current_user, limit=40)
    return {"status": "success", "history": history}

@app.delete("/api/ai/history")
async def clear_ai_chat_history(
    current_user: str = Depends(verify_session)
):
    """
    Elimina el contexto del chat del usuario actual.
    """
    from ai_service.memory.store import memory_store
    memory_store.clear_chat_history(current_user)
    return {"status": "success", "message": "Historial limpiado correctamente."}

@app.get("/api/ai/memories")
async def get_ai_memories(
    current_user: str = Depends(verify_session)
):
    """
    Obtiene las preferencias guardadas del usuario actual.
    """
    from ai_service.memory.store import memory_store
    memories = memory_store.get_user_memories(current_user)
    return {"status": "success", "memories": memories}

@app.post("/api/ai/memories")
async def save_ai_memory(
    req: AIMemoryRequest,
    current_user: str = Depends(verify_session)
):
    """
    Guarda o actualiza una preferencia o memoria aislada para el usuario actual.
    """
    from ai_service.memory.store import memory_store
    ok = memory_store.save_memory(
        user_email=current_user,
        memory_key=req.key,
        memory_value=req.value,
        memory_type=req.memory_type or "preference"
    )
    if ok:
        return {"status": "success", "message": "Preferencia guardada."}
    raise HTTPException(status_code=500, detail="Error al guardar preferencia.")

