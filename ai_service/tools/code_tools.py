import os
from typing import Dict, Any, Optional
from .registry import registry

WORKSPACE_ROOT = r"c:\Users\junio\Downloads\PROYECTO_ZOOM\PROYECTO_ZOOM"

@registry.register(
    name="search_code_files",
    description="Busca términos, funciones o patrones en los archivos del código fuente del proyecto.",
    parameters={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Término a buscar (ej. 'verify_admin', 'get_db_conn', 'ai_audit_logs')"}
        },
        "required": ["query"]
    },
    required_role="super_admin"
)
async def search_code_files(context: Dict[str, Any], query: str) -> Dict[str, Any]:
    if not context.get("is_super_admin", False):
        return {"status": "error", "message": "Acceso denegado: El análisis del código fuente está restringido a Super Administradores."}

    results = []
    q_lower = query.lower()
    
    target_files = ["main.py", "requirements.txt", "templates/index.html", "templates/login.html"]
    for rel_path in target_files:
        full_path = os.path.join(WORKSPACE_ROOT, rel_path)
        if os.path.exists(full_path):
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    for idx, line in enumerate(lines, start=1):
                        if q_lower in line.lower():
                            results.append({
                                "file": rel_path,
                                "line": idx,
                                "content": line.strip()
                            })
            except Exception:
                pass

    return {
        "status": "success",
        "query": query,
        "total_matches": len(results),
        "matches": results[:30]
    }

@registry.register(
    name="view_source_code",
    description="Lee un fragmento específico de un archivo de código fuente del proyecto.",
    parameters={
        "type": "object",
        "properties": {
            "file_name": {"type": "string", "description": "Nombre del archivo (ej. 'main.py' o 'templates/index.html')"},
            "start_line": {"type": "integer", "description": "Línea inicial (default 1)"},
            "num_lines": {"type": "integer", "description": "Cantidad de líneas a leer (default 50)"}
        },
        "required": ["file_name"]
    },
    required_role="super_admin"
)
async def view_source_code(context: Dict[str, Any], file_name: str, start_line: int = 1, num_lines: int = 50) -> Dict[str, Any]:
    if not context.get("is_super_admin", False):
        return {"status": "error", "message": "Acceso denegado: El análisis del código fuente está restringido a Super Administradores."}

    clean_name = os.path.basename(file_name)
    full_path = os.path.join(WORKSPACE_ROOT, clean_name)
    
    if not os.path.exists(full_path):
        # Probar en subcarpetas permitidas
        full_path = os.path.join(WORKSPACE_ROOT, file_name)

    if not os.path.exists(full_path):
        return {"status": "error", "message": f"El archivo '{file_name}' no existe en el proyecto."}

    try:
        with open(full_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        total_lines = len(lines)
        sl = max(1, start_line)
        el = min(total_lines, sl + num_lines - 1)
        
        snippet = "".join([f"{i}: {lines[i-1]}" for i in range(sl, el + 1)])
        return {
            "status": "success",
            "file": file_name,
            "start_line": sl,
            "end_line": el,
            "total_lines": total_lines,
            "snippet": snippet
        }
    except Exception as e:
        return {"status": "error", "message": f"Error al leer el archivo: {str(e)}"}
