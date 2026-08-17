import json
import pymysql
from typing import Dict, Any, Optional
from main import DB_HOST, DB_USER, DB_PASS, DB_NAME

class AIAuditLogger:
    """
    Registra de forma inmutable todas las interacciones, herramientas invocadas,
    parámetros y resultados ejecutados por el Agente de IA en la tabla ai_audit_logs.
    """
    
    def __init__(self):
        self._ensure_table()

    def _ensure_table(self):
        try:
            conn = pymysql.connect(
                host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor
            )
            with conn.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ai_audit_logs (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        user_email VARCHAR(255) NOT NULL,
                        user_role VARCHAR(50) NOT NULL,
                        assigned_group VARCHAR(100) NULL,
                        action_prompt TEXT NOT NULL,
                        tool_name VARCHAR(100) NULL,
                        tool_parameters JSON NULL,
                        tool_result JSON NULL,
                        status VARCHAR(50) NOT NULL,
                        execution_time_ms INT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
            conn.close()
        except Exception as e:
            print("Error al verificar tabla ai_audit_logs:", str(e))

    def log_action(
        self,
        user_email: str,
        user_role: str,
        assigned_group: Optional[str],
        action_prompt: str,
        tool_name: Optional[str] = None,
        tool_parameters: Optional[Dict[str, Any]] = None,
        tool_result: Optional[Dict[str, Any]] = None,
        status: str = "SUCCESS",
        execution_time_ms: Optional[int] = None
    ):
        try:
            conn = pymysql.connect(
                host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor
            )
            with conn.cursor() as cursor:
                sql = """
                    INSERT INTO ai_audit_logs (
                        user_email, user_role, assigned_group, action_prompt,
                        tool_name, tool_parameters, tool_result, status, execution_time_ms
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                params = (
                    user_email.strip().lower(),
                    user_role,
                    assigned_group,
                    action_prompt,
                    tool_name,
                    json.dumps(tool_parameters) if tool_parameters else None,
                    json.dumps(tool_result) if tool_result else None,
                    status,
                    execution_time_ms
                )
                cursor.execute(sql, params)
                conn.commit()
            conn.close()
        except Exception as e:
            print("Error al registrar auditoría IA:", str(e))

ai_audit_logger = AIAuditLogger()
