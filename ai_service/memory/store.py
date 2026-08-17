import pymysql
from typing import Dict, Any, List, Optional
from main import DB_HOST, DB_USER, DB_PASS, DB_NAME

class MemoryStore:
    """
    Administra y aísla las memorias, preferencias y reglas personalizadas de cada usuario en db_sigav.
    """
    
    def __init__(self):
        self._ensure_tables()

    def _ensure_tables(self):
        try:
            conn = pymysql.connect(
                host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor
            )
            with conn.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS user_ai_memories (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        user_email VARCHAR(255) NOT NULL,
                        memory_type VARCHAR(50) NOT NULL,
                        memory_key VARCHAR(100) NOT NULL,
                        memory_value TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        UNIQUE KEY uq_user_memory (user_email, memory_key)
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ai_conversations (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        conversation_id VARCHAR(100) NOT NULL,
                        user_email VARCHAR(255) NOT NULL,
                        role VARCHAR(20) NOT NULL,
                        content TEXT NOT NULL,
                        metadata JSON NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
            conn.close()
        except Exception as e:
            print("Error al inicializar tablas de memoria IA:", str(e))

    def save_memory(self, user_email: str, memory_key: str, memory_value: str, memory_type: str = "preference") -> bool:
        try:
            conn = pymysql.connect(
                host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor
            )
            with conn.cursor() as cursor:
                sql = """
                    INSERT INTO user_ai_memories (user_email, memory_type, memory_key, memory_value)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE memory_value = VALUES(memory_value), memory_type = VALUES(memory_type)
                """
                cursor.execute(sql, (user_email.strip().lower(), memory_type, memory_key.strip(), memory_value.strip()))
                conn.commit()
            conn.close()
            return True
        except Exception as e:
            print("Error al guardar memoria:", str(e))
            return False

    def get_user_memories(self, user_email: str) -> List[Dict[str, Any]]:
        try:
            conn = pymysql.connect(
                host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor
            )
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT memory_key, memory_value, memory_type, updated_at FROM user_ai_memories WHERE user_email = %s",
                    (user_email.strip().lower(),)
                )
                rows = cursor.fetchall()
            conn.close()
            return rows
        except Exception:
            return []

    def get_formatted_memories(self, user_email: str) -> str:
        memories = self.get_user_memories(user_email)
        if not memories:
            return "Ninguna preferencia guardada."
        lines = [f"- {m['memory_key']}: {m['memory_value']}" for m in memories]
        return "\n".join(lines)

    def save_chat_message(self, conversation_id: str, user_email: str, role: str, content: str, metadata: Optional[Dict[str, Any]] = None):
        import json
        try:
            conn = pymysql.connect(
                host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor
            )
            with conn.cursor() as cursor:
                meta_json = json.dumps(metadata) if metadata else None
                sql = """
                    INSERT INTO ai_conversations (conversation_id, user_email, role, content, metadata)
                    VALUES (%s, %s, %s, %s, %s)
                """
                cursor.execute(sql, (conversation_id, user_email.strip().lower(), role, content, meta_json))
                conn.commit()
            conn.close()
        except Exception as e:
            print("Error al guardar mensaje en historial:", str(e))

    def get_chat_history(self, user_email: str, limit: int = 30) -> List[Dict[str, Any]]:
        import json
        try:
            conn = pymysql.connect(
                host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor
            )
            with conn.cursor() as cursor:
                sql = """
                    SELECT role, content, metadata, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at
                    FROM ai_conversations
                    WHERE user_email = %s
                    ORDER BY id DESC LIMIT %s
                """
                cursor.execute(sql, (user_email.strip().lower(), limit))
                rows = cursor.fetchall()
            conn.close()
            rows.reverse()
            for r in rows:
                if r.get("metadata") and isinstance(r["metadata"], str):
                    try:
                        r["metadata"] = json.loads(r["metadata"])
                    except Exception:
                        pass
            return rows
        except Exception:
            return []

    def clear_chat_history(self, user_email: str):
        try:
            conn = pymysql.connect(
                host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor
            )
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM ai_conversations WHERE user_email = %s", (user_email.strip().lower(),))
                conn.commit()
            conn.close()
        except Exception:
            pass

memory_store = MemoryStore()
