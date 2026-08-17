import os
import re
from typing import List, Dict, Any

class RAGEngine:
    """
    Motor RAG (Retrieval-Augmented Generation) ligero para indexar y buscar semánticamente
    en la documentación interna del sistema, normativas de la USMP y guías de Zoom.
    """
    
    def __init__(self):
        self.documents: List[Dict[str, Any]] = []
        self._load_built_in_knowledge()

    def _load_built_in_knowledge(self):
        """
        Carga el conocimiento base sobre el sistema de licenciamiento y políticas de la USMP.
        """
        base_docs = [
            {
                "id": "doc_licencias_usmp",
                "title": "Política de Licencias Zoom USMP",
                "content": (
                    "La Universidad de San Martín de Porres (USMP) cuenta con un total de 2001 licencias de pago 'Licensed' (Zoom Meetings). "
                    "Las licencias de tipo 'Basic' son gratuitas con límite de 40 minutos por reunión. "
                    "Las invitaciones pendientes a nuevos usuarios reservan una licencia de pago 'Licensed' hasta que el usuario activa su cuenta. "
                    "Si las licencias libres llegan a 0, Zoom bloquea nuevas asignaciones o invitaciones hasta que se liberen cupos cancelando invitaciones pendientes obsoletas o degradando usuarios a Basic."
                )
            },
            {
                "id": "doc_roles_y_facultades",
                "title": "Estructura de Roles y Facultades",
                "content": (
                    "El sistema asigna grupos de Zoom a cada facultad (ej. UVA, FCCTP, FMH, FCCEF, CIAR, FILIAL SUR, FILIAL NORTE). "
                    "Los administradores de facultad (como uva@usmp.pe o fcctp@usmp.pe) solo tienen visibilidad y permisos sobre los usuarios y reuniones de su respectiva facultad. "
                    "Únicamente los administradores globales (admin@usmpvirtual.edu.pe y jtovar@usmpvirtual.edu.pe) pueden gestionar todas las facultades e ingresar a la pestaña de Operaciones (Logs)."
                )
            },
            {
                "id": "doc_procedimiento_quitar_licencias",
                "title": "Procedimiento de Desasignación Masiva de Licencias",
                "content": (
                    "Para quitar licencias masivamente a un grupo en el sistema, se utiliza la función 'Quitar Licencias' del panel de facultades. "
                    "Esta acción convierte a los usuarios de tipo Licensed (2) a tipo Basic (1) y libera los cupos de licenciamiento en Zoom para que puedan ser reasignados a otros docentes."
                )
            },
            {
                "id": "doc_faq_zoom_error_403",
                "title": "Preguntas Frecuentes: Error 403 o Sin Permisos",
                "content": (
                    "Si Zoom retorna error 403 Forbidden al consultar planes de uso, indica que falta el scope 'billing:read:plan_usage:admin' "
                    "o 'billing:read:admin' en la aplicación Server-to-Server OAuth en Zoom Marketplace."
                )
            }
        ]
        self.documents.extend(base_docs)

    def add_document(self, doc_id: str, title: str, content: str):
        self.documents.append({
            "id": doc_id,
            "title": title,
            "content": content
        })

    def search(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        if not query or not self.documents:
            return []
            
        words = [w.lower() for w in re.findall(r'\w+', query) if len(w) > 3]
        if not words:
            return []

        results = []
        for doc in self.documents:
            text_lower = (doc["title"] + " " + doc["content"]).lower()
            score = sum(1 for w in words if w in text_lower)
            if score > 0:
                results.append((score, doc))

        results.sort(key=lambda x: x[0], reverse=True)
        return [doc for score, doc in results[:top_k]]

    def get_context_str(self, query: str) -> str:
        matched = self.search(query)
        if not matched:
            return "No se encontró documentación interna específica para esta consulta."
            
        snippets = []
        for doc in matched:
            snippets.append(f"--- Documento: {doc['title']} ---\n{doc['content']}")
            
        return "\n\n".join(snippets)

rag_engine = RAGEngine()
