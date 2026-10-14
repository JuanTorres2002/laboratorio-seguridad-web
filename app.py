"""Aplicación didáctica local para demostrar SQL injection y XSS."""
from __future__ import annotations

import html
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs

from http.server import BaseHTTPRequestHandler, HTTPServer
from html import escape

DB_PATH = Path(__file__).with_name("lab.db")

PRODUCTS = [
    (1, "Teclado mecánico", "Periféricos"),
    (2, "Ratón inalámbrico", "Periféricos"),
    (3, "Monitor 24 pulgadas", "Pantallas"),
    (4, "Cable de red", "Redes"),
]


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS products "
            "(id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL)"
        )
        count = conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]
        if count == 0:
            conn.executemany(
                "INSERT INTO products (id, name, category) VALUES (?, ?, ?)",
                PRODUCTS,
            )


def search_products(query: str, vulnerable: bool = False) -> tuple[list[tuple], str]:
    """Run the selected search mode and return rows plus a safe query description."""
    with sqlite3.connect(DB_PATH) as conn:
        if vulnerable:
            # Intentionally unsafe, restricted to this local teaching lab.
            sql = (
                "SELECT id, name, category FROM products "
                f"WHERE name LIKE '%{query}%'"
            )
            rows = conn.execute(sql).fetchall()
            return rows, sql
        sql = "SELECT id, name, category FROM products WHERE name LIKE ?"
        rows = conn.execute(sql, (f"%{query}%",)).fetchall()
        return rows, "SELECT id, name, category FROM products WHERE name LIKE ?"


def page(title: str, content: str) -> bytes:
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
<style>
body{{font-family:system-ui,Arial,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#202124}}
header{{border-bottom:1px solid #ddd;margin-bottom:1.5rem}} .notice{{background:#fff3cd;padding:1rem;border-radius:8px}}
.card{{border:1px solid #ddd;border-radius:10px;padding:1rem;margin:1rem 0}}
label{{display:block;margin:.6rem 0 .2rem}} input,select,button{{padding:.6rem;font:inherit}} table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:.5rem;text-align:left}} code,pre{{background:#f4f4f4;padding:.2rem .4rem}} .mode{{font-weight:bold}}
</style></head><body>
<header><h1>Laboratorio de seguridad web</h1><p>SQL injection · XSS · Vulnerable frente a corregido</p></header>
<div class="notice"><strong>Solo para aprendizaje:</strong> ejecutándose en localhost. No expongas esta aplicación a Internet ni la uses contra sistemas ajenos.</div>
{content}
</body></html>""".encode("utf-8")


class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.startswith("/favicon.ico"):
            self.send_response(204)
            self.end_headers()
            return
        content = """
<div class="card">
<h2>1. Búsqueda de productos — SQL injection</h2>
<form method="POST" action="/search">
<label for="query">Texto de búsqueda</label><input id="query" name="query" value="teclado">
<label for="sqlmode">Modo</label><select id="sqlmode" name="mode">
<option value="safe">Corregido (consulta parametrizada)</option>
<option value="vulnerable">Vulnerable (solo laboratorio)</option></select>
<button type="submit">Buscar</button></form>
</div>
<div class="card">
<h2>2. Saludo — XSS reflejado</h2>
<form method="POST" action="/greet">
<label for="name">Texto a mostrar</label><input id="name" name="name" value="Hola">
<label for="xssmode">Modo</label><select id="xssmode" name="mode">
<option value="safe">Corregido (escape HTML)</option>
<option value="vulnerable">Vulnerable (solo laboratorio)</option></select>
<button type="submit">Mostrar saludo</button></form>
</div>
<div class="card"><h2>Objetivo</h2><p>Compara cómo se comporta la aplicación cuando trata la entrada como código y cuando la trata como datos. Consulta el README para los ejercicios y las mitigaciones.</p></div>
"""
        self.respond(page("Laboratorio de seguridad web", content))

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 10000:
            self.send_error(413, "Solicitud demasiado grande")
            return
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse_qs(body, keep_blank_values=True)
        mode = form.get("mode", ["safe"])[0]
        vulnerable = mode == "vulnerable"

        if self.path == "/search":
            query = form.get("query", [""])[0][:200]
            try:
                rows, sql = search_products(query, vulnerable=vulnerable)
                table_rows = "".join(
                    f"<tr><td>{int(pid)}</td><td>{escape(name)}</td><td>{escape(category)}</td></tr>"
                    for pid, name, category in rows
                ) or '<tr><td colspan="3">No se encontraron productos.</td></tr>'
                # Escape query text and SQL display so the page itself does not introduce XSS.
                content = f"""
<h2>Resultado de búsqueda</h2>
<p>Modo: <span class="mode">{'VULNERABLE (laboratorio)' if vulnerable else 'CORREGIDO'}</span></p>
<p>Entrada recibida: <code>{escape(query)}</code></p>
<table><thead><tr><th>ID</th><th>Producto</th><th>Categoría</th></tr></thead><tbody>{table_rows}</tbody></table>
<p>Consulta ejecutada/plantilla: <code>{escape(sql)}</code></p>
<p><a href="/">Volver al laboratorio</a></p>
"""
            except sqlite3.Error:
                content = "<h2>Error SQL</h2><p>La entrada provocó un error en el modo vulnerable. Repite el ejercicio en el modo corregido.</p><p><a href='/'>Volver</a></p>"
            self.respond(page("Resultado SQL injection", content))
            return

        if self.path == "/greet":
            name = form.get("name", [""])[0][:300]
            shown = name if vulnerable else escape(name)
            content = f"""
<h2>Resultado de saludo</h2>
<p>Modo: <span class="mode">{'VULNERABLE (laboratorio)' if vulnerable else 'CORREGIDO'}</span></p>
<div class="card"><p>{shown}</p></div>
<p>Entrada recibida (texto escapado para inspección): <code>{escape(name)}</code></p>
<p><a href="/">Volver al laboratorio</a></p>
"""
            self.respond(page("Resultado XSS", content))
            return

        self.send_error(404, "Ruta no encontrada")

    def respond(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        # Keep console output concise for the educational lab.
        print("%s - %s" % (self.address_string(), format % args))


if __name__ == "__main__":
    init_db()
    server = HTTPServer(("127.0.0.1", 5000), LabHandler)
    print("Laboratorio disponible en http://127.0.0.1:5000")
    print("Solo escucha en localhost. Pulsa Ctrl+C para detenerlo.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCerrando laboratorio...")
    finally:
        server.server_close()
        if DB_PATH.exists():
            DB_PATH.unlink()
