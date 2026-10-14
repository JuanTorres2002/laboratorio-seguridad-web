# Laboratorio de seguridad web

Laboratorio **local y educativo** para entender y practicar dos vulnerabilidades web frecuentes: SQL injection y Cross-Site Scripting (XSS). Incluye una aplicación deliberadamente vulnerable, ejemplos de explotación contra `localhost`, una versión corregida y una guía de mitigación.

> **Importante:** ejecuta este proyecto únicamente en tu propio equipo y en `127.0.0.1`. La aplicación vulnerable está diseñada para enseñar fallos de seguridad y no debe exponerse a Internet ni utilizarse contra sistemas de terceros.

## Requisitos

- Python 3.10 o superior
- Navegador web moderno
- No requiere paquetes externos

Comprueba Python:

```bash
python --version
```

## Iniciar el laboratorio

Desde esta carpeta:

```bash
python app.py
```

Abre `http://127.0.0.1:5000`. Detén el servidor con `Ctrl+C`.

La aplicación solo escucha en la interfaz local (`127.0.0.1`) para reducir el riesgo de exposición a la red.

## Práctica 1: SQL injection

1. En la página principal, abre el apartado de búsqueda de productos.
2. Prueba una búsqueda normal, por ejemplo `teclado`.
3. En el modo vulnerable, prueba una entrada como:

```text
' OR '1'='1' --
```

4. Observa cómo la entrada altera la consulta SQL construida por concatenación.
5. Cambia al modo corregido y repite la prueba. La consulta parametrizada trata la entrada como un valor, no como parte del código SQL.

## Práctica 2: XSS reflejado

1. Abre el formulario de saludo.
2. Escribe un texto normal y envíalo.
3. En el modo vulnerable, prueba este payload inocuo que muestra una alerta en el navegador:

```html
<script>alert('XSS de laboratorio')</script>
```

4. Observa que el navegador interpreta la entrada como HTML/JavaScript.
5. Activa el modo corregido y repite la prueba: la entrada se muestra como texto y no se ejecuta.

## Modo corregido

Usa el selector de la aplicación para comparar la versión vulnerable con la versión mitigada:
- SQL injection: consultas parametrizadas con `?`.
- XSS: escape de contenido mediante `html.escape`.
- El laboratorio no usa información real ni credenciales.

## Pruebas automatizadas

En otra terminal, desde esta carpeta:

```bash
python -m unittest discover -s tests -v
```

## Qué demuestra

- Comprensión básica de SQL injection y XSS.
- Capacidad para reproducir vulnerabilidades en un entorno aislado.
- Aplicación de mitigaciones y comparación de resultados.
- Pruebas automatizadas y documentación técnica.

## Limitaciones

Este proyecto es una demostración didáctica, no un escáner de seguridad ni una aplicación lista para producción. No incorpora un sistema completo de autenticación, protección CSRF, control de sesiones ni despliegue endurecido. No lo despliegues en un servidor público.

## Mejoras futuras

- Añadir tests de integración para las rutas web.
- Incluir una guía OWASP Top 10 con referencias.
- Añadir una matriz de riesgo, evidencias y medidas correctoras.
- Implementar cabeceras de seguridad y protección CSRF para una versión endurecida.
