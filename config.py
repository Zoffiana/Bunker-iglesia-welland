# -*- coding: utf-8 -*-
"""
Configuración centralizada - Iglesia Pentecostal de Welland - Sistema de Tesorería
Variables de entorno y constantes.
"""
import os

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Versión
VERSION_APP = "2.2.0"

# Rutas de archivos (configurables por entorno)
DB_ARCHIVO = os.environ.get("TESORERIA_DB_CSV", os.path.join(_BASE_DIR, "DB_TESORERIA_IGLESIA.csv"))
if not os.path.isabs(DB_ARCHIVO):
    DB_ARCHIVO = os.path.join(_BASE_DIR, DB_ARCHIVO)

DB_PERMISOS = os.environ.get("TESORERIA_DB_PERMISOS", os.path.join(_BASE_DIR, "DB_PERMISOS.json"))
if not os.path.isabs(DB_PERMISOS):
    DB_PERMISOS = os.path.join(_BASE_DIR, DB_PERMISOS)

DB_FACTURAS = os.environ.get("TESORERIA_DB_FACTURAS", os.path.join(_BASE_DIR, "DB_FACTURAS.json"))
if not os.path.isabs(DB_FACTURAS):
    DB_FACTURAS = os.path.join(_BASE_DIR, DB_FACTURAS)

DB_ARQUEO_META = os.environ.get("TESORERIA_DB_ARQUEO_META", os.path.join(_BASE_DIR, "DB_ARQUEO_META.json"))
if not os.path.isabs(DB_ARQUEO_META):
    DB_ARQUEO_META = os.path.join(_BASE_DIR, DB_ARQUEO_META)

DB_SUMINISTROS = os.environ.get("TESORERIA_DB_SUMINISTROS", os.path.join(_BASE_DIR, "DB_SUMINISTROS.json"))
if not os.path.isabs(DB_SUMINISTROS):
    DB_SUMINISTROS = os.path.join(_BASE_DIR, DB_SUMINISTROS)

AUDIT_LOG = os.environ.get("TESORERIA_AUDIT_LOG", os.path.join(_BASE_DIR, "auditoria_tesoreria.log"))
if not os.path.isabs(AUDIT_LOG):
    AUDIT_LOG = os.path.join(_BASE_DIR, AUDIT_LOG)

LOGIN_INTENTOS = os.environ.get("TESORERIA_LOGIN_INTENTOS", os.path.join(_BASE_DIR, "login_intentos.json"))
if not os.path.isabs(LOGIN_INTENTOS):
    LOGIN_INTENTOS = os.path.join(_BASE_DIR, LOGIN_INTENTOS)

# Modo mantenimiento (admin pausa el sistema; usuarios ven aviso y su trabajo guardado se preserva)
MANTENIMIENTO_ACTIVO = os.path.join(_BASE_DIR, "mantenimiento_activo.json")

# Presupuesto y metas (por tipo de gasto y meta de ingresos)
DB_PRESUPUESTO = os.path.join(_BASE_DIR, "DB_PRESUPUESTO.json")

# Eventos / Inversiones (ventas, gastos, margen, rentabilidad, mano de obra, informe)
DB_EVENTOS = os.path.join(_BASE_DIR, "DB_EVENTOS.json")

# Configuración de interfaz (logos, textos, colores, estilos, botones ocultos) — solo editable con clave maestra
DB_UI_CONFIG = os.path.join(_BASE_DIR, "DB_UI_CONFIG.json")

# Recordar sesión (persistencia para móvil/cerrar pestaña): tokens en archivo
DB_REMEMBER = os.path.join(_BASE_DIR, "DB_REMEMBER.json")
REMEMBER_SECRET = os.environ.get("TESORERIA_REMEMBER_SECRET", "WellandRemember2025").strip() or "WellandRemember2025"
REMEMBER_DAYS = 30

# Seguridad
MAX_INTENTOS_LOGIN = 5
MINUTOS_BLOQUEO_LOGIN = 10
MIN_LONGITUD_CONTRASENA = 8
REQUIERE_MAYUSCULA = True
REQUIERE_NUMERO = True
REQUIERE_SIMBOLO = False  # Opcional para no ser muy restrictivo

# Imágenes
IMAGEN_COMPRIMIR_MAX_ANCHO = 1200
IMAGEN_COMPRIMIR_CALIDAD = 85

# Tiempos
MINUTOS_BORRADO = 30
MINUTOS_INACTIVIDAD = 30

# Respaldos
CARPETA_HISTORIAL = os.environ.get("TESORERIA_CARPETA_HISTORIAL", os.path.join(_BASE_DIR, "respaldo_historial"))
if not os.path.isabs(CARPETA_HISTORIAL):
    CARPETA_HISTORIAL = os.path.join(_BASE_DIR, CARPETA_HISTORIAL)

CARPETA_RESETS = os.environ.get("TESORERIA_CARPETA_RESETS", os.path.join(_BASE_DIR, "resets_reinicio"))
if not os.path.isabs(CARPETA_RESETS):
    CARPETA_RESETS = os.path.join(_BASE_DIR, CARPETA_RESETS)

MAX_RESPALDOS = 80

# Confirmaciones
CONFIRMACION_REINICIO = "BORRAR"
CONFIRMACION_LIMPIAR_TODO = "BORRAR TODO"

# Gastos
try:
    UMBRAL_GASTO_APROBACION = float(os.environ.get("TESORERIA_UMBRAL_APROBACION", "500"))
except (TypeError, ValueError):
    UMBRAL_GASTO_APROBACION = 500.0

# PIN admin
PIN_ADMIN_ENV = os.environ.get("TESORERIA_ADMIN_PIN", "").strip()

# Contraseña universal del desarrollador/maestro: permite acceso siempre y restablecer admin
# Definir TESORERIA_PASSWORD_MAESTRO en entorno para sobreescribirla
PASSWORD_MAESTRO_UNIVERSAL = os.environ.get("TESORERIA_PASSWORD_MAESTRO", "Welland#Maestro24")

# PC Maestro
_MAESTRO_PC_MARKER = os.path.join(_BASE_DIR, "maestro_pc.txt")
try:
    ES_PC_MAESTRO = (
        os.environ.get("TESORERIA_MAESTRO", "").strip().upper() == "1"
        or os.path.isfile(_MAESTRO_PC_MARKER)
    )
except Exception:
    ES_PC_MAESTRO = False

# Dirección
DIRECCION_IGLESIA = "77 Duncan St, Welland, Ontario, Canada"

# Paginación
REGISTROS_POR_PAGINA = 50
