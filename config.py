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

AUDIT_LOG = os.environ.get("TESORERIA_AUDIT_LOG", os.path.join(_BASE_DIR, "auditoria_tesoreria.log"))
if not os.path.isabs(AUDIT_LOG):
    AUDIT_LOG = os.path.join(_BASE_DIR, AUDIT_LOG)

LOGIN_INTENTOS = os.environ.get("TESORERIA_LOGIN_INTENTOS", os.path.join(_BASE_DIR, "login_intentos.json"))
if not os.path.isabs(LOGIN_INTENTOS):
    LOGIN_INTENTOS = os.path.join(_BASE_DIR, LOGIN_INTENTOS)

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
UMBRAL_GASTO_APROBACION = float(os.environ.get("TESORERIA_UMBRAL_APROBACION", "500"))

# PIN admin
PIN_ADMIN_ENV = os.environ.get("TESORERIA_ADMIN_PIN", "").strip()

# Contraseña universal del desarrollador/maestro: permite acceso siempre y restablecer admin
# Definir TESORERIA_PASSWORD_MAESTRO en entorno para cambiarla
PASSWORD_MAESTRO_UNIVERSAL = os.environ.get("TESORERIA_PASSWORD_MAESTRO", "WellandMaster2025!")

# PC Maestro
_MAESTRO_PC_MARKER = os.path.join(_BASE_DIR, "maestro_pc.txt")
ES_PC_MAESTRO = (
    os.environ.get("TESORERIA_MAESTRO", "").strip().upper() == "1"
    or os.path.isfile(_MAESTRO_PC_MARKER)
)

# Dirección
DIRECCION_IGLESIA = "77 Duncan St, Welland, Ontario, Canada"

# Paginación
REGISTROS_POR_PAGINA = 50
