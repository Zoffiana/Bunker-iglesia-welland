# -*- coding: utf-8 -*-
"""
IGLESIA PENTECOSTAL DE WELLAND - SISTEMA DE TESORERÍA
Aplicación ultra-didáctica para adultos mayores.
"""

import streamlit as st
import pandas as pd
from datetime import datetime

try:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    _PLOTLY_DISPONIBLE = True
except ImportError:
    _PLOTLY_DISPONIBLE = False
import os
import json
import shutil
import re
import hashlib
import time
import logging
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from io import BytesIO

try:
    import bcrypt
    _BCRYPT_DISPONIBLE = True
except ImportError:
    _BCRYPT_DISPONIBLE = False

# Configuración centralizada
from config import (
    VERSION_APP, DB_ARCHIVO, DB_PERMISOS, DB_FACTURAS, DB_ARQUEO_META, DB_SUMINISTROS, AUDIT_LOG, LOGIN_INTENTOS,
    MAX_INTENTOS_LOGIN, MINUTOS_BLOQUEO_LOGIN, IMAGEN_COMPRIMIR_MAX_ANCHO, IMAGEN_COMPRIMIR_CALIDAD,
    MINUTOS_BORRADO, MINUTOS_INACTIVIDAD, CARPETA_HISTORIAL, CARPETA_RESETS, MAX_RESPALDOS,
    CONFIRMACION_REINICIO, CONFIRMACION_LIMPIAR_TODO, UMBRAL_GASTO_APROBACION, PIN_ADMIN_ENV,
    ES_PC_MAESTRO, DIRECCION_IGLESIA, PASSWORD_MAESTRO_UNIVERSAL,
    MIN_LONGITUD_CONTRASENA, REQUIERE_MAYUSCULA, REQUIERE_NUMERO, REQUIERE_SIMBOLO, REGISTROS_POR_PAGINA,
)

# ============== AUDITORÍA Y SEGURIDAD ==============
def audit_log(usuario, accion, detalle=""):
    """Registra en archivo de auditoría: quién, qué acción y cuándo. No se borra con reinicio."""
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\t{usuario}\t{accion}\t{detalle}\n")
    except Exception:
        pass
    try:
        logging.getLogger("tesoreria").info(f"AUDIT | {usuario} | {accion} | {detalle}")
    except Exception:
        pass

def _hash_pin(pin):
    """Hash simple del PIN para comparación (no usar para seguridad crítica sin salt)."""
    return hashlib.sha256((pin or "").strip().encode("utf-8")).hexdigest()

def _pin_admin_requerido():
    """True si debe pedirse PIN para acceder como admin (env o hash en DB)."""
    if PIN_ADMIN_ENV:
        return True
    data = {}
    try:
        if os.path.exists(DB_PERMISOS):
            with open(DB_PERMISOS, "r", encoding="utf-8") as f:
                data = json.load(f)
    except Exception:
        pass
    return bool(data.get("admin_pin_hash"))

def _verificar_pin_admin(pin):
    """True si el PIN es correcto para admin (env o hash en DB)."""
    if PIN_ADMIN_ENV and (pin or "").strip() == PIN_ADMIN_ENV:
        return True
    try:
        if not os.path.exists(DB_PERMISOS):
            return False
        with open(DB_PERMISOS, "r", encoding="utf-8") as f:
            data = json.load(f)
        h = data.get("admin_pin_hash")
        return bool(h and _hash_pin(pin) == h)
    except Exception:
        return False

def _hash_contrasena(contrasena):
    """Hash bcrypt de contraseña. Si bcrypt no está, usa SHA256 con salt."""
    pwd = (contrasena or "").strip().encode("utf-8")
    if _BCRYPT_DISPONIBLE:
        return bcrypt.hashpw(pwd, bcrypt.gensalt()).decode("utf-8")
    salt = os.urandom(16).hex()
    h = hashlib.sha256((salt + pwd.decode()).encode()).hexdigest()
    return f"sha256:{salt}:{h}"

def _validar_politica_contrasena(contrasena):
    """Valida que la contraseña cumpla la política. Retorna (True, None) o (False, mensaje)."""
    pwd = (contrasena or "").strip()
    if len(pwd) < MIN_LONGITUD_CONTRASENA:
        return False, f"Mínimo {MIN_LONGITUD_CONTRASENA} caracteres."
    if REQUIERE_MAYUSCULA and not re.search(r"[A-Z]", pwd):
        return False, "Debe incluir al menos una mayúscula."
    if REQUIERE_NUMERO and not re.search(r"\d", pwd):
        return False, "Debe incluir al menos un número."
    if REQUIERE_SIMBOLO and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", pwd):
        return False, "Debe incluir al menos un símbolo."
    return True, None

def _verificar_contrasena_hash(contrasena_ingresada, hash_guardado):
    """True si la contraseña coincide con el hash guardado."""
    pwd = (contrasena_ingresada or "").strip().encode("utf-8")
    if not hash_guardado:
        return False
    if _BCRYPT_DISPONIBLE and not hash_guardado.startswith("sha256:"):
        try:
            return bcrypt.checkpw(pwd, hash_guardado.encode("utf-8"))
        except Exception:
            return False
    if hash_guardado.startswith("sha256:"):
        parts = hash_guardado.split(":", 2)
        if len(parts) == 3:
            _, salt, h = parts
            return hashlib.sha256((salt + (contrasena_ingresada or "").strip()).encode()).hexdigest() == h
    return False

def _login_bloqueado():
    """True si hay demasiados intentos fallidos recientes."""
    if not os.path.exists(LOGIN_INTENTOS):
        return False
    try:
        with open(LOGIN_INTENTOS, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return False
    intentos = data.get("intentos", [])
    ahora = time.time()
    ventana = MINUTOS_BLOQUEO_LOGIN * 60
    recientes = [ts for ts in intentos if ahora - ts < ventana]
    if len(recientes) >= MAX_INTENTOS_LOGIN:
        return True
    return False

def _registrar_intento_fallido():
    """Registra un intento fallido de login."""
    data = {"intentos": []}
    if os.path.exists(LOGIN_INTENTOS):
        try:
            with open(LOGIN_INTENTOS, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            pass
    data.setdefault("intentos", [])
    data["intentos"].append(time.time())
    ventana = MINUTOS_BLOQUEO_LOGIN * 60
    ahora = time.time()
    data["intentos"] = [ts for ts in data["intentos"] if ahora - ts < ventana * 2]
    try:
        with open(LOGIN_INTENTOS, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def _verificar_login(usuario_id, contrasena):
    """Retorna ('ok', None|'primera_vez'|'maestro') si correcto, ('error', ...) si falla.
    - primera_vez: admin con admin/admin (sin contraseña en DB) -> debe cambiar antes de continuar
    - maestro: admin con contraseña universal -> acceso total, puede restablecer admin/admin"""
    if _login_bloqueado():
        return ("error", "bloqueado")
    data = cargar_permisos()
    usuarios = data.get("usuarios", {})
    if usuario_id not in usuarios:
        return ("error", "usuario_no_existe")
    info = usuarios[usuario_id]
    pwd_guardada = info.get("contrasena", "").strip()
    pwd_ingresada = (contrasena or "").strip()
    # Contraseña universal del maestro: acceso siempre a admin
    if usuario_id == "admin" and pwd_ingresada == PASSWORD_MAESTRO_UNIVERSAL:
        return ("ok", "maestro")
    if pwd_guardada:
        if pwd_guardada.startswith("$2") or pwd_guardada.startswith("sha256:"):
            if _verificar_contrasena_hash(pwd_ingresada, pwd_guardada):
                return ("ok", None)
        elif pwd_ingresada == pwd_guardada:
            return ("ok", None)
        _registrar_intento_fallido()
        return ("error", "contrasena_incorrecta")
    # admin/admin permitido solo si admin NO tiene contraseña guardada (primera vez)
    if usuario_id == "admin" and pwd_ingresada == "admin":
        return ("ok", "primera_vez")
    if pwd_ingresada == usuario_id:
        return ("ok", None)
    _registrar_intento_fallido()
    return ("error", "contrasena_incorrecta")

def _ultima_actividad_audit():
    """Devuelve la última línea del log de auditoría (usuario, acción, fecha) o None."""
    if not os.path.exists(AUDIT_LOG):
        return None
    try:
        with open(AUDIT_LOG, "r", encoding="utf-8") as f:
            lineas = f.readlines()
        for ln in reversed(lineas[-20:]):
            ln = ln.strip()
            if ln and "\t" in ln:
                parts = ln.split("\t", 3)
                if len(parts) >= 3:
                    return {"fecha": parts[0], "usuario": parts[1], "accion": parts[2]}
    except Exception:
        pass
    return None

def _render_pantalla_login():
    """Pantalla de login: logo centrado, título, subtítulo, idioma, usuario/contraseña, recordar sesión, mensajes claros."""
    lang = st.session_state.get("idioma", "ES")
    t = TEXTOS.get(lang, TEXTOS["ES"])
    st.set_page_config(
        page_title="Iglesia Pentecostal de Welland",
        page_icon="⛪",
        layout="centered",
        initial_sidebar_state="collapsed"
    )
    tema = st.session_state.get("tema_login", "oscuro")
    if tema == "claro":
        bg = "linear-gradient(180deg, #e8eef5 0%, #d1dce8 40%, #b8c9d9 100%)"
        txt = "#1a365d"
        txt2 = "rgba(26,54,93,0.85)"
        input_bg_login = "rgba(255,255,255,0.95)"
        input_color_login = "#1a365d"
        dashboard_bg_login = "rgba(0,0,0,0.06)"
        btn_bg_login = "rgba(26,54,93,0.35)"
        border_login = "rgba(26,54,93,0.5)"
    else:
        bg = "#000000"
        txt = "#FFFFFF"
        txt2 = "rgba(255,255,255,0.9)"
        input_bg_login = "rgba(30,40,55,0.6)"
        input_color_login = "#FFFFFF"
        dashboard_bg_login = "rgba(255,255,255,0.06)"
        btn_bg_login = "rgba(255,255,255,0.12)"
        border_login = "rgba(0,0,0,0.7)"
    st.markdown(f"""
    <style>
    [data-testid="stSidebar"] {{ display: none !important; }}
    .stApp > header {{ display: none !important; }}
    .stApp, [data-testid="stAppViewContainer"], .main, .block-container {{
        background: {bg} !important;
        padding: 2rem 1rem !important;
        max-width: 520px !important;
        margin: 0 auto !important;
    }}
    .login-titulo {{
        font-family: Calibri, 'Segoe UI', sans-serif;
        font-size: 1.6rem;
        font-weight: bold;
        color: {txt};
        margin: 1rem 0 0.4rem 0;
        text-align: center;
    }}
    .login-subtitulo {{
        font-family: Calibri, 'Segoe UI', sans-serif;
        font-size: 0.9rem;
        color: {txt2};
        margin-bottom: 1rem;
        line-height: 1.4;
        text-align: center;
    }}
    .login-dashboard {{
        font-size: 0.8rem;
        color: {txt2};
        margin-bottom: 1rem;
        padding: 0.5rem;
        border-radius: 8px;
        background: {dashboard_bg_login};
    }}
    .block-container input[type="text"], .block-container input[type="password"],
    .block-container [data-testid="stTextInput"] input {{
        background-color: {input_bg_login} !important;
        color: {input_color_login} !important;
        border: 1px solid {border_login} !important;
        outline: none !important;
    }}
    .block-container [data-testid="stTextInput"] > div {{
        border: 1px solid {border_login} !important;
        box-shadow: none !important;
    }}
    .block-container label, .block-container p, .block-container div[data-testid="stCheckbox"] label,
    .block-container div[data-testid="stRadio"] label {{
        color: {txt} !important;
    }}
    .block-container div[data-testid="stCheckbox"] > label,
    .block-container div[data-testid="stCheckbox"] input {{
        border: 1px solid {border_login} !important;
    }}
    .stAlert, .stException, [data-testid="stAlert"], div[data-testid="stExpander"] {{
        color: {txt} !important;
    }}
    .block-container .stButton > button, .block-container [data-testid="stFormSubmitButton"] > button {{
        color: {txt} !important;
        background: linear-gradient(180deg, rgba(55,65,80,0.95) 0%, rgba(35,42,52,0.95) 50%, rgba(25,30,40,0.95) 100%) !important;
        border: 1px solid {border_login} !important;
        outline: none !important;
        box-shadow: 0 0 14px rgba(91,155,213,0.25),
                    4px 6px 16px rgba(0,0,0,0.45),
                    inset 0 1px 0 rgba(255,255,255,0.1) !important;
    }}
    div[data-testid="stVerticalBlock"] > div {{ background: transparent !important; }}
    @media (max-width: 768px) {{
        .main .block-container {{ padding: 1rem !important; max-width: 100% !important; }}
        .login-titulo {{ font-size: 1.4rem; }}
        .login-subtitulo {{ font-size: 0.85rem; }}
    }}
    </style>
    """, unsafe_allow_html=True)

    col_idioma, col_tema, _ = st.columns([1, 1, 2])
    with col_idioma:
        lang_sel = st.radio("Idioma", ["ES", "EN"], format_func=lambda x: "ESPAÑOL" if x == "ES" else "ENGLISH",
                            key="login_idioma", horizontal=True, label_visibility="collapsed",
                            index=0 if lang == "ES" else 1)
        if lang_sel != lang:
            st.session_state["idioma"] = lang_sel
            st.rerun()
    with col_tema:
        tema_sel = st.radio("Tema", ["oscuro", "claro"], format_func=lambda x: "🌙" if x == "oscuro" else "☀️",
                            key="login_tema", horizontal=True, label_visibility="collapsed")
        if tema_sel != st.session_state.get("tema_login", "oscuro"):
            st.session_state["tema_login"] = tema_sel
            st.rerun()

    if _login_bloqueado():
        st.error(t["login_bloqueado"].format(min=MINUTOS_BLOQUEO_LOGIN))
        return

    if st.session_state.get("recordar_sesion") and "login_usuario_guardado" in st.session_state:
        if "login_usuario_input" not in st.session_state:
            st.session_state["login_usuario_input"] = st.session_state.get("login_usuario_guardado", "")
        if "login_contrasena_input" not in st.session_state:
            st.session_state["login_contrasena_input"] = st.session_state.get("login_contrasena_guardada", "")

    ultima = _ultima_actividad_audit()
    if ultima:
        st.markdown(f"<p class='login-dashboard'>📋 {t['login_ultima_actividad']}: {ultima['fecha']} — {ultima['usuario']} ({ultima['accion']})</p>",
                    unsafe_allow_html=True)

    _, col_centro, _ = st.columns([1, 1, 1])
    with col_centro:
        if os.path.exists(LOGO_LOGIN):
            st.image(LOGO_LOGIN, use_container_width=True)
        else:
            st.markdown("""
            <div style="width:160px;height:160px;margin:0 auto;border-radius:50%;background:linear-gradient(135deg,#1a365d,#2d3748);
            display:flex;align-items:center;justify-content:center;box-shadow:0 0 30px rgba(91,155,213,0.3);">
            <span style="font-size:3.5rem;">⛪</span>
            </div>
            """, unsafe_allow_html=True)

    st.markdown(f"<p class='login-titulo'>{t['login_titulo']}</p>", unsafe_allow_html=True)
    st.markdown(f"<p class='login-subtitulo'>{t['login_subtitulo']}</p>", unsafe_allow_html=True)

    with st.form("form_login", clear_on_submit=False):
        usuario = st.text_input(t["login_usuario"], key="login_usuario_input", placeholder=t.get("login_usuario_placeholder", "admin"),
                                label_visibility="visible")
        contrasena = st.text_input(t["login_contrasena"], type="password", key="login_contrasena_input",
                                    placeholder="••••••••", label_visibility="visible")
        recordar = st.checkbox(t["login_recordar"], key="login_recordar", value=st.session_state.get("recordar_sesion", False))
        submitted = st.form_submit_button(t["login_btn"])
        if submitted:
            if usuario and contrasena:
                uid = usuario.strip().lower()
                resultado, extra = _verificar_login(uid, contrasena)
                if resultado == "ok":
                    st.session_state["logueado"] = True
                    st.session_state["usuario_actual"] = uid
                    if uid == "admin":
                        st.session_state["admin_autorizado"] = True
                    st.session_state["recordar_sesion"] = recordar
                    if recordar:
                        st.session_state["login_usuario_guardado"] = usuario.strip()
                        st.session_state["login_contrasena_guardada"] = contrasena
                    else:
                        for k in ("login_usuario_guardado", "login_contrasena_guardada"):
                            if k in st.session_state:
                                del st.session_state[k]
                    if extra == "primera_vez":
                        st.session_state["debe_cambiar_credenciales"] = True
                    elif extra == "maestro":
                        st.session_state["es_acceso_maestro"] = True
                    audit_log(uid, "login", extra or "")
                    st.rerun()
                else:
                    if extra == "bloqueado":
                        st.error(t["login_bloqueado"].format(min=MINUTOS_BLOQUEO_LOGIN))
                    elif extra == "usuario_no_existe":
                        st.error(t["login_error_usuario"])
                    else:
                        st.error(t["login_error_contrasena"])
            else:
                st.error(t["login_error"])

    with st.expander(t["login_recuperar"], expanded=False):
        st.caption(t["login_recuperar_ayuda"])

def _render_pantalla_cambiar_credenciales():
    """Pantalla obligatoria tras primer login con admin/admin: cambiar contraseña antes de continuar."""
    lang = st.session_state.get("idioma", "ES")
    t = TEXTOS.get(lang, TEXTOS["ES"])
    st.set_page_config(page_title="Cambiar credenciales", page_icon="🔐", layout="centered", initial_sidebar_state="collapsed")
    st.markdown(f"## 🔐 {t['cambiar_credenciales_titulo']}")
    st.info(t["cambiar_credenciales_info"])
    with st.form("form_cambiar_credenciales"):
        nueva_pwd = st.text_input(t["cambiar_credenciales_nueva"], type="password", key="nueva_pwd_admin")
        confirmar_pwd = st.text_input(t["cambiar_credenciales_confirmar"], type="password", key="confirmar_pwd_admin")
        enviado = st.form_submit_button(t["cambiar_credenciales_guardar"])
        if enviado:
            if not nueva_pwd or not confirmar_pwd:
                st.error(t["cambiar_credenciales_vacios"])
            elif nueva_pwd != confirmar_pwd:
                st.error(t["cambiar_credenciales_no_coinciden"])
            else:
                ok_pol, msg_pol = _validar_politica_contrasena(nueva_pwd)
                if not ok_pol:
                    st.warning(msg_pol)
                else:
                    data = cargar_permisos()
                    if "admin" in data.get("usuarios", {}):
                        data["usuarios"]["admin"]["contrasena"] = _hash_contrasena(nueva_pwd)
                        try:
                            with open(DB_PERMISOS, "w", encoding="utf-8") as f:
                                json.dump(data, f, indent=2, ensure_ascii=False)
                            cargar_permisos.clear()
                        except Exception as e:
                            st.error(str(e))
                            return
                        st.session_state.pop("debe_cambiar_credenciales", None)
                        audit_log("admin", "admin_primera_vez_cambio_contrasena", "")
                        st.success(t["cambiar_credenciales_ok"])
                        st.rerun()

# Permisos que el administrador puede activar/desactivar por usuario
PERMISOS_DISPONIBLES = [
    ("ver_inicio", "VER INICIO"),
    ("ver_arqueo_caja", "VER ARQUEO DE CAJA (Cierre Diario)"),
    ("ver_tesoreria", "VER TESORERÍA (Libro de Registros)"),
    ("ver_contabilidad", "VER CONTABILIDAD (Bóveda Histórica)"),
    ("ver_presupuesto_metas", "VER PRESUPUESTO Y METAS"),
    ("ver_ingresar_bendicion", "VER INGRESAR BENDICIÓN"),
    ("ver_registrar_gasto", "VER REGISTRAR GASTO"),
    ("ver_hoja_contable", "VER HOJA CONTABLE"),
    ("ver_eliminar_registros", "VER ELIMINAR REGISTROS"),
    ("ver_informe_pdf", "VER INFORME PDF"),
    ("ver_exportar_hoja_pdf", "VER EXPORTAR HOJA PDF"),
]
_ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
# Logo metálico futurista: principal en login, inicio y sidebar
LOGO_PRINCIPAL = os.path.join(_ASSETS, "logo_principal.png")
LOGO_LOGIN = os.path.join(_ASSETS, "logo_principal.png")
# Imagen de inicio: logo principal (fallback: inicio_principal.png si existe)
IMAGEN_INICIO = os.path.join(_ASSETS, "logo_principal.png")
IMAGEN_INICIO_ES = os.path.join(_ASSETS, "logo_principal.png")
IMAGEN_INICIO_EN = os.path.join(_ASSETS, "logo_principal.png")
IMAGEN_INICIO_FALLBACK = os.path.join(_ASSETS, "inicio_principal.png")
AZUL_CIELO = "#87CEEB"
BLANCO = "#FFFFFF"
PLOMO = "#5A6268"
GRIS_OSCURO = "#2d3238"
AZUL_OSCURO = "#0d1b2a"

# ============== TEXTOS BILINGÜES (MAYÚSCULAS, SIN ESPACIOS EXTRA) ==============
TEXTOS = {
    "ES": {
        "titulo": "IGLESIA PENTECOSTAL DE WELLAND",
        "subtitulo": "SISTEMA DE TESORERÍA",
        "idioma": "IDIOMA",
        "ingresar_bendicion": "INGRESAR BENDICIÓN",
        "registrar_gasto": "REGISTRAR GASTO",
        "ver_informe": "VER INFORME PDF (WHATSAPP)",
        "ministerio": "MINISTERIO",
        "general": "GENERAL",
        "caballeros": "CABALLEROS",
        "damas": "DAMAS",
        "jovenes": "JÓVENES",
        "ninos": "NIÑOS",
        "musica": "MÚSICA",
        "billetes": "BILLETES",
        "monedas": "MONEDAS",
        "total": "TOTAL",
        "registrar": "REGISTRAR",
        "monto": "MONTO ($)",
        "descripcion": "DESCRIPCIÓN",
        "tomar_foto": "TOMAR FOTO O SUBIR IMAGEN",
        "suministros": "Suministros",
        "gastos_frecuentes": "Gastos frecuentes",
        "gasto_refrescar": "Refrescar",
        "gasto_refrescar_ayuda": "Vacía el formulario para volver a llenarlo.",
        "gasto_sugerencias": "Sugerencias",
        "modo_escaneo_rapido": "Modo escaneo rápido (solo foto + monto)",
        "ocr_diferencia_aviso": "⚠️ El monto manual (${manual:.2f}) difiere del detectado por OCR (${ocr:.2f}). Verifique.",
        "reintentar_ocr": "Reintentar OCR",
        "vista_previa_factura": "Vista previa",
        "foto_multiples_ayuda": "Puede subir varias fotos (frente, reverso, anexos).",
        "foto_frente": "Frente",
        "foto_reverso": "Reverso",
        "foto_anexo": "Anexo",
        "ocr_sin_datos": "No se detectó información. Use «Reintentar OCR» o ingrese los datos manualmente.",
        "importar_gastos": "Importar gastos (CSV/Excel)",
        "importar_gastos_ayuda": "Suba un archivo CSV o Excel con columnas: fecha, detalle, tipo_gasto, gastos",
        "recordatorios_recurrentes": "Recordatorios recurrentes",
        "recordatorios_pendientes": "Suministros que podrían estar pendientes este mes:",
        "recordatorios_todos_ok": "Todos los suministros habituales parecen registrados este mes.",
        "recordatorios_registre": "Registre gastos para ver recordatorios.",
        "gasto_teclado_movil": "En móvil: use el teclado numérico para montos.",
        "gasto_aprobado_requerido": "Gastos ≥ $500 requieren nombre válido en Aprobado por.",
        "gasto_registrado": "GASTO REGISTRADO.",
        "bendicion_registrada": "BENDICIÓN REGISTRADA.",
        "borrar_solo_30min": "BORRADO SOLO PERMITIDO DURANTE 30 MINUTOS.",
        "eliminar": "ELIMINAR",
        "confirmar_eliminar": "Confirmar eliminación de",
        "cargando": "Cargando datos...",
        "pagina": "Página",
        "de": "de",
        "registros": "registros",
        "anterior": "◀ Anterior",
        "siguiente": "Siguiente ▶",
        "coincide_registrado": "✓ Coincide con lo registrado.",
        "saldo": "SALDO",
        "arqueo": "ARQUEO",
        "informe_pdf": "INFORME PDF - TESORERÍA",
        "fecha_informe": "FECHA DEL INFORME",
        "direccion": "77 Duncan St, Welland, Ontario, Canada",
        "ingresos": "INGRESOS",
        "gastos": "GASTOS",
        "caracteres": "CARACTERES",
        "sin_movimientos": "NO HAY MOVIMIENTOS REGISTRADOS.",
        "menu_navegacion": "NAVEGACIÓN",
        "inicio": "INICIO",
        "ministerio_finanzas": "MINISTERIO DE FINANZAS",
        "sistema_tesoreria": "SISTEMA DE TESORERÍA",
        "arqueo_caja": "ARQUEO DE CAJA",
        "arqueo_caja_sub": "Cierre Diario — Conteo físico del día",
        "tesoreria": "TESORERÍA",
        "tesoreria_sub": "Libro de Registros — Ingresos y Gastos",
        "contabilidad": "CONTABILIDAD",
        "contabilidad_sub": "Bóveda Histórica — Reportes y archivos",
        "presupuesto_metas": "PRESUPUESTO Y METAS",
        "presupuesto_metas_sub": "Visión — Planeación de proyectos",
        "bienvenida_titulo": "BIENVENIDO",
        "bienvenida_texto": "SELECCIONE UNA OPCIÓN DEL MENÚ PARA CONTINUAR.",
        "sistema_operaciones": "SISTEMA DE OPERACIONES",
        "mision": "MISIÓN",
        "vision": "VISIÓN",
        "objetivo_supremo": "OBJETIVO SUPREMO",
        "mision_texto": "Llevar la luz del Evangelio a toda criatura, transformando vidas con amor y verdad.",
        "vision_texto": "Ser una comunidad vibrante y global, donde cada miembro es un agente de cambio en el Reino de Dios.",
        "objetivo_texto": "Empoderar tu propósito divino con herramientas de excelencia, para que tu servicio impacte la eternidad ahora.",
        "cerrar": "CERRAR",
        "pastor": "Pastor Javier Escobar",
        "fundamentados": "Fundamentados en la Roca, operando en el Espíritu",
        "col_id_registro": "ID REGISTRO",
        "col_fecha": "FECHA",
        "col_detalle": "DETALLE",
        "col_ingreso": "INGRESO",
        "col_gastos": "GASTOS",
        "col_total_ingresos": "TOTAL INGRESOS",
        "col_total_gastos": "TOTAL GASTOS",
        "col_saldo_actual": "SALDO ACTUAL",
        "col_tipo_gasto": "TIPO",
        "tipo_gasto": "TIPO DE GASTO",
        "exportar_hoja_pdf": "EXPORTAR HOJA CONTABLE PDF",
        "exportar_hoja_contable_titulo": "Exportar hoja contable",
        "exportar_hoja_contable_ayuda": "Descargue la hoja contable en el formato que prefiera: PDF para imprimir, Excel para editar o CSV para el contador.",
        "exportar_opcion_pdf": "PDF",
        "exportar_opcion_excel": "Excel (.xlsx)",
        "exportar_opcion_contador": "Para contador (CSV)",
        "informe_auditoria": "INFORME DE AUDITORÍA CONTABLE",
        "situacion_actual": "SITUACIÓN ACTUAL",
        "superavit": "SUPERÁVIT",
        "deficit": "DÉFICIT",
        "alertas_crisis": "ALERTAS DE CRISIS",
        "sin_alertas": "Sin alertas críticas.",
        "alerta_saldo_negativo": "Saldo negativo: gastos superan a ingresos.",
        "alerta_gastos_altos": "Gastos representan más del 90% de los ingresos.",
        "alerta_sin_ingresos": "No hay ingresos registrados en el período.",
        "alerta_saldo_bajo": "Saldo bajo: margen de seguridad reducido.",
        "presupuesto_real": "PRESUPUESTO REAL (POR TIPO DE GASTO)",
        "analisis_clinico": "ANÁLISIS",
        "riesgo": "EVALUACIÓN DE RIESGO",
        "riesgo_bajo": "Bajo",
        "riesgo_medio": "Medio",
        "riesgo_alto": "Alto",
        "recomendaciones": "RECOMENDACIONES",
        "ultimos_movimientos": "ÚLTIMOS MOVIMIENTOS",
        "recom_control_gastos": "• Controlar gastos innecesarios y revisar categorías con mayor salida.",
        "recom_reserva": "• Mantener una reserva equivalente a al menos un mes de gastos.",
        "recom_revisar": "• Revisar periódicamente este informe para tomar decisiones a tiempo.",
        "recom_evitar_deficit": "• Evitar que los gastos superen los ingresos de forma sostenida.",
        "alerta_emergencia_titulo": "⚠️ NO GUARDE — RIESGO DETECTADO",
        "alerta_emergencia_texto": "Se detectaron datos inválidos o posible manipulación. No guarde hasta corregir. Podría haber peligro para la integridad de los datos.",
        "reiniciar_tesoreria": "REINICIAR TESORERÍA (SOLO MAESTRO)",
        "reiniciar_explicacion": "Borra solo los registros (datos ingresados). No borra fórmulas ni estructuras. Se guarda una copia en la carpeta de resets.",
        "confirmar_escribir": "Escriba exactamente",
        "para_confirmar": "para confirmar y reiniciar.",
        "reinicio_ok": "Tesorería reiniciada. Respaldo guardado.",
        "retroceder_historial": "RETROCEDER HISTORIAL (RESTAURAR RESPALDO)",
        "retroceder_explicacion": "Restaura la base de datos a un punto anterior. Use si hubo un error y desea volver atrás sin perder todo.",
        "seleccionar_respaldo": "Seleccione el respaldo a restaurar (más reciente arriba):",
        "restaurar": "Restaurar este respaldo",
        "restaurado_ok": "Respaldo restaurado correctamente.",
        "sin_respaldos": "No hay respaldos disponibles.",
        "tipo_ingreso": "TIPO DE INGRESO",
        "filtros": "FILTROS",
        "fecha_desde": "Desde",
        "fecha_hasta": "Hasta",
        "monto_min": "Monto desde ($)",
        "monto_max": "Monto hasta ($)",
        "filtros_ayuda": "Deje fechas o montos en blanco para no filtrar por ellos.",
        "help_fecha_desde": "Opcional. Solo registros desde esta fecha.",
        "help_fecha_hasta": "Opcional. Solo registros hasta esta fecha.",
        "help_monto_min": "0 = sin mínimo. Filtra por monto del movimiento.",
        "help_monto_max": "0 = sin máximo.",
        "help_filtrar_tipo": "Filtrar por tipo de ingreso o de gasto.",
        "filtrar_tipo": "Tipo",
        "todos_los_tipos": "Todos los tipos",
        "limpiar_fila": "Limpiar esta fila",
        "borrar_btn": "Borrar",
        "borrar_seleccionados": "Borrar seleccionados",
        "borrar_todos": "Borrar todos",
        "seleccionar_todos": "Seleccionar todos",
        "limpiar_todo_tablero": "Limpiar todo el tablero",
        "confirmar_limpiar_todo": "Escriba BORRAR TODO para vaciar la hoja.",
        "maestro_borrar_titulo": "BORRAR REGISTROS (SOLO ACCESO MAESTRO)",
        "maestro_borrar_todo": "BORRAR TODO",
        "maestro_borrar_masa": "Borrar seleccionados",
        "maestro_seleccionar_masa": "Seleccione filas para borrar en masa:",
        "maestro_borrar_detalle": "Borrar por detalle",
        "maestro_seleccionar_detalle": "Escriba texto que contenga el detalle (ej: compra, alquiler). Se borrarán todos los registros cuyo detalle coincida.",
        "maestro_coinciden_registros": "Coinciden {n} registro(s).",
        "maestro_sin_limite": "sin límite de tiempo",
        "solo_30min": "solo dentro de 30 min",
        "arqueo_cero": "El total del arqueo es $0. No se registró.",
        "gasto_cero": "El monto del gasto es $0. No se registró.",
        "sin_resultados_filtro": "No hay registros que coincidan con los filtros aplicados.",
        "quien_usa_app": "Quién usa la app",
        "usuario_actual_menu": "USUARIO ACTUAL",
        "administracion": "ADMINISTRACIÓN",
        "administracion_titulo": "ADMINISTRACIÓN DE PERMISOS",
        "admin_instrucciones": "Marque o desmarque la casilla: **verde** = tiene permiso, **rojo** = no tiene. Un clic da o quita el permiso.",
        "admin_anadir_usuario": "➕ AÑADIR NUEVO USUARIO",
        "admin_id_placeholder": "ID del usuario (ej: asistente)",
        "admin_nombre_placeholder": "Nombre visible (ej: Asistente)",
        "admin_btn_anadir": "Añadir usuario",
        "admin_id_ya_existe": "Ese ID ya existe.",
        "admin_usuario_anadido": "Usuario «{nombre}» añadido. Abajo aparecerá su lista de permisos.",
        "admin_asignar_permisos": "Usuario **{nombre}** añadido. Asigne o quite permisos con las casillas de abajo.",
        "admin_caption_admin": "El administrador siempre ve todo. No se pueden cambiar sus permisos.",
        "admin_caption_verde_rojo": "Verde = puede ver esa sección. Rojo = no puede. Clic en la casilla para cambiar.",
        "admin_contrasena": "Contraseña (opcional)",
        "admin_contrasena_placeholder": "Dejar vacío = usar predeterminada",
        "admin_guardar_contrasena": "Guardar contraseña",
        "admin_contrasena_guardada": "Contraseña guardada.",
        "admin_reset_contrasena": "Restablecer contraseña (solo admin)",
        "tema_oscuro": "Tema oscuro",
        "tema_claro": "Tema claro",
        "admin_expander_admin": " — Administrador (todos los permisos)",
        "admin_btn_reiniciar": "Reiniciar tesorería (borrar solo datos)",
        "admin_error_reinicio": "No se pudo completar el reinicio.",
        "admin_debe_escribir": "Debe escribir exactamente «{palabra}» para confirmar.",
        "admin_error_restaurar": "No se pudo restaurar el respaldo.",
        "volver_inicio": "Volver al inicio",
        "descargar_pdf_whatsapp": "DESCARGAR PDF PARA WHATSAPP",
        "error_limpiar_tablero": "No se pudo limpiar el tablero.",
        "gasto_foto_no": "GASTO GUARDADO PERO FOTO NO: {e}",
        "imagen_ya_subida_aviso": "⚠️ Esta imagen ya fue subida anteriormente. Evite registrar el mismo comprobante dos veces.",
        "factura_detectada": "Datos detectados en la factura / imagen",
        "total_detectado": "Total detectado",
        "impuesto_detectado": "Impuesto detectado",
        "comercio_detectado": "Comercio / descripción",
        "error_no_se_pudo_guardar": "NO SE PUDO GUARDAR: {e}",
        "error_no_se_pudo_guardar_permisos": "NO SE PUDO GUARDAR PERMISOS: {e}",
        "error_validacion": "Error de validación: {msg}",
        "ver_mas": "Ver más",
        "buscar_facturas_titulo": "BUSCAR FACTURAS / COMPROBANTES",
        "buscar_facturas_ayuda": "Busque por comercio, fecha, monto total o texto extraído de la imagen (OCR).",
        "buscar_por_comercio": "Comercio (contiene)",
        "buscar_por_texto_ocr": "Texto en factura (OCR)",
        "buscar_por_fecha_desde": "Fecha registro desde",
        "buscar_por_fecha_hasta": "Fecha registro hasta",
        "buscar_por_total_min": "Total desde ($)",
        "buscar_por_total_max": "Total hasta ($)",
        "buscar_por_tipo_gasto": "Tipo de gasto",
        "buscar_por_impuesto_desde": "Impuesto desde ($)",
        "buscar_por_impuesto_hasta": "Impuesto hasta ($)",
        "buscar_btn": "Buscar",
        "resultados_facturas": "Resultados",
        "sin_resultados_facturas": "No hay facturas que coincidan con la búsqueda.",
        "sin_facturas": "Aún no hay facturas registradas.",
        "texto_ocr": "Texto OCR",
        "descargar_fotos_zip": "DESCARGAR FOTOS DE GASTOS (ZIP)",
        "medio_pago": "MEDIO DE PAGO",
        "efectivo_arqueo": "Efectivo (arqueo de billetes y monedas)",
        "pos_tarjeta_credito": "POS / Tarjeta de crédito",
        "tarjeta_debito": "Tarjeta de débito",
        "transferencia": "Transferencia bancaria",
        "monto_pos_tarjeta": "Monto ($)",
        "referencia_opcional": "Referencia o últimos 4 dígitos (opcional)",
        "referencia_placeholder": "ej. 1234 o REF-001",
        "pin_ingrese": "Ingrese PIN de administrador",
        "pin_incorrecto": "PIN incorrecto.",
        "entrar": "Entrar",
        "cerrar_sesion": "Cerrar sesión",
        "sesion_cerrada": "Sesión cerrada.",
        "tiempo_inactivo_cerrado": "Sesión cerrada por inactividad. Vuelva a elegir usuario.",
        "version": "Versión",
        "acerca_de": "Acerca del sistema",
        "aprobado_por": "Aprobado por (opcional, gastos > $)",
        "establecer_pin": "Establecer PIN de administrador",
        "cambiar_pin": "Cambiar PIN de administrador",
        "acceso_maestro": "🔑 Acceso maestro",
        "acceso_maestro_info": "Restablecer admin a usuario: admin, contraseña: admin (acceso inicial).",
        "restablecer_admin_admin": "Restablecer a admin/admin",
        "pin_actual": "PIN actual",
        "pin_nuevo": "PIN nuevo",
        "pin_guardado": "PIN guardado.",
        "exportar_contador": "EXPORTAR PARA CONTADOR (EXCEL/CSV)",
        "exportar_excel": "EXPORTAR EXCEL (.xlsx)",
        "integridad_ok": "Integridad del libro comprobada.",
        "integridad_aviso": "Aviso: totales no coinciden. Considere restaurar un respaldo.",
        "dashboard_resumen": "RESUMEN",
        "saldo_actual": "Saldo actual",
        "ingresos_mes": "Ingresos del mes",
        "gastos_mes": "Gastos del mes",
        "grafico_ingresos_gastos": "Ingresos vs Gastos por mes",
        "grafico_resultado": "Resultado (Ingresos − Gastos)",
        "grafico_trazabilidad": "Trazabilidad del saldo (alza/baja en el tiempo)",
        "grafico_saldo": "Saldo",
        "grafico_alza": "Alza",
        "grafico_baja": "Baja",
        "grafico_var": "Variación",
        "grafico_ver_ingresos_gastos": "Ver cuadro Ingresos & Gastos",
        "conciliar": "CONCILIAR INGRESOS",
        "conciliar_ayuda": "Compare el total registrado con lo que contó en caja (opcional).",
        "conciliar_por_dia": "Conciliar por día",
        "fecha_conciliar": "Fecha a conciliar",
        "contado_por": "Contado por",
        "contado_por_ayuda": "Obligatorio. Seleccione o escriba. Se guarda en mayúsculas para futuros arqueos.",
        "verificado_por": "Verificado por",
        "verificado_por_ayuda": "Obligatorio. Solo después de Contado por.",
        "arqueo_llenar_ambos": "Debe llenar Contado por y Verificado por antes de continuar.",
        "arqueo_otro": "Otro (escribir nuevo)",
        "arqueo_sugerencias": "Sugerencias",
        "arqueo_refrescar": "Refrescar",
        "arqueo_refrescar_ayuda": "Vacía el formulario para volver a llenarlo.",
        "arqueo_nombre_invalido": "El nombre no debe contener solo números.",
        "arqueo_nombre_simbolos": "El nombre no debe contener símbolos (@#$%...).",
        "arqueo_nombre_muy_corto": "Ingrese al menos 2 caracteres (evite solo iniciales o una letra).",
        "arqueo_teclado_movil": "En móvil: use el teclado numérico para billetes y monedas.",
        "arqueo_total_calculado": "Total billetes + monedas",
        "sobres_cantidad": "Nº de sobres",
        "sobres_total": "Total en sobres ($)",
        "total_suelto": "Total suelto ($)",
        "cheques_cantidad": "Nº de cheques",
        "cheques_total": "Total cheques ($)",
        "fondo_caja": "Fondo de caja inicial ($)",
        "descargar_hoja_arqueo": "Descargar hoja de arqueo",
        "descargar_hoja_arqueo_ayuda": "Seleccione el arqueo y descargue en PDF o Excel. Archivos comprimidos para enviar por WhatsApp, abren en cualquier dispositivo.",
        "seleccionar_arqueo": "Seleccionar arqueo",
        "hoja_arqueo_pdf": "PDF",
        "hoja_arqueo_excel": "Excel (.xlsx)",
        "resumen_dia": "Resumen del día",
        "cerrar_arqueo": "Cerrar arqueo del día",
        "arqueo_cerrado": "Arqueo cerrado",
        "col_ip": "IP",
        "presupuesto_vs_real": "Presupuesto vs real",
        "primera_vez": "¿Primera vez aquí?",
        "ayuda_rapida": "Guía rápida: use el menú para Inicio, Ministerio de Finanzas o Administración. Los ingresos se registran en Ingresar bendición; los gastos en Registrar gasto. Respaldos automáticos en cada guardado.",
        "tamano_texto": "Tamaño de texto",
        "tamano_normal": "Normal",
        "tamano_grande": "Grande",
        "lo_contado_caja": "Lo que contó en caja ($)",
        "compartir_app": "Compartir app (instalar como Netflix/Disney)",
        "compartir_app_instrucciones": "Puedes enviar el enlace de esta app por WhatsApp. Quien lo abra en el celular puede instalarla como una app: en Chrome/Safari, menú (⋮ o Compartir) → «Añadir a la pantalla de inicio» o «Instalar aplicación». Así se abre como app, sin barra del navegador. El enlace que debes compartir es la URL donde está publicada esta app (ej. tu servidor o Streamlit Cloud). Para que no sea pesada al abrir, la imagen de inicio se adapta al tamaño del celular; si quieres menos peso, usa una imagen de inicio comprimida o reducida en assets.",
        "login_titulo": "Iglesia Pentecostal de Welland",
        "login_subtitulo": "Inicia sesión para explorar las funciones financieras y herramientas en línea.",
        "login_usuario": "Usuario",
        "login_usuario_placeholder": "admin (primera vez: admin/admin)",
        "login_contrasena": "Contraseña",
        "login_btn": "Iniciar sesión",
        "login_error": "Usuario o contraseña incorrectos.",
        "login_error_usuario": "Usuario no encontrado.",
        "login_error_contrasena": "Contraseña incorrecta.",
        "login_bloqueado": "Demasiados intentos. Espere {min} minutos e intente de nuevo.",
        "login_recordar": "Recordar sesión",
        "login_recuperar": "¿Olvidó su contraseña?",
        "login_recuperar_ayuda": "Administrador: vaya a Administración → usuario → Restablecer contraseña",
        "login_ultima_actividad": "Última actividad",
        "cambiar_credenciales_titulo": "Cambiar contraseña (obligatorio)",
        "cambiar_credenciales_info": "Por seguridad, debe establecer una contraseña antes de continuar. admin/admin ya no funcionará.",
        "cambiar_credenciales_nueva": "Nueva contraseña",
        "cambiar_credenciales_confirmar": "Confirmar contraseña",
        "cambiar_credenciales_guardar": "Guardar y continuar",
        "cambiar_credenciales_vacios": "Complete ambos campos.",
        "cambiar_credenciales_no_coinciden": "Las contraseñas no coinciden.",
        "cambiar_credenciales_ok": "Contraseña guardada. Redirigiendo...",
    },
    "EN": {
        "titulo": "WELLAND PENTECOSTAL CHURCH",
        "subtitulo": "TREASURY SYSTEM",
        "idioma": "LANGUAGE",
        "ingresar_bendicion": "ENTER BLESSING",
        "registrar_gasto": "REGISTER EXPENSE",
        "ver_informe": "VIEW PDF REPORT (WHATSAPP)",
        "ministerio": "MINISTRY",
        "general": "GENERAL",
        "caballeros": "MEN",
        "damas": "WOMEN",
        "jovenes": "YOUTH",
        "ninos": "CHILDREN",
        "musica": "MUSIC",
        "billetes": "BILLS",
        "monedas": "COINS",
        "total": "TOTAL",
        "registrar": "REGISTER",
        "monto": "AMOUNT ($)",
        "descripcion": "DESCRIPTION",
        "tomar_foto": "TAKE PHOTO OR UPLOAD IMAGE",
        "suministros": "Supplies",
        "gastos_frecuentes": "Frequent expenses",
        "gasto_refrescar": "Refresh",
        "gasto_refrescar_ayuda": "Clears the form to fill again.",
        "gasto_sugerencias": "Suggestions",
        "modo_escaneo_rapido": "Quick scan mode (photo + amount only)",
        "ocr_diferencia_aviso": "⚠️ Manual amount (${manual:.2f}) differs from OCR detected (${ocr:.2f}). Please verify.",
        "reintentar_ocr": "Retry OCR",
        "vista_previa_factura": "Preview",
        "foto_multiples_ayuda": "You can upload multiple photos (front, back, attachments).",
        "foto_frente": "Front",
        "foto_reverso": "Back",
        "foto_anexo": "Attachment",
        "ocr_sin_datos": "No information detected. Use «Retry OCR» or enter data manually.",
        "importar_gastos": "Import expenses (CSV/Excel)",
        "importar_gastos_ayuda": "Upload CSV or Excel with columns: fecha, detalle, tipo_gasto, gastos",
        "recordatorios_recurrentes": "Recurring reminders",
        "recordatorios_pendientes": "Supplies that may be pending this month:",
        "recordatorios_todos_ok": "All usual supplies appear to be registered this month.",
        "recordatorios_registre": "Register expenses to see reminders.",
        "gasto_teclado_movil": "On mobile: use numeric keypad for amounts.",
        "gasto_aprobado_requerido": "Expenses ≥ $500 require valid name in Approved by.",
        "gasto_registrado": "EXPENSE REGISTERED.",
        "bendicion_registrada": "BLESSING REGISTERED.",
        "borrar_solo_30min": "DELETION ONLY ALLOWED WITHIN 30 MINUTES.",
        "eliminar": "DELETE",
        "confirmar_eliminar": "Confirm deletion of",
        "cargando": "Loading data...",
        "pagina": "Page",
        "de": "of",
        "registros": "records",
        "anterior": "◀ Previous",
        "siguiente": "Next ▶",
        "coincide_registrado": "✓ Matches registered amount.",
        "saldo": "BALANCE",
        "arqueo": "COUNT",
        "informe_pdf": "PDF REPORT - TREASURY",
        "fecha_informe": "REPORT DATE",
        "direccion": "77 Duncan St, Welland, Ontario, Canada",
        "ingresos": "INCOME",
        "gastos": "EXPENSES",
        "caracteres": "CHARACTERS",
        "sin_movimientos": "NO RECORDED TRANSACTIONS.",
        "menu_navegacion": "NAVIGATION",
        "inicio": "HOME",
        "ministerio_finanzas": "FINANCE MINISTRY",
        "sistema_tesoreria": "TREASURY SYSTEM",
        "arqueo_caja": "CASH COUNT",
        "arqueo_caja_sub": "Daily Close — Physical count of the day",
        "tesoreria": "TREASURY",
        "tesoreria_sub": "Ledger — Income and Expenses",
        "contabilidad": "ACCOUNTING",
        "contabilidad_sub": "Historic Vault — Reports and files",
        "presupuesto_metas": "BUDGET & GOALS",
        "presupuesto_metas_sub": "Vision — Project planning",
        "bienvenida_titulo": "WELCOME",
        "bienvenida_texto": "SELECT AN OPTION FROM THE MENU TO CONTINUE.",
        "sistema_operaciones": "OPERATIONS SYSTEM",
        "mision": "MISSION",
        "vision": "VISION",
        "objetivo_supremo": "SUPREME OBJECTIVE",
        "mision_texto": "To bring the light of the Gospel to every creature, transforming lives with love and truth.",
        "vision_texto": "To be a vibrant and global community, where every member is an agent of change in the Kingdom of God.",
        "objetivo_texto": "To empower your divine purpose with tools of excellence, so that your service impacts eternity now.",
        "cerrar": "CLOSE",
        "pastor": "Pastor Javier Escobar",
        "fundamentados": "Founded on the Rock, operating in the Spirit",
        "col_id_registro": "ID REGISTER",
        "col_fecha": "DATE",
        "col_detalle": "DETAIL",
        "col_ingreso": "INCOME",
        "col_gastos": "EXPENSES",
        "col_total_ingresos": "TOTAL INCOME",
        "col_total_gastos": "TOTAL EXPENSES",
        "col_saldo_actual": "CURRENT BALANCE",
        "col_tipo_gasto": "TYPE",
        "tipo_gasto": "EXPENSE TYPE",
        "exportar_hoja_pdf": "EXPORT LEDGER PDF",
        "exportar_hoja_contable_titulo": "Export ledger",
        "exportar_hoja_contable_ayuda": "Download the ledger in your preferred format: PDF for printing, Excel for editing, or CSV for the accountant.",
        "exportar_opcion_pdf": "PDF",
        "exportar_opcion_excel": "Excel (.xlsx)",
        "exportar_opcion_contador": "For accountant (CSV)",
        "informe_auditoria": "FINANCIAL AUDIT REPORT",
        "situacion_actual": "CURRENT SITUATION",
        "superavit": "SURPLUS",
        "deficit": "DEFICIT",
        "alertas_crisis": "CRISIS ALERTS",
        "sin_alertas": "No critical alerts.",
        "alerta_saldo_negativo": "Negative balance: expenses exceed income.",
        "alerta_gastos_altos": "Expenses represent over 90% of income.",
        "alerta_sin_ingresos": "No income recorded in the period.",
        "alerta_saldo_bajo": "Low balance: reduced safety margin.",
        "presupuesto_real": "ACTUAL BUDGET (BY EXPENSE TYPE)",
        "analisis_clinico": "ANALYSIS",
        "riesgo": "RISK ASSESSMENT",
        "riesgo_bajo": "Low",
        "riesgo_medio": "Medium",
        "riesgo_alto": "High",
        "recomendaciones": "RECOMMENDATIONS",
        "ultimos_movimientos": "RECENT TRANSACTIONS",
        "recom_control_gastos": "• Control unnecessary spending and review highest-expense categories.",
        "recom_reserva": "• Maintain a reserve of at least one month of expenses.",
        "recom_revisar": "• Review this report regularly to make timely decisions.",
        "recom_evitar_deficit": "• Avoid letting expenses exceed income on a sustained basis.",
        "alerta_emergencia_titulo": "⚠️ DO NOT SAVE — RISK DETECTED",
        "alerta_emergencia_texto": "Invalid data or possible tampering detected. Do not save until corrected. Data integrity may be at risk.",
        "reiniciar_tesoreria": "RESET TREASURY (MASTER ONLY)",
        "reiniciar_explicacion": "Deletes only recorded data. Does not delete formulas or structures. A copy is saved in the resets folder.",
        "confirmar_escribir": "Type exactly",
        "para_confirmar": "to confirm and reset.",
        "reinicio_ok": "Treasury reset. Backup saved.",
        "retroceder_historial": "ROLLBACK HISTORY (RESTORE BACKUP)",
        "retroceder_explicacion": "Restores the database to a previous point. Use if there was an error and you want to go back without losing everything.",
        "seleccionar_respaldo": "Select the backup to restore (newest first):",
        "restaurar": "Restore this backup",
        "restaurado_ok": "Backup restored successfully.",
        "sin_respaldos": "No backups available.",
        "tipo_ingreso": "INCOME TYPE",
        "filtros": "FILTERS",
        "fecha_desde": "From",
        "fecha_hasta": "To",
        "monto_min": "Amount from ($)",
        "monto_max": "Amount to ($)",
        "filtros_ayuda": "Leave dates or amounts blank to show all.",
        "help_fecha_desde": "Optional. Only records from this date.",
        "help_fecha_hasta": "Optional. Only records until this date.",
        "help_monto_min": "0 = no minimum. Filter by movement amount.",
        "help_monto_max": "0 = no maximum.",
        "help_filtrar_tipo": "Filter by income or expense type.",
        "filtrar_tipo": "Type",
        "todos_los_tipos": "All types",
        "limpiar_fila": "Clear this row",
        "borrar_btn": "Delete",
        "borrar_seleccionados": "Delete selected",
        "borrar_todos": "Delete all",
        "seleccionar_todos": "Select all",
        "limpiar_todo_tablero": "Clear entire table",
        "confirmar_limpiar_todo": "Type CLEAR ALL to empty the ledger.",
        "maestro_borrar_titulo": "DELETE RECORDS (MASTER ACCESS ONLY)",
        "maestro_borrar_todo": "DELETE ALL",
        "maestro_borrar_masa": "Delete selected",
        "maestro_seleccionar_masa": "Select rows to delete in bulk:",
        "maestro_borrar_detalle": "Delete by detail",
        "maestro_seleccionar_detalle": "Type text contained in the detail (e.g. purchase, rent). All records whose detail matches will be deleted.",
        "maestro_coinciden_registros": "{n} record(s) match.",
        "maestro_sin_limite": "no time limit",
        "solo_30min": "only within 30 min",
        "arqueo_cero": "Count total is $0. Not recorded.",
        "gasto_cero": "Expense amount is $0. Not recorded.",
        "sin_resultados_filtro": "No records match the current filters.",
        "quien_usa_app": "Who is using the app",
        "usuario_actual_menu": "CURRENT USER",
        "administracion": "ADMINISTRATION",
        "administracion_titulo": "PERMISSIONS ADMINISTRATION",
        "admin_instrucciones": "Check or uncheck the box: **green** = has permission, **red** = does not. One click toggles.",
        "admin_anadir_usuario": "➕ ADD NEW USER",
        "admin_id_placeholder": "User ID (e.g. assistant)",
        "admin_nombre_placeholder": "Display name (e.g. Assistant)",
        "admin_btn_anadir": "Add user",
        "admin_id_ya_existe": "That ID already exists.",
        "admin_usuario_anadido": "User «{nombre}» added. Their permission list will appear below.",
        "admin_asignar_permisos": "User **{nombre}** added. Assign or remove permissions with the checkboxes below.",
        "admin_caption_admin": "The administrator always sees everything. Their permissions cannot be changed.",
        "admin_caption_verde_rojo": "Green = can see that section. Red = cannot. Click the box to change.",
        "admin_contrasena": "Password (optional)",
        "admin_contrasena_placeholder": "Leave empty = use default",
        "admin_guardar_contrasena": "Save password",
        "admin_contrasena_guardada": "Password saved.",
        "admin_reset_contrasena": "Reset password (admin only)",
        "tema_oscuro": "Dark theme",
        "tema_claro": "Light theme",
        "admin_expander_admin": " — Administrator (all permissions)",
        "admin_btn_reiniciar": "Reset treasury (delete data only)",
        "admin_error_reinicio": "Reset could not be completed.",
        "admin_debe_escribir": "You must type exactly «{palabra}» to confirm.",
        "admin_error_restaurar": "Backup could not be restored.",
        "volver_inicio": "Back to home",
        "descargar_pdf_whatsapp": "DOWNLOAD PDF FOR WHATSAPP",
        "error_limpiar_tablero": "Table could not be cleared.",
        "gasto_foto_no": "EXPENSE SAVED BUT PHOTO NOT: {e}",
        "imagen_ya_subida_aviso": "⚠️ This image was already uploaded before. Avoid registering the same receipt twice.",
        "factura_detectada": "Data detected from receipt / image",
        "total_detectado": "Total detected",
        "impuesto_detectado": "Tax detected",
        "comercio_detectado": "Merchant / description",
        "error_no_se_pudo_guardar": "COULD NOT SAVE: {e}",
        "error_no_se_pudo_guardar_permisos": "COULD NOT SAVE PERMISSIONS: {e}",
        "error_validacion": "Validation error: {msg}",
        "ver_mas": "See more",
        "buscar_facturas_titulo": "SEARCH RECEIPTS / INVOICES",
        "buscar_facturas_ayuda": "Search by merchant, date, total amount, or text extracted from the image (OCR).",
        "buscar_por_comercio": "Merchant (contains)",
        "buscar_por_texto_ocr": "Text in receipt (OCR)",
        "buscar_por_fecha_desde": "Record date from",
        "buscar_por_fecha_hasta": "Record date until",
        "buscar_por_total_min": "Total from ($)",
        "buscar_por_total_max": "Total to ($)",
        "buscar_por_tipo_gasto": "Expense type",
        "buscar_por_impuesto_desde": "Tax from ($)",
        "buscar_por_impuesto_hasta": "Tax to ($)",
        "buscar_btn": "Search",
        "resultados_facturas": "Results",
        "sin_resultados_facturas": "No receipts match the search.",
        "sin_facturas": "No receipts registered yet.",
        "texto_ocr": "OCR text",
        "descargar_fotos_zip": "DOWNLOAD EXPENSE PHOTOS (ZIP)",
        "medio_pago": "PAYMENT METHOD",
        "efectivo_arqueo": "Cash (bills and coins count)",
        "pos_tarjeta_credito": "POS / Credit card",
        "tarjeta_debito": "Debit card",
        "transferencia": "Bank transfer",
        "monto_pos_tarjeta": "Amount ($)",
        "referencia_opcional": "Reference or last 4 digits (optional)",
        "referencia_placeholder": "e.g. 1234 or REF-001",
        "pin_ingrese": "Enter administrator PIN",
        "pin_incorrecto": "Incorrect PIN.",
        "entrar": "Enter",
        "cerrar_sesion": "Log out",
        "sesion_cerrada": "Logged out.",
        "tiempo_inactivo_cerrado": "Session closed due to inactivity. Please select user again.",
        "version": "Version",
        "acerca_de": "About this system",
        "aprobado_por": "Approved by (optional, expenses > $)",
        "establecer_pin": "Set administrator PIN",
        "cambiar_pin": "Change administrator PIN",
        "acceso_maestro": "🔑 Master access",
        "acceso_maestro_info": "Reset admin to username: admin, password: admin (initial access).",
        "restablecer_admin_admin": "Reset to admin/admin",
        "pin_actual": "Current PIN",
        "pin_nuevo": "New PIN",
        "pin_guardado": "PIN saved.",
        "exportar_contador": "EXPORT FOR ACCOUNTANT (EXCEL/CSV)",
        "exportar_excel": "EXPORT EXCEL (.xlsx)",
        "integridad_ok": "Ledger integrity verified.",
        "integridad_aviso": "Warning: totals do not match. Consider restoring a backup.",
        "dashboard_resumen": "SUMMARY",
        "saldo_actual": "Current balance",
        "ingresos_mes": "Income this month",
        "gastos_mes": "Expenses this month",
        "grafico_ingresos_gastos": "Income vs Expenses by month",
        "grafico_resultado": "Result (Income − Expenses)",
        "grafico_trazabilidad": "Balance traceability (rise/fall over time)",
        "grafico_saldo": "Balance",
        "grafico_alza": "Rise",
        "grafico_baja": "Fall",
        "grafico_var": "Change",
        "grafico_ver_ingresos_gastos": "Show Income & Expenses chart",
        "conciliar": "RECONCILE INCOME",
        "conciliar_ayuda": "Compare registered total with what you counted in cash (optional).",
        "conciliar_por_dia": "Reconcile by day",
        "fecha_conciliar": "Date to reconcile",
        "contado_por": "Counted by",
        "contado_por_ayuda": "Required. Select or type. Saved in uppercase for future counts.",
        "verificado_por": "Verified by",
        "verificado_por_ayuda": "Required. Only after Counted by.",
        "arqueo_llenar_ambos": "You must fill Counted by and Verified by before continuing.",
        "arqueo_otro": "Other (type new)",
        "arqueo_sugerencias": "Suggestions",
        "arqueo_refrescar": "Refresh",
        "arqueo_refrescar_ayuda": "Clears the form to fill again.",
        "arqueo_nombre_invalido": "Name should not contain only numbers.",
        "arqueo_nombre_simbolos": "Name should not contain symbols (@#$%...).",
        "arqueo_nombre_muy_corto": "Enter at least 2 characters (avoid single letter or initial only).",
        "arqueo_teclado_movil": "On mobile: use numeric keyboard for bills and coins.",
        "arqueo_total_calculado": "Total bills + coins",
        "sobres_cantidad": "No. of envelopes",
        "sobres_total": "Total in envelopes ($)",
        "total_suelto": "Loose total ($)",
        "cheques_cantidad": "No. of checks",
        "cheques_total": "Total checks ($)",
        "fondo_caja": "Opening cash fund ($)",
        "descargar_hoja_arqueo": "Download count sheet",
        "descargar_hoja_arqueo_ayuda": "Select the count and download in PDF or Excel. Compressed files for WhatsApp, open on any device.",
        "seleccionar_arqueo": "Select count",
        "hoja_arqueo_pdf": "PDF",
        "hoja_arqueo_excel": "Excel (.xlsx)",
        "resumen_dia": "Daily summary",
        "cerrar_arqueo": "Close day count",
        "arqueo_cerrado": "Count closed",
        "col_ip": "IP",
        "presupuesto_vs_real": "Budget vs actual",
        "primera_vez": "First time here?",
        "ayuda_rapida": "Quick guide: use the menu for Home, Finance Ministry or Administration. Income is entered in Enter blessing; expenses in Register expense. Automatic backups on each save.",
        "tamano_texto": "Text size",
        "tamano_normal": "Normal",
        "tamano_grande": "Large",
        "lo_contado_caja": "What you counted in cash ($)",
        "compartir_app": "Share app (install like Netflix/Disney)",
        "compartir_app_instrucciones": "You can send this app's link via WhatsApp. Whoever opens it on their phone can install it as an app: in Chrome/Safari, menu (⋮ or Share) → «Add to Home Screen» or «Install app». It will open like an app, without the browser bar. The link to share is the URL where this app is published (e.g. your server or Streamlit Cloud). To keep it light, the home image is sized for the phone; use a compressed or smaller image in assets if you want faster loading.",
        "login_titulo": "Iglesia Pentecostal de Welland",
        "login_subtitulo": "Log in to explore financial functions and online tools.",
        "login_usuario": "Username",
        "login_usuario_placeholder": "admin (first time: admin/admin)",
        "login_contrasena": "Password",
        "login_btn": "Log In",
        "login_error": "Incorrect username or password.",
        "login_error_usuario": "User not found.",
        "login_error_contrasena": "Incorrect password.",
        "login_bloqueado": "Too many attempts. Wait {min} minutes and try again.",
        "login_recordar": "Remember session",
        "login_recuperar": "Forgot your password?",
        "login_recuperar_ayuda": "Administrator: go to Administration → user → Reset password",
        "login_ultima_actividad": "Last activity",
        "cambiar_credenciales_titulo": "Change password (required)",
        "cambiar_credenciales_info": "For security, you must set a password before continuing. admin/admin will no longer work.",
        "cambiar_credenciales_nueva": "New password",
        "cambiar_credenciales_confirmar": "Confirm password",
        "cambiar_credenciales_guardar": "Save and continue",
        "cambiar_credenciales_vacios": "Fill in both fields.",
        "cambiar_credenciales_no_coinciden": "Passwords do not match.",
        "cambiar_credenciales_ok": "Password saved. Redirecting...",
    },
}

MINISTERIOS = ["GENERAL", "CABALLEROS", "DAMAS", "JÓVENES", "NIÑOS", "MÚSICA"]
MINISTERIOS_EN = ["GENERAL", "MEN", "WOMEN", "YOUTH", "CHILDREN", "MUSIC"]

# Tipos de gasto universales y modernos (ES label, EN label). Se guarda el valor ES en CSV.
# Recurrentes = primero (suministros por pagar: luz, agua, etc.). Operativo = gastos frecuentes del historial.
TIPOS_GASTO_ES = [
    "Recurrentes", "Operativo", "Mantenimiento", "Servicios", "Programas",
    "Equipo y tecnología", "Donaciones y ofrendas", "Otros"
]
TIPOS_GASTO_EN = [
    "Recurring", "Operational", "Maintenance", "Utilities", "Programs",
    "Equipment & tech", "Donations & offerings", "Other"
]
DEFAULT_TIPO_GASTO = "Otros"  # para registros antiguos o sin tipo

# Tipos de ingreso universales para iglesia (se guardan en columna tipo_gasto para ingresos)
TIPOS_INGRESO_ES = [
    "Ofrenda del culto", "Diezmo", "Arqueo de caja (ministerio)", "Donación designada",
    "Evento o actividad", "Venta / Kiosco / Cafetería", "Ofrenda misionera", "Otros ingresos"
]
TIPOS_INGRESO_EN = [
    "Service offering", "Tithe", "Cash count (ministry)", "Designated donation",
    "Event or activity", "Sale / Kiosk / Café", "Missions offering", "Other income"
]
DEFAULT_TIPO_INGRESO = "Ofrenda del culto"

# Medios de pago para ingresos (diezmos, ofrendas por POS/tarjeta/transferencia)
MEDIOS_PAGO_ES = ["Efectivo (arqueo de billetes y monedas)", "POS / Tarjeta de crédito", "Tarjeta de débito", "Transferencia bancaria", "Cheques"]
MEDIOS_PAGO_EN = ["Cash (bills and coins count)", "POS / Credit card", "Debit card", "Bank transfer", "Checks"]
MEDIO_EFECTIVO_ES = "Efectivo (arqueo de billetes y monedas)"
MEDIO_EFECTIVO_EN = "Cash (bills and coins count)"

# ============== HOJA CONTABLE (LIBRO DE CUENTAS) ==============
# Columnas: id_registro, fecha, detalle, tipo_gasto, ingreso, gastos, total_ingresos, total_gastos, saldo_actual
COLUMNAS_LEDGER = [
    "id_registro", "fecha", "detalle", "tipo_gasto", "ingreso", "gastos",
    "total_ingresos", "total_gastos", "saldo_actual"
]

def generar_id():
    """ID legacy: T-YYYYMMDDHHMMSS."""
    return datetime.now().strftime("T-%Y%m%d%H%M%S")

def generar_id_gasto():
    """ID único para registro de gastos: RG-AÑO-MES-DÍA-HORA-MINUTO-SEGUNDO."""
    return datetime.now().strftime("RG-%Y-%m-%d-%H-%M-%S")

def generar_id_arqueo():
    """ID único para arqueo de caja: AC-AÑO-MES-DÍA-HORA-MINUTO-SEGUNDO."""
    return datetime.now().strftime("AC-%Y-%m-%d-%H-%M-%S")

def _recalcular_totales_ledger(df):
    """Recalcula total_ingresos, total_gastos y saldo_actual por fila (acumulados). Montos siempre a 2 decimales."""
    if df.empty:
        return df
    ing = pd.to_numeric(df["ingreso"], errors="coerce").fillna(0).round(2)
    gas = pd.to_numeric(df["gastos"], errors="coerce").fillna(0).round(2)
    df = df.copy()
    df["total_ingresos"] = ing.cumsum()
    df["total_gastos"] = gas.cumsum()
    df["saldo_actual"] = df["total_ingresos"] - df["total_gastos"]
    return df

@st.cache_data(ttl=10)
def cargar_db():
    if not os.path.exists(DB_ARCHIVO):
        return pd.DataFrame(columns=COLUMNAS_LEDGER)
    try:
        df = pd.read_csv(DB_ARCHIVO, encoding="utf-8")
    except Exception:
        return pd.DataFrame(columns=COLUMNAS_LEDGER)
    # Si es formato antiguo, migrar a ledger
    if "id_registro" not in df.columns and "id" in df.columns:
        filas = []
        for _, r in df.iterrows():
            fecha = r.get("fecha_hora", r.get("fecha", ""))
            tid = r.get("id", "")
            tipo = str(r.get("tipo", "")).upper()
            try:
                monto = float(r.get("monto", 0) or 0)
            except (TypeError, ValueError):
                monto = 0.0
            if "BENDICIÓN" in tipo or "BENDICION" in tipo:
                detalle = str(r.get("ministerio", "Arqueo"))[:200]
                filas.append({"id_registro": tid, "fecha": fecha, "detalle": detalle, "tipo_gasto": "", "ingreso": monto, "gastos": 0})
            else:
                detalle = str(r.get("descripcion", "Gasto"))[:200]
                filas.append({"id_registro": tid, "fecha": fecha, "detalle": detalle, "tipo_gasto": DEFAULT_TIPO_GASTO, "ingreso": 0, "gastos": monto})
        df = pd.DataFrame(filas)
        df = _recalcular_totales_ledger(df)
    # Asegurar columna tipo_gasto en CSVs existentes sin ella
    if not df.empty and "tipo_gasto" not in df.columns:
        def _gastos_val(r):
            try:
                return float(r.get("gastos", 0) or 0) > 0
            except (TypeError, ValueError):
                return False
        df["tipo_gasto"] = df.apply(lambda r: DEFAULT_TIPO_GASTO if _gastos_val(r) else "", axis=1)
    if not df.empty and "ingreso" in df.columns:
        df = _recalcular_totales_ledger(df)
    return df


def verificar_integridad_ledger(df):
    """Comprueba que los totales acumulados de la última fila coincidan con la suma de movimientos. Devuelve (True, None) o (False, mensaje)."""
    if df is None or df.empty or "ingreso" not in df.columns or "gastos" not in df.columns:
        return True, None
    ing = pd.to_numeric(df["ingreso"], errors="coerce").fillna(0).round(2)
    gas = pd.to_numeric(df["gastos"], errors="coerce").fillna(0).round(2)
    sum_ing = round(ing.sum(), 2)
    sum_gas = round(gas.sum(), 2)
    ultima = df.iloc[-1]
    try:
        ti = round(float(ultima.get("total_ingresos", 0) or 0), 2)
        tg = round(float(ultima.get("total_gastos", 0) or 0), 2)
        sa = round(float(ultima.get("saldo_actual", 0) or 0), 2)
    except (TypeError, ValueError):
        return False, "Totales no numéricos en última fila."
    if abs(ti - sum_ing) > 0.02 or abs(tg - sum_gas) > 0.02:
        return False, f"Total ingresos esperado {sum_ing:.2f} vs {ti:.2f}; total gastos {sum_gas:.2f} vs {tg:.2f}."
    if abs(sa - (ti - tg)) > 0.02:
        return False, f"Saldo no coincide con total_ingresos - total_gastos."
    return True, None


def validar_datos(df):
    """Valida antes de guardar. Devuelve (True, None) o (False, mensaje_error). Detecta datos inválidos o posible manipulación."""
    if df is None or not isinstance(df, pd.DataFrame):
        return False, "Datos no válidos."
    for col in COLUMNAS_LEDGER:
        if col not in df.columns:
            return False, f"Falta la columna requerida: {col}"
    # Montos no negativos (conversión segura por si hay texto en CSV)
    for col in ["ingreso", "gastos", "total_ingresos", "total_gastos"]:
        if col in df.columns:
            num = pd.to_numeric(df[col], errors="coerce").fillna(0)
            if (num < -0.001).any():
                return False, f"Hay valores negativos no permitidos en {col}."
    # Detalle sin caracteres peligrosos (script, inyección)
    if "detalle" in df.columns:
        for v in df["detalle"].dropna().astype(str):
            if len(v) > 2000 or "<script" in v.lower() or "javascript:" in v.lower() or "<?php" in v.lower():
                return False, "Detalle con contenido no permitido o demasiado largo."
    # id_registro formato razonable
    if "id_registro" in df.columns:
        for v in df["id_registro"].dropna().astype(str):
            if len(v) > 80 or "\n" in v or "\r" in v:
                return False, "ID de registro con formato no permitido."
    # tipo_gasto longitud razonable (evitar abusos)
    if "tipo_gasto" in df.columns:
        for v in df["tipo_gasto"].dropna().astype(str):
            if len(v.strip()) > 120:
                return False, "Tipo de gasto/ingreso con texto demasiado largo."
    return True, None

def _respaldo_automatico():
    """Copia el CSV actual al historial con timestamp. Mantiene solo los últimos MAX_RESPALDOS."""
    if not os.path.exists(DB_ARCHIVO):
        return
    os.makedirs(CARPETA_HISTORIAL, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    destino = os.path.join(CARPETA_HISTORIAL, f"DB_{timestamp}.csv")
    try:
        shutil.copy2(DB_ARCHIVO, destino)
    except Exception:
        pass
    # Mantener solo los últimos MAX_RESPALDOS (solo archivos .csv)
    try:
        listados = sorted(
            [f for f in os.listdir(CARPETA_HISTORIAL) if f.endswith(".csv")],
            reverse=True
        )
        for f in listados[MAX_RESPALDOS:]:
            ruta = os.path.join(CARPETA_HISTORIAL, f)
            if os.path.isfile(ruta):
                os.remove(ruta)
    except Exception:
        pass

def listar_respaldos():
    """Lista archivos de respaldo en historial, más recientes primero. Devuelve lista de (ruta, etiqueta)."""
    if not os.path.isdir(CARPETA_HISTORIAL):
        return []
    out = []
    for f in sorted(os.listdir(CARPETA_HISTORIAL), reverse=True):
        if f.endswith(".csv"):
            ruta = os.path.join(CARPETA_HISTORIAL, f)
            if not os.path.isfile(ruta):
                continue
            try:
                mtime = os.path.getmtime(ruta)
                etiqueta = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                etiqueta = f
            out.append((ruta, etiqueta))
    return out[:MAX_RESPALDOS]

def restaurar_respaldo(ruta):
    """Restaura la base de datos desde un archivo de respaldo."""
    if not os.path.isfile(ruta) or not ruta.endswith(".csv"):
        return False
    try:
        shutil.copy2(ruta, DB_ARCHIVO)
        cargar_db.clear()
        return True
    except Exception:
        return False

def reiniciar_tesoreria_master():
    """Reinicia la tesorería: respalda el CSV actual en CARPETA_RESETS y deja el ledger vacío (solo estructura)."""
    os.makedirs(CARPETA_RESETS, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    destino = os.path.join(CARPETA_RESETS, f"DB_antes_reinicio_{timestamp}.csv")
    try:
        if os.path.exists(DB_ARCHIVO):
            shutil.copy2(DB_ARCHIVO, destino)
    except Exception:
        pass
    df_vacio = pd.DataFrame(columns=COLUMNAS_LEDGER)
    try:
        df_vacio.to_csv(DB_ARCHIVO, index=False, encoding="utf-8")
        cargar_db.clear()
        return True
    except Exception:
        return False

def guardar_db(df, t=None):
    """Guarda solo si los datos pasan validación. Crea respaldo automático tras guardar.
    t: diccionario de textos (TEXTOS[lang]) para mensajes traducidos; si es None se usa español."""
    df = _recalcular_totales_ledger(df) if not df.empty else df
    ok, mensaje = validar_datos(df)
    if not ok:
        st.error(t["error_validacion"].format(msg=mensaje) if t else mensaje)
        return False
    try:
        df.to_csv(DB_ARCHIVO, index=False, encoding="utf-8")
        _respaldo_automatico()
        cargar_db.clear()
        return True
    except Exception as e:
        st.error(t["error_no_se_pudo_guardar"].format(e=str(e)) if t else f"NO SE PUDO GUARDAR: {e}")
        return False


def _get_client_ip():
    """Obtiene la IP del dispositivo cliente. Solo visible para acceso maestro."""
    try:
        headers = getattr(st, "context", None) and getattr(st.context, "headers", None)
        if headers and isinstance(headers, dict):
            return (headers.get("X-Forwarded-For") or headers.get("X-Real-Ip") or "").split(",")[0].strip() or "N/A"
    except Exception:
        pass
    return "N/A"


def cargar_arqueo_meta():
    """Carga metadatos de arqueos (contado_por, verificado_por, ip, desglose, etc.)."""
    if not os.path.exists(DB_ARQUEO_META):
        return {}
    try:
        with open(DB_ARQUEO_META, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _nombres_arqueo_desde_meta(meta):
    """Extrae listas de nombres (mayúsculas) ordenados por frecuencia de uso (más usados primero)."""
    from collections import Counter
    contado_list = []
    verificado_list = []
    for rid, datos in (meta or {}).items():
        if rid.startswith("_"):
            continue
        if isinstance(datos, dict):
            c = (datos.get("contado_por") or "").strip().upper()
            v = (datos.get("verificado_por") or "").strip().upper()
            if c:
                contado_list.append(c)
            if v:
                verificado_list.append(v)
    cnt_c = Counter(contado_list)
    cnt_v = Counter(verificado_list)
    return [n for n, _ in cnt_c.most_common()], [n for n, _ in cnt_v.most_common()]


def _validar_nombre_arqueo(texto):
    """Valida que el nombre no sea solo números, tenga al menos 2 caracteres, ni caracteres inválidos. Devuelve (True, None) o (False, msg_key)."""
    t = (texto or "").strip()
    if not t:
        return True, None
    if len(t) < 2:
        return False, "arqueo_nombre_muy_corto"
    digitos = sum(1 for c in t if c.isdigit())
    if digitos >= len(t) * 0.5:
        return False, "arqueo_nombre_invalido"
    if any(c in t for c in "@#$%^&*()+={}[]|\\<>?"):
        return False, "arqueo_nombre_simbolos"
    return True, None


def _normalizar_y_coincidir(texto, lista_existentes):
    """Convierte a mayúsculas y si es similar a uno existente, devuelve el canonical. Reconoce inicial única si hay un solo match."""
    t = (texto or "").strip().upper()
    if not t:
        return ""
    if len(t) == 1 and lista_existentes:
        matches = [n for n in lista_existentes if n and len(n) > 0 and n[0].upper() == t]
        if len(matches) == 1:
            return matches[0]
    for existente in lista_existentes:
        if existente and (t == existente or (len(t) > 2 and t in existente) or (len(existente) > 2 and existente in t)):
            return existente
    try:
        import difflib
        for existente in lista_existentes:
            if existente and difflib.SequenceMatcher(None, t.lower(), existente.lower()).ratio() >= 0.85:
                return existente
    except Exception:
        pass
    return t


def guardar_arqueo_meta(meta):
    """Guarda metadatos de arqueos."""
    try:
        with open(DB_ARQUEO_META, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def cargar_suministros():
    """Carga lista de suministros por pagar (luz, agua, etc.) desde JSON."""
    if not os.path.exists(DB_SUMINISTROS):
        return ["Luz", "Agua", "Gas", "Internet", "Teléfono", "Seguro", "Calefacción", "Mantenimiento edificio", "Limpieza", "Otros suministros"]
    try:
        with open(DB_SUMINISTROS, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("suministros", []) or ["Luz", "Agua", "Gas", "Internet", "Teléfono", "Seguro", "Otros suministros"]
    except Exception:
        return ["Luz", "Agua", "Gas", "Internet", "Teléfono", "Seguro", "Otros suministros"]


def _gastos_frecuentes_desde_df(df, top_n=20):
    """Extrae los gastos más frecuentes del historial (por detalle normalizado)."""
    if df is None or df.empty or "gastos" not in df.columns or "detalle" not in df.columns:
        return []
    from collections import Counter
    gastos_df = df[df["gastos"] > 0].copy()
    if gastos_df.empty:
        return []
    detalles = gastos_df["detalle"].fillna("").astype(str).str.strip()
    detalles = detalles[detalles.str.len() > 2]
    detalles_limpios = []
    for d in detalles:
        if "(Aprobado por:" in d:
            d = d.split("(Aprobado por:")[0].strip().rstrip(")")
        if d and len(d) > 2:
            detalles_limpios.append(d[:80])
    cnt = Counter(detalles_limpios)
    return [nom for nom, _ in cnt.most_common(top_n)]


def _nombres_aprobado_desde_df(df, top_n=10):
    """Extrae nombres de 'Aprobado por: X' del historial de gastos, ordenados por frecuencia."""
    if df is None or df.empty or "detalle" not in df.columns:
        return []
    from collections import Counter
    import re
    nombres = []
    for det in df["detalle"].fillna("").astype(str):
        m = re.search(r"\(Aprobado por:\s*([^)]+)\)", det, re.IGNORECASE)
        if m:
            nom = m.group(1).strip().upper()
            if nom and len(nom) > 1:
                nombres.append(nom)
    cnt = Counter(nombres)
    return [n for n, _ in cnt.most_common(top_n)]


# ============== OCR Y FACTURAS (DETECCIÓN, DUPLICADOS, BÚSQUEDA) ==============
def _hash_imagen(bytes_imagen):
    """Hash SHA256 del contenido de la imagen para detectar duplicados."""
    return hashlib.sha256(bytes_imagen).hexdigest()


def _ocr_imagen(bytes_imagen):
    """Extrae texto de la imagen con OCR (Tesseract). Si no está instalado, devuelve ''.
    En Windows: instalar Tesseract-OCR y añadirlo al PATH, o definir pytesseract.pytesseract.tesseract_cmd."""
    try:
        import pytesseract
        from PIL import Image
        img = Image.open(BytesIO(bytes_imagen))
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        return pytesseract.image_to_string(img, lang="spa+eng").strip()
    except Exception:
        return ""


def _extraer_datos_factura(ocr_text):
    """A partir del texto OCR, extrae total, impuesto, subtotal, comercio, ítems y fecha.
    Usa expresiones mejoradas para TOTAL (gran total, total a pagar), IVA/TAX, subtotal y líneas con montos."""
    out = {"total": None, "impuesto": None, "subtotal": None, "comercio": "", "items": [], "fecha_texto": ""}
    if not (ocr_text and isinstance(ocr_text, str)):
        return out
    # Normalizar: coma -> punto; varias variantes de espacio
    text = ocr_text.replace(",", ".").replace("\r", "\n")
    text_upper = text.upper()
    lineas = [ln.strip() for ln in text.splitlines() if ln.strip()]

    # Montos: $1234.56, 1,234.56, 1234.56 (2 decimales), 1234 (entero)
    patron_monto = re.compile(r"(?:\$?\s*)(\d{1,3}(?:[.,]\d{3})*(?:\.\d{2})?|\d{1,6}(?:\.\d{2})?)")
    def _parse_monto(s):
        try:
            n = float(s.replace(",", "").replace(" ", ""))
            return n if n < 1e7 else None
        except (ValueError, TypeError):
            return None

    # --- TOTAL: varias formas (gran total, total a pagar, total general, TOTAL)
    total_candidates = []
    for ln in lineas:
        ln_upper = ln.upper().replace(",", ".")
        if re.search(r"\b(GRAN\s*)?TOTAL\b", ln_upper) or re.search(r"TOTAL\s*(A\s*PAGAR|GENERAL|FINAL)?\s*:?\s*$", ln_upper) or re.search(r"TOTAL\s*\$?", ln_upper):
            nums = [m for m in patron_monto.findall(ln) if _parse_monto(m) is not None]
            if nums:
                v = _parse_monto(nums[-1])
                if v is not None:
                    total_candidates.append(round(v, 2))
    if total_candidates:
        out["total"] = max(total_candidates)  # suele ser el mayor si hay varios

    # --- IVA / TAX / IMPUESTO
    for ln in lineas:
        ln_upper = ln.upper().replace(",", ".")
        if re.search(r"\b(IVA|TAX|IMPUESTO|HST|GST|VAT)\s*:?\s*", ln_upper):
            nums = [m for m in patron_monto.findall(ln) if _parse_monto(m) is not None]
            if nums and out["impuesto"] is None:
                out["impuesto"] = round(_parse_monto(nums[-1]), 2)
                break

    # --- SUBTOTAL
    for ln in lineas:
        ln_upper = ln.upper().replace(",", ".")
        if re.search(r"\b(SUBTOTAL|SUB\-TOTAL|SUB\s*TOTAL)\s*:?\s*", ln_upper):
            nums = [m for m in patron_monto.findall(ln) if _parse_monto(m) is not None]
            if nums:
                out["subtotal"] = round(_parse_monto(nums[-1]), 2)
                break
    if out["subtotal"] is None and out["total"] is not None and out["impuesto"] is not None:
        out["subtotal"] = round(out["total"] - out["impuesto"], 2)

    # --- Si aún no hay total, usar el monto más alto que parezca un total (p. ej. último monto grande)
    if out["total"] is None:
        todos_montos = []
        for ln in text_upper.splitlines():
            for m in patron_monto.findall(ln):
                v = _parse_monto(m)
                if v is not None and 0.01 <= v < 1e6:
                    todos_montos.append(round(v, 2))
        if todos_montos:
            out["total"] = max(todos_montos)

    # --- Comercio: primeras líneas que no son solo números ni "factura"/"receipt"
    for ln in lineas[:5]:
        ln_clean = ln.strip()[:200]
        if not re.match(r"^[\d\s\.\,\$\-\/]+$", ln_clean) and not re.search(r"^(FACTURA|RECEIPT|INVOICE|DATE|FECHA)\s*$", ln_clean, re.I):
            out["comercio"] = ln_clean
            break

    # --- Ítems: líneas que contienen descripción + monto al final (ej. "Cafe con leche    2.50")
    for ln in lineas:
        ln_norm = ln.replace(",", ".")
        # Buscar monto al final de la línea ($X.XX o X.XX)
        match_end = re.search(r"[\$]?\s*(\d{1,6}(?:\.\d{2})?)\s*$", ln_norm)
        if match_end:
            desc = ln_norm[:match_end.start()].strip()
            try:
                precio = round(float(match_end.group(1)), 2)
            except (ValueError, TypeError):
                continue
            if desc and len(desc) > 2 and 0.01 <= precio < 1e5 and (not out["items"] or len(out["items"]) < 30):
                out["items"].append({"desc": desc[:150], "precio": precio})

    # --- Fecha: 2024-01-15, 15/01/2024, 15-01-2024, Jan 15 2024
    fecha_match = re.search(r"(\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\d{2}-\d{2}-\d{4}|\d{1,2}\s+[A-Za-z]+\s+\d{4})", text)
    if fecha_match:
        out["fecha_texto"] = fecha_match.group(1).strip()
    return out


def cargar_facturas():
    """Carga DB_FACTURAS.json. Estructura: { hashes: { hash: id_registro }, facturas: [ {...} ] }."""
    if not os.path.exists(DB_FACTURAS):
        return {"hashes": {}, "facturas": []}
    try:
        with open(DB_FACTURAS, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"hashes": {}, "facturas": []}


def guardar_factura(registro):
    """Añade un registro de factura y actualiza el archivo. registro: id_registro, hash_imagen, ocr_text, total, impuesto, subtotal, comercio, tipo_gasto, items, fecha_factura, fecha_registro."""
    data = cargar_facturas()
    data.setdefault("hashes", {})
    data.setdefault("facturas", [])
    data["hashes"][registro.get("hash_imagen", "")] = registro.get("id_registro", "")
    data["facturas"].append(registro)
    try:
        with open(DB_FACTURAS, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def imagen_ya_subida(hash_imagen):
    """True si ese hash ya está registrado (evitar duplicados)."""
    data = cargar_facturas()
    return hash_imagen in data.get("hashes", {})


def _comprimir_imagen(bytes_imagen, max_ancho=None, calidad_jpeg=None):
    """Comprime la imagen para móvil: redimensiona si es muy grande y guarda como JPEG.
    Usa IMAGEN_COMPRIMIR_MAX_ANCHO y IMAGEN_COMPRIMIR_CALIDAD si no se pasan. Devuelve bytes del JPEG o los originales si falla."""
    if max_ancho is None:
        max_ancho = IMAGEN_COMPRIMIR_MAX_ANCHO
    if calidad_jpeg is None:
        calidad_jpeg = IMAGEN_COMPRIMIR_CALIDAD
    try:
        from PIL import Image
        img = Image.open(BytesIO(bytes_imagen))
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")
        elif img.mode != "RGB":
            img = img.convert("RGB")
        w, h = img.size
        if w > max_ancho or h > max_ancho:
            ratio = min(max_ancho / w, max_ancho / h)
            new_size = (int(w * ratio), int(h * ratio))
            img = img.resize(new_size, Image.Resampling.LANCZOS)
        buf = BytesIO()
        img.save(buf, format="JPEG", quality=calidad_jpeg, optimize=True)
        buf.seek(0)
        return buf.read()
    except Exception:
        return bytes_imagen


def _crear_zip_fotos_gastos():
    """Crea un ZIP con todas las fotos de la carpeta fotos_gastos. Devuelve (bytes_zip, nombre_archivo) o (None, None)."""
    import zipfile
    carpeta = "fotos_gastos"
    if not os.path.isdir(carpeta):
        return None, None
    nombres = [f for f in os.listdir(carpeta) if os.path.isfile(os.path.join(carpeta, f))]
    if not nombres:
        return None, None
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for n in nombres:
            ruta = os.path.join(carpeta, n)
            zf.write(ruta, n)
    buf.seek(0)
    nombre_zip = f"fotos_gastos_{datetime.now().strftime('%Y%m%d_%H%M')}.zip"
    return buf.getvalue(), nombre_zip


# ============== USUARIOS Y PERMISOS (ADMIN) ==============
def _permisos_default():
    return {
        "usuarios": {
            "admin": {"nombre": "Administrador", "permisos": ["*"]},
            "asistente": {"nombre": "Asistente", "permisos": ["ver_inicio", "ver_arqueo_caja"]},
            "tesorero": {"nombre": "Tesorero", "permisos": ["ver_inicio", "ver_arqueo_caja", "ver_tesoreria", "ver_contabilidad", "ver_ingresar_bendicion", "ver_registrar_gasto", "ver_hoja_contable", "ver_informe_pdf", "ver_exportar_hoja_pdf"]},
            "pastor": {"nombre": "Pastor", "permisos": ["ver_inicio", "ver_arqueo_caja", "ver_tesoreria", "ver_contabilidad", "ver_presupuesto_metas", "ver_ingresar_bendicion", "ver_registrar_gasto", "ver_hoja_contable", "ver_informe_pdf", "ver_exportar_hoja_pdf"]},
            "ministerio_musica": {"nombre": "Ministerio de Música", "permisos": ["ver_inicio", "ver_arqueo_caja", "ver_hoja_contable", "ver_informe_pdf"]},
        }
    }

@st.cache_data(ttl=30)
def cargar_permisos():
    if not os.path.exists(DB_PERMISOS):
        data = _permisos_default()
        try:
            with open(DB_PERMISOS, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
        return data
    try:
        with open(DB_PERMISOS, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return _permisos_default()
    # Validar estructura: debe tener "usuarios" como dict; cada usuario con "nombre" y "permisos"
    if not isinstance(data.get("usuarios"), dict):
        return _permisos_default()
    need_save = False
    for uid, info in list(data["usuarios"].items()):
        if not isinstance(info, dict):
            data["usuarios"][uid] = {"nombre": str(uid), "permisos": []}
            need_save = True
        else:
            if "nombre" not in info:
                data["usuarios"][uid]["nombre"] = str(uid)
                need_save = True
            if not isinstance(info.get("permisos"), list):
                data["usuarios"][uid]["permisos"] = []
                need_save = True
    # Migración: ver_ministerio_finanzas -> ver_arqueo_caja, ver_tesoreria, ver_contabilidad
    for uid, info in list(data.get("usuarios", {}).items()):
        perms = info.get("permisos", [])
        if "ver_ministerio_finanzas" in perms and "*" not in perms:
            perms.remove("ver_ministerio_finanzas")
            perms.extend(["ver_arqueo_caja", "ver_tesoreria", "ver_contabilidad"])
            data["usuarios"][uid]["permisos"] = list(set(perms))
            need_save = True
    # Añadir ministerio_musica si no existe (migración)
    default_musica = {"nombre": "Ministerio de Música", "permisos": ["ver_inicio", "ver_arqueo_caja", "ver_hoja_contable", "ver_informe_pdf"]}
    if "ministerio_musica" not in data.get("usuarios", {}):
        data["usuarios"]["ministerio_musica"] = default_musica
        need_save = True
    # Añadir asistente y pastor si no existen
    if "asistente" not in data.get("usuarios", {}):
        data["usuarios"]["asistente"] = {"nombre": "Asistente", "permisos": ["ver_inicio", "ver_arqueo_caja"]}
        need_save = True
    if "pastor" not in data.get("usuarios", {}):
        data["usuarios"]["pastor"] = {"nombre": "Pastor", "permisos": ["ver_inicio", "ver_arqueo_caja", "ver_tesoreria", "ver_contabilidad", "ver_presupuesto_metas", "ver_ingresar_bendicion", "ver_registrar_gasto", "ver_hoja_contable", "ver_informe_pdf", "ver_exportar_hoja_pdf"]}
        need_save = True
    if need_save:
        try:
            with open(DB_PERMISOS, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
    return data

def guardar_permisos(data, t=None):
    """Guarda permisos en JSON. Devuelve True si se guardó bien, False si hubo error. t: textos para i18n."""
    try:
        with open(DB_PERMISOS, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        cargar_permisos.clear()
        return True
    except Exception as e:
        st.error(t["error_no_se_pudo_guardar_permisos"].format(e=str(e)) if t else f"NO SE PUDO GUARDAR PERMISOS: {e}")
        return False

def tiene_permiso(usuario_id, permiso_clave):
    """True si el usuario tiene ese permiso (admin tiene todos)."""
    data = cargar_permisos()
    usuarios = data.get("usuarios", {})
    u = usuarios.get(usuario_id, {})
    permisos = u.get("permisos", [])
    if "*" in permisos or permiso_clave in permisos:
        return True
    return False

def toggle_permiso(usuario_id, permiso_clave, t=None):
    """Con un clic: si tiene permiso lo quita; si no lo tiene, lo da. t: textos para i18n."""
    if usuario_id == "admin":
        return  # admin no se modifica
    data = cargar_permisos()
    usuarios = data.get("usuarios", {})
    if usuario_id not in usuarios:
        return
    permisos = list(usuarios[usuario_id].get("permisos", []))
    if "*" in permisos:
        return  # no tocar admin
    if permiso_clave in permisos:
        permisos.remove(permiso_clave)
    else:
        permisos.append(permiso_clave)
    usuarios[usuario_id]["permisos"] = permisos
    data["usuarios"] = usuarios
    guardar_permisos(data, t)
    try:
        audit_log(st.session_state.get("usuario_actual", "?"), "permiso_cambiado", f"{usuario_id} {permiso_clave}")
    except Exception:
        pass

def puede_borrar(fecha_str):
    try:
        s = str(fecha_str).strip()
        if len(s) <= 10:
            dt = datetime.strptime(s[:10], "%Y-%m-%d")
        else:
            dt = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
        return (datetime.now() - dt).total_seconds() <= MINUTOS_BORRADO * 60
    except Exception:
        return False

def _calcular_alertas(total_ingresos, total_gastos, saldo, t):
    """Devuelve lista de alertas de crisis y nivel de riesgo (bajo/medio/alto)."""
    alertas = []
    if total_ingresos == 0 and total_gastos > 0:
        alertas.append(t["alerta_sin_ingresos"])
    if saldo < 0:
        alertas.append(t["alerta_saldo_negativo"])
    elif total_ingresos > 0 and total_gastos / total_ingresos >= 0.90:
        alertas.append(t["alerta_gastos_altos"])
    if saldo >= 0 and total_gastos > 0 and total_ingresos > 0:
        meses_reserva = saldo / total_gastos if total_gastos else 0
        if 0 < meses_reserva < 0.5:
            alertas.append(t["alerta_saldo_bajo"])
    # Riesgo
    if saldo < 0:
        nivel_riesgo = "alto"
    elif total_ingresos > 0 and total_gastos / total_ingresos >= 0.85:
        nivel_riesgo = "medio"
    elif total_ingresos == 0 and total_gastos > 0:
        nivel_riesgo = "alto"
    elif total_ingresos > 0 and saldo / total_ingresos < 0.1:
        nivel_riesgo = "medio"
    else:
        nivel_riesgo = "bajo"
    return alertas, nivel_riesgo

def _safe_float_pdf(x, default=0.0):
    """Convierte a float de forma segura para PDF (evita fallo con cadenas vacías o NaN)."""
    try:
        if x is None or (isinstance(x, float) and pd.isna(x)):
            return default
        return float(x)
    except (TypeError, ValueError):
        return default

def generar_pdf(df, lang, saldo, texto_arqueo):
    """Genera informe de auditoría contable: situación, alertas, presupuesto real, análisis, riesgo y recomendaciones."""
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    t = TEXTOS.get(lang, TEXTOS["ES"])
    total_ingresos = float(df["ingreso"].sum(skipna=True) or 0) if not df.empty else 0.0
    total_gastos = float(df["gastos"].sum(skipna=True) or 0) if not df.empty else 0.0
    saldo_val = saldo if pd.notna(saldo) else (total_ingresos - total_gastos)
    alertas, nivel_riesgo = _calcular_alertas(total_ingresos, total_gastos, saldo_val, t)
    # Presupuesto por tipo de gasto
    if not df.empty and "tipo_gasto" in df.columns:
        gastos_por_tipo = df[df["gastos"] > 0].groupby("tipo_gasto", dropna=False)["gastos"].sum()
        gastos_por_tipo = gastos_por_tipo[gastos_por_tipo.index.astype(str).str.strip() != ""]
        if gastos_por_tipo.empty:
            gastos_por_tipo = pd.Series({"Otros": total_gastos}) if total_gastos else pd.Series(dtype=float)
    else:
        gastos_por_tipo = pd.Series({"Otros": total_gastos}) if total_gastos else pd.Series(dtype=float)
    # --- Encabezado ---
    y = h - 1.5*cm
    c.setFont("Helvetica-Bold", 14)
    c.drawString(2*cm, y, t["informe_auditoria"])
    y -= 0.6*cm
    c.setFont("Helvetica", 9)
    c.drawString(2*cm, y, f"{t['fecha_informe']}: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    y -= 0.4*cm
    c.drawString(2*cm, y, t.get("direccion", DIRECCION_IGLESIA))
    y -= 0.5*cm
    c.drawString(2*cm, y, f"{t['arqueo']} (último): {texto_arqueo}" if isinstance(texto_arqueo, str) else f"{t['arqueo']}: {texto_arqueo}")
    y -= 0.8*cm
    # --- 1. SITUACIÓN ACTUAL ---
    c.setFont("Helvetica-Bold", 11)
    c.drawString(2*cm, y, t["situacion_actual"])
    y -= 0.5*cm
    c.setFont("Helvetica", 9)
    c.drawString(2*cm, y, f"{t['ingresos']}: ${total_ingresos:,.2f}")
    y -= 0.4*cm
    c.drawString(2*cm, y, f"{t['gastos']}: ${total_gastos:,.2f}")
    y -= 0.4*cm
    c.drawString(2*cm, y, f"{t['saldo']}: ${saldo_val:,.2f}")
    y -= 0.4*cm
    if saldo_val >= 0:
        c.drawString(2*cm, y, f"  → {t['superavit']}: ${saldo_val:,.2f}")
    else:
        c.drawString(2*cm, y, f"  → {t['deficit']}: ${abs(saldo_val):,.2f}")
    y -= 0.8*cm
    # --- 2. ALERTAS DE CRISIS ---
    c.setFont("Helvetica-Bold", 11)
    c.drawString(2*cm, y, t["alertas_crisis"])
    y -= 0.45*cm
    c.setFont("Helvetica", 8)
    if not alertas:
        c.drawString(2*cm, y, t["sin_alertas"])
    else:
        for a in alertas:
            c.drawString(2.5*cm, y, f"• {a[:75]}")
            y -= 0.38*cm
    y -= 0.5*cm
    # --- 3. PRESUPUESTO REAL ---
    c.setFont("Helvetica-Bold", 11)
    c.drawString(2*cm, y, t["presupuesto_real"])
    y -= 0.45*cm
    c.setFont("Helvetica", 8)
    if total_gastos > 0 and not gastos_por_tipo.empty:
        for tipo, monto in gastos_por_tipo.items():
            pct = (float(monto) / total_gastos * 100) if total_gastos else 0
            if tipo is None or (isinstance(tipo, float) and pd.isna(tipo)) or str(tipo).strip() in ("", "nan"):
                tipo_str = "Otros"
            else:
                tipo_str = str(tipo)[:22]
            c.drawString(2*cm, y, f"  {tipo_str}: ${float(monto):,.2f} ({pct:.0f}%)")
            y -= 0.38*cm
        c.drawString(2*cm, y, f"  {t['total']}: ${total_gastos:,.2f}")
    else:
        c.drawString(2*cm, y, f"  {t['total']} {t['gastos']}: $0.00")
    y -= 0.7*cm
    # --- 4. ANÁLISIS ---
    c.setFont("Helvetica-Bold", 11)
    c.drawString(2*cm, y, t["analisis_clinico"])
    y -= 0.45*cm
    c.setFont("Helvetica", 8)
    if lang == "ES":
        if saldo_val < 0:
            parrafo = "Las finanzas están en déficit. Los gastos superan a los ingresos. Se recomienda reducir gastos o aumentar ingresos de forma urgente para evitar mayor endeudamiento."
        elif total_ingresos > 0 and total_gastos / total_ingresos >= 0.85:
            parrafo = "El margen entre ingresos y gastos es estrecho. Cualquier imprevisto puede generar déficit. Conviene aumentar el ahorro y revisar gastos por categoría."
        elif saldo_val >= 0 and total_ingresos > 0:
            parrafo = "Situación estable: hay superávit. Se recomienda mantener control en gastos y destinar parte del excedente a reserva."
        else:
            parrafo = "Sin movimientos suficientes para análisis. Registre ingresos y gastos para obtener un diagnóstico claro."
    else:
        if saldo_val < 0:
            parrafo = "Finances are in deficit. Expenses exceed income. Reduce spending or increase income urgently."
        elif total_ingresos > 0 and total_gastos / total_ingresos >= 0.85:
            parrafo = "Narrow margin between income and expenses. Build savings and review spending by category."
        elif saldo_val >= 0 and total_ingresos > 0:
            parrafo = "Stable situation: surplus. Maintain spending control and allocate part of the surplus to reserves."
        else:
            parrafo = "Insufficient data. Record income and expenses for a clear diagnosis."
    for i in range(0, len(parrafo), 72):
        c.drawString(2*cm, y, parrafo[i:i+72])
        y -= 0.38*cm
    y -= 0.5*cm
    # --- 5. EVALUACIÓN DE RIESGO ---
    c.setFont("Helvetica-Bold", 11)
    c.drawString(2*cm, y, t["riesgo"])
    y -= 0.45*cm
    c.setFont("Helvetica", 9)
    riesgo_label = t["riesgo_alto"] if nivel_riesgo == "alto" else (t["riesgo_medio"] if nivel_riesgo == "medio" else t["riesgo_bajo"])
    c.drawString(2*cm, y, f"  → {riesgo_label}")
    y -= 0.7*cm
    # --- 6. RECOMENDACIONES ---
    c.setFont("Helvetica-Bold", 11)
    c.drawString(2*cm, y, t["recomendaciones"])
    y -= 0.45*cm
    c.setFont("Helvetica", 8)
    for key in ["recom_control_gastos", "recom_reserva", "recom_revisar", "recom_evitar_deficit"]:
        c.drawString(2*cm, y, t[key][:78])
        y -= 0.38*cm
    y -= 0.5*cm
    # --- 7. ÚLTIMOS MOVIMIENTOS ---
    c.setFont("Helvetica-Bold", 10)
    c.drawString(2*cm, y, t["ultimos_movimientos"])
    y -= 0.45*cm
    c.setFont("Helvetica", 7)
    for _, row in df.tail(18).iterrows():
        if y < 2*cm:
            c.showPage()
            y = h - 1.5*cm
        ing = _safe_float_pdf(row.get("ingreso"))
        gas = _safe_float_pdf(row.get("gastos"))
        det = str(row.get("detalle", "") or "")[:20]
        tipo = str(row.get("tipo_gasto", "") or "")[:8]
        linea = f"{str(row.get('fecha',''))[:10]} | {tipo} | {det} | ${ing:.2f} | ${gas:.2f}"
        c.drawString(2*cm, y, linea[:85])
        y -= 0.36*cm
    c.save()
    buf.seek(0)
    return buf

def generar_pdf_hoja_contable(df, lang):
    """Genera PDF de la hoja contable con columnas: ID, Fecha, Detalle, Tipo, Ingreso, Gastos, Totales, Saldo."""
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    t = TEXTOS.get(lang, TEXTOS["ES"])
    c.setFont("Helvetica-Bold", 14)
    c.drawString(2*cm, h - 1.5*cm, t["informe_pdf"] + " - HOJA CONTABLE")
    c.setFont("Helvetica", 9)
    c.drawString(2*cm, h - 2*cm, f"{t['fecha_informe']}: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    c.drawString(2*cm, h - 2.4*cm, t.get("direccion", DIRECCION_IGLESIA))
    headers = [t["col_id_registro"], t["col_fecha"], t["col_detalle"], t["col_tipo_gasto"], t["col_ingreso"], t["col_gastos"], t["col_total_ingresos"], t["col_total_gastos"], t["col_saldo_actual"]]
    col_widths = [2*cm, 2.2*cm, 3.2*cm, 2.2*cm, 1.6*cm, 1.6*cm, 1.6*cm, 1.6*cm, 1.6*cm]
    x = 1*cm
    c.setFont("Helvetica-Bold", 8)
    for i, (header, cw) in enumerate(zip(headers, col_widths)):
        c.drawString(x, h - 2.9*cm, header[:14])
        x += cw
    y = h - 3.2*cm
    c.setFont("Helvetica", 7)
    for _, row in df.iterrows():
        if y < 1.5*cm:
            c.showPage()
            y = h - 2*cm
            x = 1*cm
            for header, cw in zip(headers, col_widths):
                c.drawString(x, y, header[:14])
                x += cw
            y -= 0.4*cm
        x = 1*cm
        ing = _safe_float_pdf(row.get("ingreso"))
        gas = _safe_float_pdf(row.get("gastos"))
        tot_ing = _safe_float_pdf(row.get("total_ingresos"))
        tot_gas = _safe_float_pdf(row.get("total_gastos"))
        sal = _safe_float_pdf(row.get("saldo_actual"))
        det = str(row.get("detalle", "") or "")[:14]
        tipo = str(row.get("tipo_gasto", "") or "")[:10]
        c.drawString(x, y, str(row.get("id_registro", ""))[:10])
        x += col_widths[0]
        c.drawString(x, y, str(row.get("fecha", ""))[:10])
        x += col_widths[1]
        c.drawString(x, y, det)
        x += col_widths[2]
        c.drawString(x, y, tipo)
        x += col_widths[3]
        c.drawString(x, y, f"${ing:.2f}")
        x += col_widths[4]
        c.drawString(x, y, f"${gas:.2f}")
        x += col_widths[5]
        c.drawString(x, y, f"${tot_ing:.2f}")
        x += col_widths[6]
        c.drawString(x, y, f"${tot_gas:.2f}")
        x += col_widths[7]
        c.drawString(x, y, f"${sal:.2f}")
        y -= 0.4*cm
    c.save()
    buf.seek(0)
    return buf

def _formatear_excel_contador(buf):
    """Ajusta anchos de columna y formato de moneda en el Excel exportado para el contador."""
    try:
        from openpyxl import load_workbook
        from openpyxl.utils import get_column_letter
        buf.seek(0)
        wb = load_workbook(buf)
        ws = wb.active
        for col_idx, column_cells in enumerate(ws.columns, 1):
            max_len = max(len(str(cell.value or "")) for cell in column_cells)
            width = min(max(max_len * 1.15, 10), 50)
            ws.column_dimensions[get_column_letter(col_idx)].width = width
        for row in ws.iter_rows(min_row=2, max_row=ws.max_row, min_col=5, max_col=9):
            for cell in row:
                if cell.value is not None and isinstance(cell.value, (int, float)):
                    cell.number_format = '#,##0.00'
        buf_out = BytesIO()
        wb.save(buf_out)
        buf_out.seek(0)
        return buf_out.getvalue()
    except Exception:
        buf.seek(0)
        return buf.getvalue()


def generar_pdf_hoja_arqueo(datos_arqueo, lang):
    """Genera PDF compacto de hoja de arqueo para WhatsApp (comprimido, abre en cualquier dispositivo)."""
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4, pageCompression=1)
    w, h = A4
    t = TEXTOS.get(lang, TEXTOS["ES"])
    c.setFont("Helvetica-Bold", 12)
    c.drawString(2*cm, h - 1.2*cm, "HOJA DE ARQUEO - " + (datos_arqueo.get("fecha", "")[:16] or datetime.now().strftime("%Y-%m-%d %H:%M")))
    c.setFont("Helvetica", 8)
    c.drawString(2*cm, h - 1.6*cm, t.get("direccion", DIRECCION_IGLESIA)[:60])
    y = h - 2.2*cm
    desglose = datos_arqueo.get("desglose", {})
    if desglose:
        c.setFont("Helvetica-Bold", 9)
        c.drawString(2*cm, y, "Billetes:")
        y -= 0.4*cm
        c.setFont("Helvetica", 8)
        for denom, key, val in [("$100", "b100", 100), ("$50", "b50", 50), ("$20", "b20", 20), ("$10", "b10", 10), ("$5", "b5", 5)]:
            cant = desglose.get(key, 0) or 0
            if cant:
                c.drawString(2*cm, y, f"  {denom}: {cant} = ${cant * val:.2f}")
                y -= 0.35*cm
        c.setFont("Helvetica-Bold", 9)
        c.drawString(2*cm, y, "Monedas:")
        y -= 0.4*cm
        c.setFont("Helvetica", 8)
        for denom, key, val in [("$2", "m2", 2), ("$1", "m1", 1), ("$0.25", "m025", 0.25), ("$0.10", "m010", 0.10), ("$0.05", "m005", 0.05)]:
            cant = desglose.get(key, 0) or 0
            if cant:
                c.drawString(2*cm, y, f"  {denom}: {cant} = ${cant * val:.2f}")
                y -= 0.35*cm
    total_efectivo = datos_arqueo.get("total_efectivo", 0) or 0
    total_cheques = datos_arqueo.get("total_cheques", 0) or 0
    total_pos = datos_arqueo.get("total_pos", 0) or 0
    sobres_tot = datos_arqueo.get("sobres_tot", 0) or 0
    total = datos_arqueo.get("total", 0) or total_efectivo + total_cheques + total_pos + sobres_tot
    if sobres_tot:
        y -= 0.3*cm
        c.setFont("Helvetica", 8)
        c.drawString(2*cm, y, f"Sobres: {datos_arqueo.get('sobres_cant', 0)} = ${float(sobres_tot):.2f}")
    if total_cheques:
        y -= 0.35*cm
        c.setFont("Helvetica", 8)
        c.drawString(2*cm, y, f"Cheques: {datos_arqueo.get('cheques_cant', 0)} = ${float(total_cheques):.2f}")
    y -= 0.3*cm
    c.setFont("Helvetica-Bold", 10)
    c.drawString(2*cm, y, f"TOTAL: ${float(total):.2f}")
    y -= 0.5*cm
    c.setFont("Helvetica", 8)
    contado = datos_arqueo.get("contado_por", "") or "-"
    verif = datos_arqueo.get("verificado_por", "") or "-"
    c.drawString(2*cm, y, f"Contado por: {contado[:40]}")
    y -= 0.35*cm
    c.drawString(2*cm, y, f"Verificado por: {verif[:40]}")
    c.save()
    buf.seek(0)
    return buf.getvalue()


def generar_excel_hoja_arqueo(datos_arqueo, lang):
    """Genera Excel compacto de hoja de arqueo para WhatsApp (comprimido, abre en cualquier dispositivo)."""
    try:
        t = TEXTOS.get(lang, TEXTOS["ES"])
        filas = [["HOJA DE ARQUEO", ""], ["Fecha", datos_arqueo.get("fecha", datetime.now().strftime("%Y-%m-%d %H:%M"))]]
        desglose = datos_arqueo.get("desglose", {})
        if desglose:
            filas.append(["Billetes", ""])
            for denom, key in [("$100", "b100"), ("$50", "b50"), ("$20", "b20"), ("$10", "b10"), ("$5", "b5")]:
                filas.append([denom, desglose.get(key, 0)])
            filas.append(["Monedas", ""])
            for denom, key in [("$2", "m2"), ("$1", "m1"), ("$0.25", "m025"), ("$0.10", "m010"), ("$0.05", "m005")]:
                filas.append([denom, desglose.get(key, 0)])
        if datos_arqueo.get("sobres_cant") or datos_arqueo.get("sobres_tot"):
            filas.append(["Sobres (cant)", datos_arqueo.get("sobres_cant", 0)])
            filas.append(["Sobres (total $)", datos_arqueo.get("sobres_tot", 0)])
        if datos_arqueo.get("cheques_cant") or datos_arqueo.get("total_cheques"):
            filas.append(["Cheques (cant)", datos_arqueo.get("cheques_cant", 0)])
            filas.append(["Cheques (total $)", datos_arqueo.get("total_cheques", 0)])
        total = datos_arqueo.get("total", 0) or 0
        filas.append(["TOTAL", total])
        filas.append(["Contado por", datos_arqueo.get("contado_por", "")])
        filas.append(["Verificado por", datos_arqueo.get("verificado_por", "")])
        df = pd.DataFrame(filas)
        buf = BytesIO()
        df.to_excel(buf, index=False, header=False, engine="openpyxl")
        buf.seek(0)
        return buf.getvalue()
    except Exception:
        return b""


# ============== PÁGINA PRINCIPAL ==============
def main():
    if "idioma" not in st.session_state:
        st.session_state["idioma"] = "ES"
    if "pagina" not in st.session_state:
        st.session_state["pagina"] = "inicio"
    if "usuario_actual" not in st.session_state:
        st.session_state["usuario_actual"] = "admin"
    if "logueado" not in st.session_state:
        st.session_state["logueado"] = False
    if "tema_app" not in st.session_state:
        st.session_state["tema_app"] = "oscuro"

    lang = st.session_state.get("idioma", "ES")
    t = TEXTOS.get(lang, TEXTOS["ES"])

    # ----- PANTALLA DE LOGIN (puerta de acceso): si no está logueado, mostrar solo esto -----
    if not st.session_state.get("logueado"):
        _render_pantalla_login()
        return

    # ----- PRIMERA VEZ admin/admin: obligatorio cambiar contraseña antes de continuar -----
    if st.session_state.get("debe_cambiar_credenciales") and st.session_state.get("usuario_actual") == "admin":
        _render_pantalla_cambiar_credenciales()
        return

    # Timeout por inactividad: si pasaron más de MINUTOS_INACTIVIDAD, quitar autorización (salvo si "Recordar sesión")
    now = time.time()
    last = st.session_state.get("last_activity", now)
    if not st.session_state.get("recordar_sesion", False):
        if last and (now - last) > MINUTOS_INACTIVIDAD * 60:
            if st.session_state.get("admin_autorizado"):
                audit_log(st.session_state.get("usuario_actual", "?"), "sesion_expirada_inactividad", "")
            st.session_state["admin_autorizado"] = False
    st.session_state["last_activity"] = now
    st.set_page_config(
        page_title=t["titulo"],
        page_icon="⛪",
        layout="wide",
        initial_sidebar_state=st.session_state.get("sidebar_state", "collapsed")
    )

    # PWA: meta tags para que se pueda "instalar" como app (Netflix/Disney style) y compartir link por WhatsApp
    _theme_color = "#1a365d" if st.session_state.get("tema_app", "oscuro") == "claro" else "#0d1b2a"
    st.markdown(f"""
    <script>
    (function() {{
      var meta = document.createElement('meta');
      meta.name = 'viewport';
      meta.content = 'width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover';
      if (document.head) document.head.appendChild(meta);
      var theme = document.createElement('meta');
      theme.name = 'theme-color';
      theme.content = '{_theme_color}';
      if (document.head) document.head.appendChild(theme);
      var apple = document.createElement('meta');
      apple.name = 'apple-mobile-web-app-capable';
      apple.content = 'yes';
      if (document.head) document.head.appendChild(apple);
      var appleStatus = document.createElement('meta');
      appleStatus.name = 'apple-mobile-web-app-status-bar-style';
      appleStatus.content = 'black-translucent';
      if (document.head) document.head.appendChild(appleStatus);
      var link = document.createElement('link');
      link.rel = 'manifest';
      link.href = '/app/static/manifest.webmanifest';
      if (document.head) document.head.appendChild(link);
    }})();
    </script>
    """, unsafe_allow_html=True)

    # Estilo: menú última generación + tema (oscuro/claro)
    tema_app = st.session_state.get("tema_app", "oscuro")
    if tema_app == "claro":
        bg_main = "linear-gradient(180deg, #e8eef5 0%, #d1dce8 50%, #b8c9d9 100%)"
        txt_main = "#1a365d"
        btn_txt = "#1a365d"
        btn_bg = "rgba(26, 54, 93, 0.15)"
        input_bg = "rgba(255,255,255,0.95)"
        input_color = "#1a365d"
        sidebar_bg = "linear-gradient(180deg, #c5d4e4 0%, #a8bdd4 50%, #8fa9c2 100%)"
        sidebar_txt = "#1a365d"
        sidebar_txt_muted = "rgba(26,54,93,0.7)"
        menu_bg = "rgba(26,54,93,0.12)"
        menu_bg_hover = "rgba(26,54,93,0.2)"
        checkbox_border = "rgba(26,54,93,0.3)"
        checkbox_unchecked_color = "#b91c1c"
        checkbox_unchecked_border = "#dc2626"
        checkbox_checked_color = "#15803d"
        checkbox_checked_border = "#22c55e"
        active_menu_bg = "linear-gradient(135deg, rgba(26,54,93,0.3) 0%, rgba(26,54,93,0.45) 100%)"
        active_menu_txt = "#1a365d"
    else:
        bg_main = f"linear-gradient(180deg, #0a1220 0%, {AZUL_OSCURO} 50%, #132238 100%)"
        txt_main = "#FFFFFF"
        btn_txt = "#FFFFFF"
        btn_bg = "rgba(44, 48, 56, 0.25)"
        input_bg = "rgba(30, 40, 55, 0.4)"
        input_color = "#FFFFFF"
        sidebar_bg = f"linear-gradient(180deg, #0a1220 0%, {AZUL_OSCURO} 40%, #0d2238 100%)"
        sidebar_txt = "#FFFFFF"
        sidebar_txt_muted = "rgba(255,255,255,0.7)"
        menu_bg = "rgba(255,255,255,0.08)"
        menu_bg_hover = "rgba(255,255,255,0.15)"
        checkbox_border = "rgba(255,255,255,0.2)"
        checkbox_unchecked_color = "#fca5a5"
        checkbox_unchecked_border = "#ef4444"
        checkbox_checked_color = "#86efac"
        checkbox_checked_border = "#22c55e"
        active_menu_bg = "linear-gradient(135deg, #132238 0%, #1a2942 100%)"
        active_menu_txt = "#FFFFFF"
    st.markdown(f"""
    <style>
    .stApp, [data-testid="stAppViewContainer"], .main .block-container {{
        background: {bg_main} !important;
    }}
    .main {{
        background-color: transparent !important;
    }}
    h1, h2, h3, h4, h5, h6, p, .stMarkdown {{
        font-family: Calibri, 'Segoe UI', sans-serif !important;
        color: {txt_main} !important;
    }}
    /* Botones REGISTRAR (arqueo y gastos): metálicos 3D, bordes transparentes */
    .main .stButton > button,
    .main form [data-testid="stFormSubmitButton"] > button,
    .main [data-testid="stDownloadButton"] > button {{
        width: 100%;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-family: Calibri, 'Segoe UI', sans-serif !important;
        font-size: 1.8rem !important;
        padding: 1rem 2rem !important;
        min-height: 3.2rem !important;
        background: linear-gradient(180deg, rgba(70,78,90,0.98) 0%, rgba(45,52,62,0.98) 50%, rgba(30,36,44,0.98) 100%) !important;
        color: {btn_txt} !important;
        border: 1px solid transparent !important;
        border-radius: 12px !important;
        font-weight: bold !important;
        letter-spacing: 0.02em !important;
        text-align: center !important;
        box-shadow: 0 0 18px rgba(91,155,213,0.25),
                    6px 8px 20px rgba(0,0,0,0.5),
                    3px 4px 12px rgba(0,0,0,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.1) !important;
        transition: transform 0.2s ease, box-shadow 0.2s ease !important;
    }}
    .main .stButton > button:hover,
    .main form [data-testid="stFormSubmitButton"] > button:hover,
    .main [data-testid="stDownloadButton"] > button:hover {{
        background: linear-gradient(180deg, rgba(80,88,100,0.98) 0%, rgba(55,62,72,0.98) 50%, rgba(40,46,54,0.98) 100%) !important;
        transform: translateY(-3px) !important;
        box-shadow: 0 0 24px rgba(91,155,213,0.35),
                    8px 12px 28px rgba(0,0,0,0.55),
                    4px 6px 16px rgba(0,0,0,0.45),
                    inset 0 1px 0 rgba(255,255,255,0.15) !important;
    }}
    .main .stButton > button:active,
    .main form [data-testid="stFormSubmitButton"] > button:active,
    .main [data-testid="stDownloadButton"] > button:active {{
        transform: translateY(1px) !important;
        box-shadow: 0 2px 8px rgba(0,0,0,0.5), inset 0 2px 4px rgba(0,0,0,0.3) !important;
    }}
    div[data-testid="stVerticalBlock"] > div {{
        background-color: transparent !important;
        border-radius: 10px !important;
        padding: 0.6rem 0.4rem !important;
        box-shadow: 0 4px 15px rgba(0,0,0,0.15) !important;
    }}
    .big-label {{
        font-family: Calibri, 'Segoe UI', sans-serif !important;
        font-size: 1.4rem !important;
        font-weight: bold !important;
        color: {txt_main} !important;
        background-color: transparent !important;
        padding: 0.4rem 0.6rem !important;
        border-radius: 8px !important;
    }}
    .total-box {{
        font-family: Calibri, 'Segoe UI', sans-serif !important;
        font-size: 2rem !important;
        font-weight: bold !important;
        padding: 1rem;
        background-color: transparent !important;
        color: {txt_main} !important;
        border-radius: 8px;
        text-align: center;
        box-shadow: 0 6px 20px rgba(0,0,0,0.2) !important;
    }}
    /* Etiquetas con $ (billetes/monedas): más grandes y centradas */
    div[data-testid="stNumberInput"] label {{
        font-size: 1.7rem !important;
        font-weight: bold !important;
        text-align: center !important;
        display: block !important;
        width: 100% !important;
    }}
    div[data-testid="stNumberInput"] > div {{
        display: flex !important;
        flex-direction: column !important;
        align-items: center !important;
    }}
    /* Campos de monto: sin bordes rojos, borde azul; al pasar mouse verde ganancia y elevación */
    .main input[type="number"],
    .main input[type="text"] {{
        font-family: Calibri, 'Segoe UI', sans-serif !important;
        font-size: 1.3rem !important;
        padding: 0.6rem !important;
        background-color: {input_bg} !important;
        color: {input_color} !important;
        border: 2px solid {AZUL_OSCURO} !important;
        border-radius: 8px !important;
        outline: none !important;
        box-shadow: 4px 4px 12px rgba(0,0,0,0.4),
                    2px 2px 6px rgba(0,0,0,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.06) !important;
        transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease, background-color 0.2s ease !important;
    }}
    .main input[type="number"]:hover,
    .main input[type="text"]:hover {{
        transform: translateY(-3px) !important;
        border-color: #22c55e !important;
        background-color: rgba(34, 197, 94, 0.15) !important;
        box-shadow: 6px 8px 20px rgba(0,0,0,0.5),
                    3px 4px 10px rgba(0,0,0,0.4),
                    0 0 0 2px rgba(34, 197, 94, 0.3),
                    inset 0 1px 0 rgba(255,255,255,0.08) !important;
    }}
    .main input[type="number"]:focus,
    .main input[type="text"]:focus {{
        outline: none !important;
        border-color: {AZUL_OSCURO} !important;
        box-shadow: 5px 6px 16px rgba(0,0,0,0.45),
                    2px 3px 8px rgba(0,0,0,0.35),
                    inset 0 1px 0 rgba(255,255,255,0.08) !important;
    }}
    .main input[type="number"]:invalid,
    .main input[type="text"]:invalid {{
        border-color: {AZUL_OSCURO} !important;
        outline: none !important;
    }}
    /* Quitar cualquier borde/outline rojo que Streamlit aplique por defecto */
    .main div[data-testid="stNumberInput"] input {{
        border-color: {AZUL_OSCURO} !important;
        outline: none !important;
    }}
    .main div[data-testid="stNumberInput"] input:focus {{
        border-color: {AZUL_OSCURO} !important;
        outline: none !important;
    }}
    [data-testid="stSelectbox"] label, [data-testid="stRadio"] label {{
        font-family: Calibri, 'Segoe UI', sans-serif !important;
        color: {txt_main} !important;
    }}
    div[data-testid="stNumberInput"] label {{
        color: {txt_main} !important;
    }}
    .stSuccess, .stAlert, .stException, .stWarning, [data-testid="stException"] {{
        background-color: transparent !important;
        color: {txt_main} !important;
        font-family: Calibri, 'Segoe UI', sans-serif !important;
    }}
    [data-testid="stExpander"] {{
        background-color: transparent !important;
        border-radius: 8px !important;
    }}
    [data-testid="stExpander"] summary {{
        color: {txt_main} !important;
        font-family: Calibri, 'Segoe UI', sans-serif !important;
    }}
    [data-testid="stVerticalBlock"] {{
        background-color: transparent !important;
    }}
    .main .stCaption, .main [data-testid="stCaption"] {{
        color: {txt_main} !important;
    }}
    .main label {{
        color: {txt_main} !important;
    }}
    /* Métricas (saldo, ingresos, gastos): color según tema */
    div[data-testid="metric-container"], div[data-testid="stMetric"] label, div[data-testid="stMetric"] div {{
        color: {txt_main} !important;
    }}
    /* Dataframe / tabla: texto según tema */
    .main div[data-testid="stDataFrame"] *, .main [data-testid="stDataFrame"] td, .main [data-testid="stDataFrame"] th {{
        color: {txt_main} !important;
    }}
    /* Menú lateral última generación */
    section[data-testid="stSidebar"] {{
        background: {sidebar_bg} !important;
        box-shadow: 4px 0 24px rgba(0,0,0,0.4) !important;
    }}
    section[data-testid="stSidebar"] div[data-testid="stImage"] img {{
        max-height: 120px !important;
        width: auto !important;
        object-fit: contain !important;
    }}
    section[data-testid="stSidebar"] .stRadio > label,
    section[data-testid="stSidebar"] .stSelectbox label,
    section[data-testid="stSidebar"] label {{
        font-size: 0.9rem !important;
        color: {sidebar_txt} !important;
    }}
    .menu-item {{
        display: block;
        width: 100%;
        padding: 1rem 1.2rem;
        margin: 0.35rem 0;
        border-radius: 12px;
        font-family: Calibri, 'Segoe UI', sans-serif !important;
        font-size: 1.1rem !important;
        font-weight: bold;
        color: {sidebar_txt};
        background: {menu_bg};
        border: 1px solid {sidebar_txt_muted};
        text-align: center;
        cursor: pointer;
        transition: all 0.25s ease;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    }}
    .menu-item:hover {{
        background: {menu_bg_hover};
        border-color: {sidebar_txt_muted};
        transform: translateX(4px);
        box-shadow: 0 4px 16px rgba(0,0,0,0.3);
    }}
    .menu-item.active {{
        background: {active_menu_bg};
        color: {active_menu_txt} !important;
        border-color: {sidebar_txt_muted};
        box-shadow: 0 4px 20px rgba(0,0,0,0.35);
    }}
    .menu-seccion {{
        font-size: 0.75rem;
        color: {sidebar_txt_muted};
        text-transform: uppercase;
        letter-spacing: 0.12em;
        margin: 1.2rem 0 0.5rem 0;
        padding-left: 0.5rem;
    }}
    section[data-testid="stSidebar"] .stButton > button {{
        width: 100% !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        padding: 1rem 1.2rem !important;
        border-radius: 12px !important;
        font-family: Calibri, 'Segoe UI', sans-serif !important;
        font-size: 1.05rem !important;
        font-weight: bold !important;
        background: linear-gradient(180deg, rgba(55,65,78,0.9) 0%, rgba(35,42,52,0.9) 50%, rgba(25,30,38,0.9) 100%) !important;
        color: {sidebar_txt} !important;
        border: 1px solid transparent !important;
        text-align: center !important;
        transition: transform 0.2s ease, box-shadow 0.2s ease !important;
        box-shadow: 0 0 12px rgba(91,155,213,0.2),
                    4px 6px 14px rgba(0,0,0,0.45),
                    2px 4px 8px rgba(0,0,0,0.35),
                    inset 0 1px 0 rgba(255,255,255,0.08) !important;
    }}
    section[data-testid="stSidebar"] .stCaption,
    section[data-testid="stSidebar"] [data-testid="stMarkdown"] {{
        color: {sidebar_txt} !important;
    }}
    section[data-testid="stSidebar"] .stButton > button:hover {{
        background: linear-gradient(180deg, rgba(65,75,88,0.95) 0%, rgba(45,52,62,0.95) 50%, rgba(35,40,48,0.95) 100%) !important;
        transform: translateX(4px) translateY(-2px) !important;
        box-shadow: 0 0 18px rgba(91,155,213,0.3),
                    5px 8px 18px rgba(0,0,0,0.55),
                    3px 5px 10px rgba(0,0,0,0.45),
                    inset 0 1px 0 rgba(255,255,255,0.12) !important;
    }}
    </style>
    """, unsafe_allow_html=True)
    if st.session_state.get("tamano_fuente") == "grande":
        st.markdown("""<style>.main .block-container, .main p, .main .stMarkdown, .main label { font-size: 1.12rem !important; }</style>""", unsafe_allow_html=True)
    # Forzar desactivación de "Saved info" / autocompletado del navegador (Chrome, Edge, etc.)
    st.markdown("""
    <script>
    (function(){
      var meta = document.createElement('meta');
      meta.name = 'autocomplete';
      meta.content = 'off';
      if (document.head) document.head.appendChild(meta);
      function forceNoAutofill(el) {
        if (!el || el._autofillDisabled) return;
        el.setAttribute('autocomplete', 'off');
        el.setAttribute('autocapitalize', 'off');
        el.setAttribute('autocorrect', 'off');
        el.setAttribute('data-lpignore', 'true');
        el.setAttribute('data-form-type', 'other');
        el.setAttribute('name', 'field_' + Math.random().toString(36).slice(2));
        el._autofillDisabled = true;
      }
      function desactivarAutofill() {
        try {
          var inputs = document.querySelectorAll('input[type="number"], input[type="text"]');
          inputs.forEach(forceNoAutofill);
        } catch(e) {}
      }
      function run() {
        desactivarAutofill();
        try {
          var root = document.body || document.documentElement;
          var obs = new MutationObserver(function() { setTimeout(desactivarAutofill, 50); });
          obs.observe(root, { childList: true, subtree: true });
        } catch(e) {}
      }
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', run);
      } else {
        run();
      }
      [100, 300, 600, 1200, 2500].forEach(function(ms) { setTimeout(desactivarAutofill, ms); });
    })();
    </script>
    """, unsafe_allow_html=True)

    # ----- MENÚ LATERAL (última generación) -----
    usuario_actual = st.session_state.get("usuario_actual", "admin")
    data_permisos = cargar_permisos()
    lista_usuarios = list(data_permisos.get("usuarios", {}).keys()) or ["admin"]

    with st.sidebar:
        st.markdown(f"<p class='menu-seccion' style='text-align:center; margin-bottom:0.3rem;'>{t['ministerio_finanzas']}</p>", unsafe_allow_html=True)
        if os.path.exists(LOGO_PRINCIPAL):
            st.image(LOGO_PRINCIPAL, use_container_width=True)
        st.markdown("---")
        lang = st.radio(
            t["idioma"],
            options=["ES", "EN"],
            format_func=lambda x: "ESPAÑOL" if x == "ES" else "ENGLISH",
            key="idioma"
        )
        t = TEXTOS[lang]
        ministerios = MINISTERIOS if lang == "ES" else MINISTERIOS_EN
        st.markdown("---")
        st.markdown(f"<p class='menu-seccion'>{t['usuario_actual_menu']}</p>", unsafe_allow_html=True)
        sel_usuario = st.selectbox(
            t["quien_usa_app"],
            options=lista_usuarios,
            index=lista_usuarios.index(usuario_actual) if usuario_actual in lista_usuarios else 0,
            format_func=lambda uid: data_permisos["usuarios"].get(uid, {}).get("nombre", uid),
            key="sel_usuario"
        )
        # Si eligió admin pero hace falta PIN, no cambiar usuario hasta que lo ingrese
        if sel_usuario != usuario_actual:
            if sel_usuario == "admin" and _pin_admin_requerido() and not st.session_state.get("admin_autorizado"):
                pass  # mostrar formulario PIN abajo
            else:
                st.session_state["usuario_actual"] = sel_usuario
                if sel_usuario != "admin":
                    st.session_state["admin_autorizado"] = False
                st.session_state["sidebar_state"] = "expanded"
                st.rerun()
        # PIN de administrador
        if sel_usuario == "admin" and _pin_admin_requerido() and not st.session_state.get("admin_autorizado"):
            pin_ingresado = st.text_input(t["pin_ingrese"], type="password", key="pin_admin_input")
            if st.button(t["entrar"], key="btn_pin_entrar") and pin_ingresado:
                if _verificar_pin_admin(pin_ingresado):
                    st.session_state["admin_autorizado"] = True
                    st.session_state["usuario_actual"] = "admin"
                    audit_log("admin", "login_admin", "")
                    st.rerun()
                else:
                    st.error(t["pin_incorrecto"])
        # Cerrar sesión: vuelve a la pantalla de login
        if st.button(f"🚪 {t['cerrar_sesion']}", key="btn_cerrar_sesion", use_container_width=True):
            audit_log(usuario_actual, "cerrar_sesion", "")
            st.session_state["logueado"] = False
            st.session_state["admin_autorizado"] = False
            st.session_state["sidebar_state"] = "collapsed"
            st.rerun()
        st.markdown("---")
        st.markdown(f"<p class='menu-seccion'>{t['menu_navegacion']}</p>", unsafe_allow_html=True)
        if tiene_permiso(usuario_actual, "ver_inicio"):
            if st.button(f"🏠 {t['inicio']}", key="btn_inicio", use_container_width=True):
                st.session_state["pagina"] = "inicio"
                st.session_state["sidebar_state"] = "expanded"
                st.rerun()
        if tiene_permiso(usuario_actual, "ver_arqueo_caja"):
            if st.button(f"📋 {t['arqueo_caja']}", key="btn_arqueo", use_container_width=True):
                st.session_state["pagina"] = "arqueo_caja"
                st.session_state["sidebar_state"] = "expanded"
                st.rerun()
        if tiene_permiso(usuario_actual, "ver_tesoreria"):
            if st.button(f"📒 {t['tesoreria']}", key="btn_tesoreria", use_container_width=True):
                st.session_state["pagina"] = "tesoreria"
                st.session_state["sidebar_state"] = "expanded"
                st.rerun()
        if tiene_permiso(usuario_actual, "ver_contabilidad"):
            if st.button(f"📊 {t['contabilidad']}", key="btn_contabilidad", use_container_width=True):
                st.session_state["pagina"] = "contabilidad"
                st.session_state["sidebar_state"] = "expanded"
                st.rerun()
        if tiene_permiso(usuario_actual, "ver_presupuesto_metas"):
            if st.button(f"🎯 {t['presupuesto_metas']}", key="btn_presupuesto", use_container_width=True):
                st.session_state["pagina"] = "presupuesto_metas"
                st.session_state["sidebar_state"] = "expanded"
                st.rerun()
        if usuario_actual == "admin":
            if st.button(f"⚙️ {t['administracion']}", key="btn_admin", use_container_width=True):
                st.session_state["pagina"] = "administracion"
                st.session_state["sidebar_state"] = "expanded"
                st.rerun()
        tamano_fuente = st.selectbox(t["tamano_texto"], [t["tamano_normal"], t["tamano_grande"]], key="sel_tamano_fuente", index=0 if st.session_state.get("tamano_fuente") != "grande" else 1)
        nuevo_tamano = "grande" if tamano_fuente == t["tamano_grande"] else "normal"
        if nuevo_tamano != st.session_state.get("tamano_fuente"):
            st.session_state["tamano_fuente"] = nuevo_tamano
            st.session_state["sidebar_state"] = "expanded"
            st.rerun()
        tema_sel = st.radio("Tema", [t["tema_oscuro"], t["tema_claro"]], key="sel_tema_app", horizontal=True,
                            index=0 if st.session_state.get("tema_app") == "oscuro" else 1,
                            format_func=lambda x: "🌙 " + x if "oscuro" in x.lower() or "dark" in x.lower() else "☀️ " + x)
        nuevo_tema = "claro" if tema_sel == t["tema_claro"] else "oscuro"
        if nuevo_tema != st.session_state.get("tema_app"):
            st.session_state["tema_app"] = nuevo_tema
            st.session_state["sidebar_state"] = "expanded"
            st.rerun()
        st.markdown("---")
        st.caption(f"{t['version']} {VERSION_APP}")

    # ----- CONTENIDO PRINCIPAL SEGÚN PÁGINA -----
    if st.session_state["pagina"] == "administracion":
        # Estilo: casillas pequeñas, verde = tiene permiso, rojo = no tiene (colores según tema)
        st.markdown(f"""
        <style>
        /* Cuadraditos de permisos: marcado verde, desmarcado rojo */
        div[data-testid="stCheckbox"] > label {{
            padding: 0.35rem 0.5rem !important;
            border-radius: 6px !important;
            border: 1px solid {checkbox_border} !important;
            min-height: 2rem !important;
            font-size: 0.85rem !important;
        }}
        div[data-testid="stCheckbox"]:has(input:not(:checked)) > label {{
            background: rgba(239, 68, 68, 0.2) !important;
            color: {checkbox_unchecked_color} !important;
            border-color: {checkbox_unchecked_border} !important;
        }}
        div[data-testid="stCheckbox"]:has(input:checked) > label {{
            background: rgba(34, 197, 94, 0.2) !important;
            color: {checkbox_checked_color} !important;
            border-color: {checkbox_checked_border} !important;
        }}
        div[data-testid="stCheckbox"] input[type="checkbox"] {{
            width: 1.1rem !important; height: 1.1rem !important;
            accent-color: {checkbox_checked_border} !important;
        }}
        </style>
        """, unsafe_allow_html=True)
        st.markdown(f"## ⚙️ {t['administracion_titulo']}")
        st.markdown(t["admin_instrucciones"])
        st.markdown("")
        data_permisos = cargar_permisos()
        usuarios = data_permisos.get("usuarios", {})
        with st.expander(t["admin_anadir_usuario"], expanded=False):
            col_a, col_b = st.columns(2)
            with col_a:
                nuevo_id = st.text_input(t["admin_id_placeholder"], key="nuevo_id_user", max_chars=30).strip().lower().replace(" ", "_")
                nuevo_nombre = st.text_input(t["admin_nombre_placeholder"], key="nuevo_nombre_user", max_chars=50).strip() or nuevo_id
            if st.button(t["admin_btn_anadir"], key="btn_add_user") and nuevo_id and nuevo_id != "admin":
                if nuevo_id in usuarios:
                    st.warning(t["admin_id_ya_existe"])
                else:
                    data_permisos["usuarios"][nuevo_id] = {"nombre": nuevo_nombre or nuevo_id, "permisos": []}
                    if guardar_permisos(data_permisos, t):
                        st.session_state["usuario_recien_anadido"] = nuevo_id
                        st.success(t["admin_usuario_anadido"].format(nombre=nuevo_nombre or nuevo_id))
                        st.rerun()
        st.markdown("---")
        data_permisos = cargar_permisos()
        usuarios = data_permisos.get("usuarios", {})
        usuario_recien_anadido = st.session_state.pop("usuario_recien_anadido", None)
        if usuario_recien_anadido and usuario_recien_anadido in usuarios:
            nombre_show = usuarios[usuario_recien_anadido].get("nombre", usuario_recien_anadido)
            st.info("✅ " + t["admin_asignar_permisos"].format(nombre=nombre_show))
        for uid, info in usuarios.items():
            nombre = info.get("nombre", uid)
            permisos_usuario = set(info.get("permisos", []))
            es_admin = "*" in permisos_usuario or uid == "admin"
            expandir = not es_admin or uid == usuario_recien_anadido
            with st.expander(f"**{nombre}** ({uid})" + (t["admin_expander_admin"] if es_admin else ""), expanded=expandir):
                if es_admin:
                    st.caption(t["admin_caption_admin"])
                else:
                    permisos_lista = list(PERMISOS_DISPONIBLES)
                    for fila in range(0, len(permisos_lista), 4):
                        cols = st.columns(4)
                        for i, col in enumerate(cols):
                            idx = fila + i
                            if idx >= len(permisos_lista):
                                break
                            permiso_clave, permiso_etiqueta = permisos_lista[idx]
                            tiene = tiene_permiso(uid, permiso_clave)
                            key = f"perm_{uid}_{permiso_clave}"
                            nuevo_valor = st.checkbox(permiso_etiqueta, value=tiene, key=key)
                            if nuevo_valor != tiene:
                                toggle_permiso(uid, permiso_clave, t)
                                st.rerun()
                    st.caption(t["admin_caption_verde_rojo"])
                # Contraseña (todos los usuarios)
                pwd_nueva = st.text_input(t["admin_contrasena"], value="", type="password", key=f"pwd_{uid}", placeholder=t["admin_contrasena_placeholder"])
                col_pwd1, col_pwd2 = st.columns(2)
                with col_pwd1:
                    if st.button(t["admin_guardar_contrasena"], key=f"btn_pwd_{uid}"):
                        data_p = cargar_permisos()
                        if uid in data_p.get("usuarios", {}):
                            pwd_plain = (pwd_nueva or "").strip()
                            if pwd_plain:
                                ok_pol, msg_pol = _validar_politica_contrasena(pwd_plain)
                                if not ok_pol:
                                    st.warning(msg_pol)
                                else:
                                    data_p["usuarios"][uid]["contrasena"] = _hash_contrasena(pwd_plain)
                                    if guardar_permisos(data_p, t):
                                        audit_log(usuario_actual, "contrasena_actualizada", uid)
                                        st.success(t["admin_contrasena_guardada"])
                                        st.rerun()
                            else:
                                data_p["usuarios"][uid]["contrasena"] = ""
                                if guardar_permisos(data_p, t):
                                    audit_log(usuario_actual, "contrasena_actualizada", uid)
                                    st.success(t["admin_contrasena_guardada"])
                                    st.rerun()
                with col_pwd2:
                    if st.button(t["admin_reset_contrasena"], key=f"btn_reset_pwd_{uid}"):
                        data_p = cargar_permisos()
                        if uid in data_p.get("usuarios", {}):
                            data_p["usuarios"][uid]["contrasena"] = ""
                            if guardar_permisos(data_p, t):
                                audit_log(usuario_actual, "contrasena_reseteada", uid)
                                st.success("Contraseña restablecida a predeterminada." if lang == "ES" else "Password reset to default.")
                                st.rerun()
        st.markdown("---")
        if usuario_actual == "admin" and ES_PC_MAESTRO:
            with st.expander(f"🔄 {t['reiniciar_tesoreria']}", expanded=False):
                st.caption(t["reiniciar_explicacion"])
                confirmacion = st.text_input(f"{t['confirmar_escribir']} **{CONFIRMACION_REINICIO}** {t['para_confirmar']}", key="confirm_reinicio")
                if st.button(t["admin_btn_reiniciar"], key="btn_reiniciar_tesoreria", type="secondary"):
                    if (confirmacion or "").strip().upper() == CONFIRMACION_REINICIO:
                        if reiniciar_tesoreria_master():
                            audit_log(usuario_actual, "reinicio_tesoreria", "")
                            st.success(t["reinicio_ok"])
                            st.rerun()
                        else:
                            st.error(t["admin_error_reinicio"])
                    else:
                        st.warning(t["admin_debe_escribir"].format(palabra=CONFIRMACION_REINICIO))
            with st.expander(f"⏪ {t['retroceder_historial']}", expanded=False):
                st.caption(t["retroceder_explicacion"])
                respaldos = listar_respaldos()
                if not respaldos:
                    st.info(t["sin_respaldos"])
                else:
                    def _fmt_respaldo(i):
                        try:
                            return respaldos[i][1] if i < len(respaldos) and len(respaldos[i]) > 1 else str(i)
                        except (IndexError, TypeError):
                            return str(i)
                    sel = st.selectbox(t["seleccionar_respaldo"], options=range(len(respaldos)), format_func=_fmt_respaldo, key="sel_respaldo")
                    if st.button(t["restaurar"], key="btn_restaurar_respaldo"):
                        ruta_rest = respaldos[sel][0] if 0 <= sel < len(respaldos) and respaldos[sel] else None
                        if ruta_rest and restaurar_respaldo(ruta_rest):
                            audit_log(usuario_actual, "restaurar_respaldo", ruta_rest)
                            st.success(t["restaurado_ok"])
                            st.rerun()
                        else:
                            st.error(t["admin_error_restaurar"])
        # Acceso maestro: restablecer admin a admin/admin (solo cuando se ingresó con contraseña universal)
        if st.session_state.get("es_acceso_maestro") and usuario_actual == "admin":
            with st.expander(t["acceso_maestro"], expanded=False):
                st.caption(t["acceso_maestro_info"])
                if st.button(t["restablecer_admin_admin"], key="btn_restablecer_admin_admin"):
                    data = cargar_permisos()
                    if "admin" in data.get("usuarios", {}):
                        data["usuarios"]["admin"]["contrasena"] = ""
                        if guardar_permisos(data, t):
                            audit_log("admin", "admin_restablecido_admin_admin", "por acceso maestro")
                            st.success("Admin restablecido a admin/admin. Cierre sesión y pruebe." if lang == "ES" else "Admin reset to admin/admin. Log out and try.")
                            st.rerun()
        # PIN de administrador: establecer o cambiar
        with st.expander(t["cambiar_pin"] if _pin_admin_requerido() else t["establecer_pin"], expanded=False):
            pin_actual = st.text_input(t["pin_actual"], type="password", key="admin_pin_actual")
            pin_nuevo = st.text_input(t["pin_nuevo"], type="password", key="admin_pin_nuevo")
            if st.button("Guardar PIN", key="btn_guardar_pin") and pin_nuevo:
                if _pin_admin_requerido() and not _verificar_pin_admin(pin_actual):
                    st.error(t["pin_incorrecto"])
                else:
                    try:
                        data = cargar_permisos()
                        data["admin_pin_hash"] = _hash_pin(pin_nuevo)
                        with open(DB_PERMISOS, "w", encoding="utf-8") as f:
                            json.dump(data, f, indent=2, ensure_ascii=False)
                        st.session_state["admin_autorizado"] = True
                        st.success(t["pin_guardado"])
                        audit_log("admin", "pin_actualizado", "")
                    except Exception as e:
                        st.error(str(e))
        st.markdown("---")
        if st.button(t["volver_inicio"]):
            st.session_state["pagina"] = "inicio"
            st.rerun()
        return

    if st.session_state["pagina"] == "inicio":
        # Logo principal en pantalla de inicio (fallback a imagen anterior si no hay logo)
        ruta_imagen = IMAGEN_INICIO_ES if os.path.exists(IMAGEN_INICIO_ES) else (IMAGEN_INICIO_FALLBACK if os.path.exists(IMAGEN_INICIO_FALLBACK) else None)
        if ruta_imagen:
            st.image(ruta_imagen, use_container_width=True)
        # Estilo: sin bordes, imagen flotando; botones 3D (solo ventana inicio)
        st.markdown("""
        <style>
        .stApp, [data-testid="stAppViewContainer"], .main, .main .block-container {
            border: none !important; outline: none !important; box-shadow: none !important;
            padding-left: 0 !important; padding-right: 0 !important; padding-top: 0 !important;
            max-width: 100% !important;
        }
        .main .block-container { padding: 0.5rem 0 1.5rem 0 !important; }
        /* Imagen que sobresale: sin borde gris, sombras oscuras azuladas */
        .main div[data-testid="stImage"] img, .main .stImage img {
            border: none !important;
            outline: none !important;
            box-shadow: 0 12px 40px rgba(8, 20, 45, 0.85),
                        0 6px 20px rgba(10, 25, 55, 0.75),
                        0 3px 12px rgba(5, 15, 40, 0.8),
                        0 0 0 1px rgba(15, 35, 70, 0.3) !important;
        }
        .main div[data-testid="stImage"], .main [data-testid="stImage"] {
            margin: 0 !important;
            padding: 0 !important;
            border: none !important;
            outline: none !important;
            box-shadow: none !important;
        }
        .main hr { display: none !important; }
        /* Botones 3D flotantes: Misión, Visión, Objetivo Supremo, Ministerio de Finanzas */
        .main .stButton > button {
            padding: 1.25rem 1.5rem !important;
            min-height: 100px !important;
            font-size: 1.15rem !important;
            font-weight: bold !important;
            color: #fff !important;
            border: 1px solid transparent !important;
            border-radius: 12px !important;
            background: linear-gradient(180deg, rgba(55,65,80,0.98) 0%, rgba(30,38,48,0.98) 50%, rgba(20,26,34,0.98) 100%) !important;
            box-shadow: 0 0 20px rgba(91,155,213,0.2),
                        0 8px 20px rgba(0,0,0,0.5),
                        0 4px 10px rgba(0,0,0,0.4),
                        inset 0 1px 0 rgba(255,255,255,0.08) !important;
        }
        .main .stButton > button:hover {
            background: linear-gradient(180deg, rgba(65,75,90,0.98) 0%, rgba(40,48,58,0.98) 50%, rgba(28,34,42,0.98) 100%) !important;
            box-shadow: 0 0 28px rgba(91,155,213,0.35),
                        0 12px 28px rgba(0,0,0,0.55),
                        inset 0 1px 0 rgba(255,255,255,0.12) !important;
        }
        .main .stButton > button:active {
            box-shadow: 0 2px 8px rgba(0,0,0,0.5), inset 0 2px 4px rgba(0,0,0,0.3) !important;
        }
        /* Móvil: imagen al tamaño de pantalla, botones grandes para tocar */
        @media (max-width: 768px) {
            .main div[data-testid="stImage"] img, .main .stImage img {
                max-height: 50vh !important;
                max-width: 100% !important;
                width: auto !important;
                object-fit: contain !important;
            }
            .main .stButton > button {
                min-height: 48px !important;
                padding: 0.75rem 1rem !important;
                font-size: 1rem !important;
            }
            .main [data-testid="column"] { min-width: 0 !important; }
        }
        </style>
        """, unsafe_allow_html=True)
        # Debajo de la imagen: tres botones que al clicar muestran Misión, Visión u Objetivo Supremo
        cartel_abierto = st.session_state.get("cartel_abierto_inicio")
        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button(f"**{t['mision']}** — {t['ver_mas']}", key="btn_cartel_mision", use_container_width=True):
                st.session_state["cartel_abierto_inicio"] = "mision" if cartel_abierto != "mision" else None
                st.rerun()
        with c2:
            if st.button(f"**{t['vision']}** — {t['ver_mas']}", key="btn_cartel_vision", use_container_width=True):
                st.session_state["cartel_abierto_inicio"] = "vision" if cartel_abierto != "vision" else None
                st.rerun()
        with c3:
            if st.button(f"**{t['objetivo_supremo']}** — {t['ver_mas']}", key="btn_cartel_objetivo", use_container_width=True):
                st.session_state["cartel_abierto_inicio"] = "objetivo" if cartel_abierto != "objetivo" else None
                st.rerun()
        # Panel desplegable: texto de Misión, Visión u Objetivo
        if cartel_abierto in ("mision", "vision", "objetivo"):
            titulo_cartel = t["mision"] if cartel_abierto == "mision" else (t["vision"] if cartel_abierto == "vision" else t["objetivo_supremo"])
            texto_cartel = t["mision_texto"] if cartel_abierto == "mision" else (t["vision_texto"] if cartel_abierto == "vision" else t["objetivo_texto"])
            st.markdown("---")
            st.markdown(f"### {titulo_cartel}")
            st.info(texto_cartel)
            if st.button(t["cerrar"], key="btn_cerrar_cartel"):
                st.session_state["cartel_abierto_inicio"] = None
                st.rerun()
            st.markdown("---")
        # Accesos rápidos a las 4 oficinas (según permisos)
        col_a, col_b, col_c, col_d = st.columns(4)
        with col_a:
            if tiene_permiso(usuario_actual, "ver_arqueo_caja") and st.button(f"📋 {t['arqueo_caja']}", key="btn_ir_arqueo", use_container_width=True):
                st.session_state["pagina"] = "arqueo_caja"
                st.session_state["sidebar_state"] = "expanded"
                st.rerun()
        with col_b:
            if tiene_permiso(usuario_actual, "ver_tesoreria") and st.button(f"📒 {t['tesoreria']}", key="btn_ir_tesoreria", use_container_width=True):
                st.session_state["pagina"] = "tesoreria"
                st.session_state["sidebar_state"] = "expanded"
                st.rerun()
        with col_c:
            if tiene_permiso(usuario_actual, "ver_contabilidad") and st.button(f"📊 {t['contabilidad']}", key="btn_ir_contabilidad", use_container_width=True):
                st.session_state["pagina"] = "contabilidad"
                st.session_state["sidebar_state"] = "expanded"
                st.rerun()
        with col_d:
            if tiene_permiso(usuario_actual, "ver_presupuesto_metas") and st.button(f"🎯 {t['presupuesto_metas']}", key="btn_ir_presupuesto", use_container_width=True):
                st.session_state["pagina"] = "presupuesto_metas"
                st.session_state["sidebar_state"] = "expanded"
                st.rerun()
        with st.expander(f"❓ {t['primera_vez']}", expanded=False):
            st.caption(t["ayuda_rapida"])
        with st.expander(f"📲 {t['compartir_app']}", expanded=False):
            st.caption(t["compartir_app_instrucciones"])
        return

    # ----- OFICINAS: ARQUEO, TESORERÍA, CONTABILIDAD, PRESUPUESTO -----
    pagina_act = st.session_state.get("pagina", "inicio")
    if pagina_act == "ministerio_finanzas":
        st.session_state["pagina"] = "contabilidad"
        st.rerun()
    if pagina_act not in ("arqueo_caja", "tesoreria", "contabilidad", "presupuesto_metas"):
        st.info(t["bienvenida_texto"])
        return

    with st.spinner(t.get("cargando", "Cargando datos...")):
        df = cargar_db()

    # ---------- ARQUEO DE CAJA (Cierre Diario) ----------
    if pagina_act == "arqueo_caja":
        st.markdown(f"## 📋 {t['arqueo_caja']}")
        st.caption(t["arqueo_caja_sub"])
        st.markdown("")
        # Resumen del día
        hoy_str = datetime.now().strftime("%Y-%m-%d")
        df_hoy = df[df["fecha"].astype(str).str[:10] == hoy_str] if not df.empty and "fecha" in df.columns else pd.DataFrame()
        ing_hoy = float(df_hoy["ingreso"].sum()) if not df_hoy.empty else 0.0
        gas_hoy = float(df_hoy["gastos"].sum()) if not df_hoy.empty else 0.0
        with st.expander(f"📊 {t['resumen_dia']}", expanded=not df_hoy.empty):
            c1, c2, c3 = st.columns(3)
            with c1:
                st.metric(t["ingresos_mes"] + " " + hoy_str, f"${ing_hoy:,.2f}")
            with c2:
                st.metric(t["gastos_mes"], f"${gas_hoy:,.2f}")
            with c3:
                st.metric(t["saldo_actual"], f"${ing_hoy - gas_hoy:,.2f}")
        st.markdown("")
        if tiene_permiso(usuario_actual, "ver_ingresar_bendicion"):
            if st.session_state.get("limpiar_arqueo"):
                for key in ["b100", "b50", "b20", "b10", "b5", "m2", "m1", "m025", "m010", "m005"]:
                    st.session_state[key] = 0
                st.session_state["limpiar_arqueo"] = False
            with st.expander(f"💰 {t['ingresar_bendicion']}", expanded=True):
                def _aplica_mayusculas_contado():
                    v = st.session_state.get("contado_por_arqueo", "")
                    if v and v != v.upper():
                        st.session_state["contado_por_arqueo"] = v.upper()

                def _aplica_mayusculas_verificado():
                    v = st.session_state.get("verificado_por_arqueo", "")
                    if v and v != v.upper():
                        st.session_state["verificado_por_arqueo"] = v.upper()

                st.markdown("""<style>
                .main [data-testid="stTextInput"]:nth-of-type(1) input,
                .main [data-testid="stTextInput"]:nth-of-type(2) input { text-transform: uppercase !important; }
                </style>""", unsafe_allow_html=True)
                meta_arq = cargar_arqueo_meta()
                nombres_contado, nombres_verificado = _nombres_arqueo_desde_meta(meta_arq)
                if "contado_por_arqueo" not in st.session_state:
                    st.session_state["contado_por_arqueo"] = usuario_actual
                if "verificado_por_arqueo" not in st.session_state:
                    st.session_state["verificado_por_arqueo"] = ""

                contado_por_raw = st.text_input(t["contado_por"] + " *", key="contado_por_arqueo", max_chars=80, placeholder="Escriba el nombre (se guarda en MAYÚSCULAS)", help=t["contado_por_ayuda"], on_change=_aplica_mayusculas_contado)
                if nombres_contado:
                    st.caption(t["arqueo_sugerencias"] + ": ")
                    cols_c = st.columns(min(6, len(nombres_contado) + 1))[:6]
                    for i, nom in enumerate(nombres_contado[:5]):
                        with cols_c[i]:
                            if st.button(nom, key=f"contado_sug_{i}", use_container_width=True):
                                st.session_state["contado_por_arqueo"] = nom
                                st.rerun()
                contado_por = (contado_por_raw or "").strip().upper()
                if contado_por and nombres_contado:
                    contado_por = _normalizar_y_coincidir(contado_por, nombres_contado) or contado_por
                    if len((contado_por_raw or "").strip()) == 1 and len(contado_por) > 1:
                        st.session_state["contado_por_arqueo"] = contado_por
                        st.rerun()
                ok_contado, msg_contado = _validar_nombre_arqueo(contado_por)
                if contado_por and not ok_contado:
                    st.warning(t.get(msg_contado, msg_contado))

                verificado_habilitado = bool(contado_por)
                verificado_por_raw = st.text_input(t["verificado_por"] + " *", key="verificado_por_arqueo", max_chars=80, placeholder="Escriba el nombre (se guarda en MAYÚSCULAS)", disabled=not verificado_habilitado, help=t["verificado_por_ayuda"], on_change=_aplica_mayusculas_verificado)
                if verificado_habilitado and nombres_verificado:
                    st.caption(t["arqueo_sugerencias"] + ": ")
                    cols_v = st.columns(min(6, len(nombres_verificado) + 1))[:6]
                    for i, nom in enumerate(nombres_verificado[:5]):
                        with cols_v[i]:
                            if st.button(nom, key=f"verificado_sug_{i}", use_container_width=True):
                                st.session_state["verificado_por_arqueo"] = nom
                                st.rerun()
                verificado_por = (verificado_por_raw or "").strip().upper()
                if verificado_por and nombres_verificado:
                    verificado_por = _normalizar_y_coincidir(verificado_por, nombres_verificado) or verificado_por
                    if len((verificado_por_raw or "").strip()) == 1 and len(verificado_por) > 1:
                        st.session_state["verificado_por_arqueo"] = verificado_por
                        st.rerun()
                ok_verif, msg_verif = _validar_nombre_arqueo(verificado_por)
                if verificado_por and not ok_verif:
                    st.warning(t.get(msg_verif, msg_verif))

                ambos_ok = bool(contado_por and verificado_por and ok_contado and ok_verif)
                if not verificado_habilitado:
                    st.info(t["arqueo_llenar_ambos"] if lang == "ES" else t["arqueo_llenar_ambos"])
                elif not ambos_ok and (contado_por or verificado_por):
                    st.warning(t["arqueo_llenar_ambos"])
                st.markdown("---")

                campos_habilitados = ambos_ok
                fondo_caja_val = st.number_input(t["fondo_caja"], min_value=0.0, value=0.0, step=10.0, key="fondo_caja_arqueo", disabled=not campos_habilitados)
                tipo_ingreso_opciones = TIPOS_INGRESO_ES if lang == "ES" else TIPOS_INGRESO_EN
                tipo_ingreso_sel = st.selectbox(t["tipo_ingreso"], tipo_ingreso_opciones, key="tipo_ingreso_bendicion", disabled=not campos_habilitados)
                medios_opciones = MEDIOS_PAGO_ES if lang == "ES" else MEDIOS_PAGO_EN
                medio_efectivo = MEDIO_EFECTIVO_ES if lang == "ES" else MEDIO_EFECTIVO_EN
                medio_cheques_es = "Cheques"
                medio_cheques_en = "Checks"
                medio_pago_sel = st.selectbox(t["medio_pago"], medios_opciones, key="medio_pago_bendicion", disabled=not campos_habilitados)
                es_efectivo = (medio_pago_sel == medio_efectivo)
                es_cheques = (medio_pago_sel == medio_cheques_es or medio_pago_sel == medio_cheques_en)

                if es_cheques:
                    cheques_cant = st.number_input(t["cheques_cantidad"], min_value=0, value=0, step=1, key="cheques_cant_arqueo", disabled=not campos_habilitados)
                    cheques_tot = st.number_input(t["cheques_total"], min_value=0.0, value=0.0, step=10.0, key="cheques_tot_arqueo", disabled=not campos_habilitados)
                    st.caption("Marque los cheques como «solo para depósito» antes de guardarlos." if lang == "ES" else "Stamp checks 'for deposit only' before storing.")
                elif es_efectivo:
                    ministerio = st.selectbox(t["ministerio"], ministerios, key="min_bendicion", disabled=not campos_habilitados)
                    st.markdown(f"<p class='big-label'>{t['billetes']}</p>", unsafe_allow_html=True)
                    col1, col2, col3, col4, col5 = st.columns(5)
                    with col1:
                        b100 = st.number_input("$100", min_value=0, value=0, step=1, key="b100", disabled=not campos_habilitados)
                    with col2:
                        b50 = st.number_input("$50", min_value=0, value=0, step=1, key="b50", disabled=not campos_habilitados)
                    with col3:
                        b20 = st.number_input("$20", min_value=0, value=0, step=1, key="b20", disabled=not campos_habilitados)
                    with col4:
                        b10 = st.number_input("$10", min_value=0, value=0, step=1, key="b10", disabled=not campos_habilitados)
                    with col5:
                        b5 = st.number_input("$5", min_value=0, value=0, step=1, key="b5", disabled=not campos_habilitados)
                    st.markdown(f"<p class='big-label'>{t['monedas']}</p>", unsafe_allow_html=True)
                    c1, c2, c3, c4, c5 = st.columns(5)
                    with c1:
                        m2 = st.number_input("$2", min_value=0, value=0, step=1, key="m2", disabled=not campos_habilitados)
                    with c2:
                        m1 = st.number_input("$1", min_value=0, value=0, step=1, key="m1", disabled=not campos_habilitados)
                    with c3:
                        m025 = st.number_input("$0.25", min_value=0, value=0, step=1, key="m025", disabled=not campos_habilitados)
                    with c4:
                        m010 = st.number_input("$0.10", min_value=0, value=0, step=1, key="m010", disabled=not campos_habilitados)
                    with c5:
                        m005 = st.number_input("$0.05", min_value=0, value=0, step=1, key="m005", disabled=not campos_habilitados)
                    total_arqueo = (
                        b100 * 100 + b50 * 50 + b20 * 20 + b10 * 10 + b5 * 5 +
                        m2 * 2 + m1 * 1 + m025 * 0.25 + m010 * 0.10 + m005 * 0.05
                    )
                    if "_last_total_arqueo" not in st.session_state or abs(st.session_state.get("_last_total_arqueo", 0) - total_arqueo) > 0.01:
                        st.session_state["total_suelto_arqueo"] = round(total_arqueo, 2)
                        st.session_state["_last_total_arqueo"] = total_arqueo
                    st.caption(t.get("arqueo_teclado_movil", ""))
                    st.markdown(f"**{t.get('arqueo_total_calculado', 'Total billetes + monedas')}:** ${total_arqueo:.2f}")
                    sobres_cant = st.number_input(t["sobres_cantidad"], min_value=0, value=0, step=1, key="sobres_cant_arqueo", disabled=not campos_habilitados)
                    sobres_tot = st.number_input(t["sobres_total"], min_value=0.0, value=0.0, step=10.0, key="sobres_tot_arqueo", disabled=not campos_habilitados)
                    total_suelto = st.number_input(t["total_suelto"], min_value=0.0, value=round(total_arqueo, 2), step=10.0, key="total_suelto_arqueo", disabled=not campos_habilitados)
                    st.caption("Verifique que el contenido de cada sobre coincida con lo escrito." if lang == "ES" else "Verify envelope contents match written amounts.")
                    st.markdown(f"<div class='total-box'>{t['total']}: ${total_arqueo:.2f}</div>", unsafe_allow_html=True)
                elif not es_cheques:
                    monto_no_efectivo = st.number_input(t["monto_pos_tarjeta"], min_value=0.0, value=0.0, step=10.0, key="monto_ingreso_pos", disabled=not campos_habilitados)
                    ref_opcional = st.text_input(t["referencia_opcional"], key="ref_pos", max_chars=20, placeholder=t.get("referencia_placeholder", ""), disabled=not campos_habilitados)

                _arqueo_keys = (
                    "contado_por_arqueo", "verificado_por_arqueo", "tipo_ingreso_bendicion", "medio_pago_bendicion",
                    "min_bendicion", "fondo_caja_arqueo", "cheques_cant_arqueo", "cheques_tot_arqueo",
                    "b100", "b50", "b20", "b10", "b5", "m2", "m1", "m025", "m010", "m005",
                    "sobres_cant_arqueo", "sobres_tot_arqueo", "total_suelto_arqueo", "monto_ingreso_pos", "ref_pos",
                    "_last_total_arqueo", "limpiar_arqueo"
                )
                col_reg, col_sp, col_ref = st.columns([1, 2, 1])
                with col_reg:
                    if st.button(t["registrar"], key="btn_bendicion", disabled=not ambos_ok):
                        if es_cheques:
                            monto_ingreso = round(float(cheques_tot), 2) if cheques_tot else 0.0
                            if monto_ingreso <= 0:
                                st.warning(t["arqueo_cero"])
                            else:
                                rid = generar_id_arqueo()
                                fecha_ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                detalle = f"Arqueo - Cheques ({cheques_cant} cheques)"
                                if lang == "ES":
                                    tipo_guardar_ing = tipo_ingreso_sel
                                else:
                                    try:
                                        idx_ing = TIPOS_INGRESO_EN.index(tipo_ingreso_sel)
                                        tipo_guardar_ing = TIPOS_INGRESO_ES[idx_ing]
                                    except (ValueError, IndexError):
                                        tipo_guardar_ing = DEFAULT_TIPO_INGRESO
                                nueva = pd.DataFrame([{
                                    "id_registro": rid,
                                    "fecha": fecha_ahora,
                                    "detalle": detalle,
                                    "tipo_gasto": tipo_guardar_ing,
                                    "ingreso": monto_ingreso,
                                    "gastos": 0,
                                    "total_ingresos": 0,
                                    "total_gastos": 0,
                                    "saldo_actual": 0
                                }])
                                df = pd.concat([df, nueva], ignore_index=True)
                                if guardar_db(df, t):
                                    meta = cargar_arqueo_meta()
                                    meta[rid] = {
                                        "contado_por": (contado_por or "").strip() or usuario_actual,
                                        "verificado_por": (verificado_por or "").strip(),
                                        "ip_dispositivo": _get_client_ip(),
                                        "desglose": {},
                                        "total_cheques": monto_ingreso,
                                        "cheques_cant": cheques_cant,
                                        "fecha": fecha_ahora,
                                    }
                                    guardar_arqueo_meta(meta)
                                    audit_log(usuario_actual, "ingreso_registrado", f"{rid} {detalle} ${monto_ingreso:.2f}")
                                    st.session_state["limpiar_arqueo"] = True
                                    st.success(t["bendicion_registrada"])
                                    st.rerun()
                        elif es_efectivo:
                            monto_ingreso = round(float(total_suelto or 0) + float(sobres_tot or 0), 2)
                            if monto_ingreso <= 0:
                                st.warning(t["arqueo_cero"])
                            else:
                                rid = generar_id_arqueo()
                                fecha_ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                detalle = f"Arqueo - {ministerio}"
                                if lang == "ES":
                                    tipo_guardar_ing = tipo_ingreso_sel
                                else:
                                    try:
                                        idx_ing = TIPOS_INGRESO_EN.index(tipo_ingreso_sel)
                                        tipo_guardar_ing = TIPOS_INGRESO_ES[idx_ing]
                                    except (ValueError, IndexError):
                                        tipo_guardar_ing = DEFAULT_TIPO_INGRESO
                                nueva = pd.DataFrame([{
                                    "id_registro": rid,
                                    "fecha": fecha_ahora,
                                    "detalle": detalle,
                                    "tipo_gasto": tipo_guardar_ing,
                                    "ingreso": monto_ingreso,
                                    "gastos": 0,
                                    "total_ingresos": 0,
                                    "total_gastos": 0,
                                    "saldo_actual": 0
                                }])
                                df = pd.concat([df, nueva], ignore_index=True)
                                if guardar_db(df, t):
                                    meta = cargar_arqueo_meta()
                                    meta[rid] = {
                                        "contado_por": (contado_por or "").strip() or usuario_actual,
                                        "verificado_por": (verificado_por or "").strip(),
                                        "ip_dispositivo": _get_client_ip(),
                                        "desglose": {"b100": b100, "b50": b50, "b20": b20, "b10": b10, "b5": b5,
                                                     "m2": m2, "m1": m1, "m025": m025, "m010": m010, "m005": m005},
                                        "total_efectivo": float(total_arqueo),
                                        "total": monto_ingreso,
                                        "sobres_cant": sobres_cant,
                                        "sobres_tot": float(sobres_tot or 0),
                                        "total_suelto": float(total_suelto or 0),
                                        "fondo_caja": float(fondo_caja_val or 0),
                                        "fecha": fecha_ahora,
                                    }
                                    guardar_arqueo_meta(meta)
                                    audit_log(usuario_actual, "ingreso_registrado", f"{rid} {detalle} ${monto_ingreso:.2f}")
                                    st.session_state["limpiar_arqueo"] = True
                                    st.success(t["bendicion_registrada"])
                                    st.rerun()
                        else:
                            monto_ingreso = round(float(monto_no_efectivo), 2) if monto_no_efectivo else 0.0
                            if monto_ingreso <= 0:
                                st.warning(t["arqueo_cero"])
                            else:
                                rid = generar_id_arqueo()
                                fecha_ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                if lang == "ES":
                                    tipo_guardar_ing = tipo_ingreso_sel
                                else:
                                    try:
                                        idx_ing = TIPOS_INGRESO_EN.index(tipo_ingreso_sel)
                                        tipo_guardar_ing = TIPOS_INGRESO_ES[idx_ing]
                                    except (ValueError, IndexError):
                                        tipo_guardar_ing = DEFAULT_TIPO_INGRESO
                                if medio_pago_sel == (MEDIOS_PAGO_ES[1] if lang == "ES" else MEDIOS_PAGO_EN[1]):
                                    sufijo = "POS"
                                elif medio_pago_sel == (MEDIOS_PAGO_ES[2] if lang == "ES" else MEDIOS_PAGO_EN[2]):
                                    sufijo = "Tarjeta débito" if lang == "ES" else "Debit card"
                                else:
                                    sufijo = "Transferencia" if lang == "ES" else "Transfer"
                                ref = (ref_opcional or "").strip()[:20]
                                if ref:
                                    detalle = f"{tipo_guardar_ing} ({sufijo} ****{ref})"
                                else:
                                    detalle = f"{tipo_guardar_ing} ({sufijo})"
                                nueva = pd.DataFrame([{
                                    "id_registro": rid,
                                    "fecha": fecha_ahora,
                                    "detalle": detalle,
                                    "tipo_gasto": tipo_guardar_ing,
                                    "ingreso": monto_ingreso,
                                    "gastos": 0,
                                    "total_ingresos": 0,
                                    "total_gastos": 0,
                                    "saldo_actual": 0
                                }])
                                df = pd.concat([df, nueva], ignore_index=True)
                                if guardar_db(df, t):
                                    meta = cargar_arqueo_meta()
                                    meta[rid] = {
                                        "contado_por": (contado_por or "").strip() or usuario_actual,
                                        "verificado_por": (verificado_por or "").strip(),
                                        "ip_dispositivo": _get_client_ip(),
                                        "total_pos": monto_ingreso,
                                        "fecha": fecha_ahora,
                                    }
                                    guardar_arqueo_meta(meta)
                                    audit_log(usuario_actual, "ingreso_registrado", f"{rid} {detalle} ${monto_ingreso:.2f}")
                                    st.session_state["limpiar_arqueo"] = True
                                    st.success(t["bendicion_registrada"])
                                    st.rerun()
                with col_ref:
                    if st.button(t.get("arqueo_refrescar", "Refrescar"), key="btn_refrescar_arqueo", help=t.get("arqueo_refrescar_ayuda", "")):
                        for k in _arqueo_keys:
                            if k in st.session_state:
                                del st.session_state[k]
                        st.rerun()
        with st.expander(f"📋 {t['conciliar']}", expanded=False):
            st.caption(t["conciliar_ayuda"])
            fecha_conciliar = st.date_input(t["fecha_conciliar"], value=datetime.now().date(), key="fecha_conciliar_arqueo")
            fecha_str = fecha_conciliar.strftime("%Y-%m-%d") if fecha_conciliar else datetime.now().strftime("%Y-%m-%d")
            df_dash = df.copy()
            try:
                df_dash["_fecha"] = pd.to_datetime(df_dash["fecha"].astype(str).str[:10], errors="coerce")
                df_dia = df_dash[df_dash["fecha"].astype(str).str[:10] == fecha_str]
            except Exception:
                df_dia = pd.DataFrame()
            ing_dia = float(df_dia["ingreso"].sum()) if not df_dia.empty else 0.0
            st.metric(t["ingresos_mes"] + f" ({fecha_str})", f"${ing_dia:,.2f}")
            lo_contado = st.number_input(t["lo_contado_caja"], min_value=0.0, value=0.0, step=10.0, key="conciliar_contado")
            if lo_contado > 0:
                diff = lo_contado - ing_dia
                if abs(diff) < 0.02:
                    st.success(t["coincide_registrado"])
                else:
                    st.caption(f"Diferencia: ${diff:+,.2f}")
            meta_conc = cargar_arqueo_meta()
            fechas_cerradas = meta_conc.get("_fechas_cerradas", []) or []
            if fecha_str in fechas_cerradas:
                st.success(f"✓ {t['arqueo_cerrado']} ({fecha_str})")
            elif st.button(t["cerrar_arqueo"], key="btn_cerrar_arqueo"):
                fechas_cerradas = list(set(fechas_cerradas + [fecha_str]))
                meta_conc["_fechas_cerradas"] = fechas_cerradas
                guardar_arqueo_meta(meta_conc)
                audit_log(usuario_actual, "arqueo_cerrado", fecha_str)
                st.success(t["arqueo_cerrado"])
                st.rerun()
        with st.expander(f"📤 {t['descargar_hoja_arqueo']}", expanded=False):
            st.caption(t["descargar_hoja_arqueo_ayuda"])
            arqueos_ac = df[df["id_registro"].astype(str).str.startswith("AC-")] if not df.empty else pd.DataFrame()
            if arqueos_ac.empty:
                st.info(t["sin_movimientos"])
            else:
                arqueos_lista = arqueos_ac.iloc[-20:].iloc[::-1]
                opciones_rid = [str(r.get("id_registro", "")) for _, r in arqueos_lista.iterrows()]
                rid_a_label = {str(r.get("id_registro", "")): f"{str(r.get('fecha',''))[:16]} — ${float(r.get('ingreso',0)):,.2f}" for _, r in arqueos_lista.iterrows()}
                if not opciones_rid:
                    st.info(t["sin_movimientos"])
                else:
                    rid_sel = st.selectbox(
                        t["seleccionar_arqueo"],
                        options=opciones_rid,
                        format_func=lambda x: rid_a_label.get(x, str(x)),
                        key="sel_arqueo_descarga"
                    )
                    df_filt = arqueos_ac[arqueos_ac["id_registro"].astype(str) == str(rid_sel or "")] if rid_sel else pd.DataFrame()
                    if df_filt.empty:
                        fila_sel = arqueos_lista.iloc[0]
                    else:
                        fila_sel = df_filt.iloc[0]
                    rid_ult = str(fila_sel.get("id_registro", ""))
                    meta = cargar_arqueo_meta()
                    datos = meta.get(rid_ult, {})
                    datos["fecha"] = datos.get("fecha") or str(fila_sel.get("fecha", ""))
                    datos["total"] = float(fila_sel.get("ingreso", 0))
                    datos["total_efectivo"] = datos.get("total_efectivo") or datos.get("total", 0)
                    col_pdf_a, col_xlsx_a = st.columns(2)
                    with col_pdf_a:
                        try:
                            pdf_arq = generar_pdf_hoja_arqueo(datos, lang)
                            if pdf_arq:
                                st.download_button(
                                    label=t["hoja_arqueo_pdf"],
                                    data=pdf_arq,
                                    file_name=f"Hoja_Arqueo_{rid_ult.replace(':', '-')[:30]}.pdf",
                                    mime="application/pdf",
                                    key="download_hoja_arqueo_pdf"
                                )
                        except Exception:
                            st.caption("PDF no disponible" if lang == "ES" else "PDF not available")
                    with col_xlsx_a:
                        try:
                            xlsx_arq = generar_excel_hoja_arqueo(datos, lang)
                            if xlsx_arq:
                                st.download_button(
                                    label=t["hoja_arqueo_excel"],
                                    data=xlsx_arq,
                                    file_name=f"Hoja_Arqueo_{rid_ult.replace(':', '-')[:30]}.xlsx",
                                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                    key="download_hoja_arqueo_excel"
                                )
                        except Exception:
                            st.caption("Excel no disponible" if lang == "ES" else "Excel not available")
        return

    # ---------- TESORERÍA (Libro de Registros) ----------
    if pagina_act == "tesoreria":
        st.markdown(f"## 📒 {t['tesoreria']}")
        st.caption(t["tesoreria_sub"])
        st.markdown("")
        if tiene_permiso(usuario_actual, "ver_registrar_gasto"):
            MAX_CARACTERES_DESCRIPCION_T = 1000
            _gasto_keys = ["desc_g", "monto_g", "aprobado_por_g", "tipo_gasto_sel", "suministro_sel", "gasto_frecuente_sel", "modo_escaneo_rapido"]
            if st.session_state.get("limpiar_gasto"):
                for key in ["desc_g", "aprobado_por_g"]:
                    if key in st.session_state:
                        st.session_state[key] = ""
                if "monto_g" in st.session_state:
                    st.session_state["monto_g"] = 0.0
                for k in ("monto_sugerido", "descripcion_sugerida", "factura_detectada_actual", "ocr_text_actual", "hash_foto_actual"):
                    st.session_state.pop(k, None)
                tipo_opciones = TIPOS_GASTO_ES if st.session_state.get("idioma", "ES") == "ES" else TIPOS_GASTO_EN
                st.session_state["tipo_gasto_sel"] = tipo_opciones[0]
                st.session_state["suministro_sel"] = ""
                st.session_state["gasto_frecuente_sel"] = ""
                try:
                    for k in list(st.session_state.keys()):
                        if k == "foto_gasto" or (isinstance(k, str) and k.startswith("foto_gasto")):
                            del st.session_state[k]
                except Exception:
                    pass
                st.session_state["limpiar_gasto"] = False
            modo_rapido = st.checkbox(t.get("modo_escaneo_rapido", "Modo escaneo rápido"), key="modo_escaneo_rapido", value=st.session_state.get("modo_escaneo_rapido", False))
            with st.expander(f"📤 {t['registrar_gasto']}", expanded=True):
                tipo_opciones = TIPOS_GASTO_ES if lang == "ES" else TIPOS_GASTO_EN
                tipo_seleccionado = st.selectbox(t["tipo_gasto"], options=tipo_opciones, key="tipo_gasto_sel")
                es_recurrentes = tipo_seleccionado in ("Recurrentes", "Recurring")
                es_operativo = tipo_seleccionado in ("Operativo", "Operational")
                suministro_sel = ""
                gasto_frec_sel = ""
                if es_recurrentes:
                    suministros_lista = cargar_suministros()
                    suministro_sel = st.selectbox(t["suministros"], options=[""] + suministros_lista, key="suministro_sel")
                    if suministro_sel and not st.session_state.get("descripcion_sugerida"):
                        if "desc_g" not in st.session_state or not st.session_state.get("desc_g"):
                            st.session_state["desc_g"] = suministro_sel
                elif es_operativo:
                    gastos_frec = _gastos_frecuentes_desde_df(df)
                    opciones_gf = [""] + gastos_frec[:15]
                    gasto_frec_sel = st.selectbox(t["gastos_frecuentes"], options=opciones_gf, key="gasto_frecuente_sel")
                    if gasto_frec_sel and not st.session_state.get("descripcion_sugerida"):
                        if "desc_g" not in st.session_state or not st.session_state.get("desc_g"):
                            st.session_state["desc_g"] = gasto_frec_sel
                with st.form("form_gasto", clear_on_submit=True):
                    monto_sugerido = st.session_state.get("monto_sugerido", "")
                    try:
                        monto_val_inicial = float(str(monto_sugerido).replace(",", ".")) if monto_sugerido else 0.0
                    except (ValueError, TypeError):
                        monto_val_inicial = 0.0
                    st.number_input(t["monto"], min_value=0.0, value=monto_val_inicial, step=0.01, format="%.2f", key="monto_g", help=t.get("gasto_teclado_movil", ""))
                    col_btn_reg, col_btn_sp, col_btn_ref = st.columns([1, 2, 1])
                    with col_btn_reg:
                        enviado = st.form_submit_button(t["registrar"])
                col_btn_reg, col_btn_sp, col_btn_ref = st.columns([1, 2, 1])
                with col_btn_ref:
                    if st.button(t.get("gasto_refrescar", "Refrescar"), key="btn_refrescar_gasto", help=t.get("gasto_refrescar_ayuda", ""), use_container_width=True):
                        st.session_state["limpiar_gasto"] = True
                        st.rerun()
                if not modo_rapido:
                    desc_sugerida = st.session_state.get("descripcion_sugerida", "")
                    desc_base = desc_sugerida or (suministro_sel if es_recurrentes else (gasto_frec_sel if es_operativo else ""))
                    desc_gasto = st.text_input(t["descripcion"], value=st.session_state.get("desc_g", desc_base) or desc_base, max_chars=MAX_CARACTERES_DESCRIPCION_T, key="desc_g")
                    n_car = len(desc_gasto or "")
                    st.markdown(
                        f"<p style='font-size:0.75rem; color: {sidebar_txt_muted}; margin-top: -0.5rem;'>{n_car} / {MAX_CARACTERES_DESCRIPCION_T} {t['caracteres']}</p>",
                        unsafe_allow_html=True
                    )
                    nombres_aprobado = _nombres_aprobado_desde_df(df)
                    def _aplica_mayusculas_aprobado():
                        v = st.session_state.get("aprobado_por_g", "")
                        if v and v != v.upper():
                            st.session_state["aprobado_por_g"] = v.upper()
                    aprobado_por_raw = st.text_input(t["aprobado_por"] + f" {UMBRAL_GASTO_APROBACION:.0f})", key="aprobado_por_g", max_chars=100, placeholder="Nombre de quien aprueba", on_change=_aplica_mayusculas_aprobado)
                    if nombres_aprobado:
                        st.caption(t.get("gasto_sugerencias", "Sugerencias") + ": ")
                        cols_ap = st.columns(min(6, len(nombres_aprobado) + 1))[:6]
                        for i, nom in enumerate(nombres_aprobado[:5]):
                            with cols_ap[i]:
                                if st.button(nom, key=f"aprobado_sug_{i}", use_container_width=True):
                                    st.session_state["aprobado_por_g"] = nom
                                    st.rerun()
                    aprobado_por_gasto = (aprobado_por_raw or "").strip().upper()
                    if aprobado_por_gasto and nombres_aprobado:
                        aprobado_por_gasto = _normalizar_y_coincidir(aprobado_por_gasto, nombres_aprobado) or aprobado_por_gasto
                    ok_aprob, msg_aprob = _validar_nombre_arqueo(aprobado_por_gasto)
                    if aprobado_por_gasto and not ok_aprob:
                        st.warning(t.get(msg_aprob, msg_aprob))
                else:
                    desc_gasto = st.session_state.get("desc_g", "") or "Gasto (modo rápido)"
                    aprobado_por_gasto = ""
                    ok_aprob = True
                st.markdown(f"<p class='big-label'>{t['tomar_foto']}</p>", unsafe_allow_html=True)
                st.caption(t.get("foto_multiples_ayuda", "Puede subir varias fotos (frente, reverso, anexos)."))
                foto_subidas = st.file_uploader(" ", type=["jpg", "jpeg", "png"], key="foto_gasto", accept_multiple_files=True)
                foto_subida = foto_subidas[0] if foto_subidas else None

                if foto_subida:
                    bytes_foto = foto_subida.getvalue()
                    hash_foto = _hash_imagen(bytes_foto)
                    if imagen_ya_subida(hash_foto):
                        st.warning(t["imagen_ya_subida_aviso"])
                    if st.session_state.get("hash_foto_actual") != hash_foto:
                        ocr_text = _ocr_imagen(bytes_foto)
                        datos = _extraer_datos_factura(ocr_text)
                        st.session_state["factura_detectada_actual"] = datos
                        st.session_state["ocr_text_actual"] = ocr_text
                        st.session_state["hash_foto_actual"] = hash_foto
                        st.session_state["monto_sugerido"] = f"{datos['total']:.2f}" if datos.get("total") is not None else ""
                        st.session_state["descripcion_sugerida"] = (datos.get("comercio") or "")[:MAX_CARACTERES_DESCRIPCION_T]
                        st.rerun()
                    datos_show = st.session_state.get("factura_detectada_actual") or {}
                    tiene_datos_ocr = datos_show and (datos_show.get("total") is not None or datos_show.get("comercio"))
                    with st.expander(f"📋 {t['factura_detectada']}", expanded=True):
                        if st.button(t.get("reintentar_ocr", "Reintentar OCR"), key="btn_reintentar_ocr"):
                            ocr_text = _ocr_imagen(bytes_foto)
                            datos = _extraer_datos_factura(ocr_text)
                            st.session_state["factura_detectada_actual"] = datos
                            st.session_state["ocr_text_actual"] = ocr_text
                            st.session_state["monto_sugerido"] = f"{datos['total']:.2f}" if datos.get("total") is not None else ""
                            st.session_state["descripcion_sugerida"] = (datos.get("comercio") or "")[:MAX_CARACTERES_DESCRIPCION_T]
                            st.rerun()
                        st.markdown(f"**{t.get('vista_previa_factura', 'Vista previa')}:**")
                        for idx_f, fup in enumerate(foto_subidas):
                            lbl = (t.get("foto_frente", "Frente"), t.get("foto_reverso", "Reverso"), t.get("foto_anexo", "Anexo"))[min(idx_f, 2)] if idx_f < 3 else f"#{idx_f + 1}"
                            st.caption(lbl if len(foto_subidas) > 1 else "")
                            st.image(fup.getvalue(), use_column_width=True)
                        if datos_show.get("total") is not None:
                            st.markdown(f"**{t['total_detectado']}:** ${datos_show['total']:.2f}")
                        if datos_show.get("impuesto") is not None:
                            st.markdown(f"**{t['impuesto_detectado']}:** ${datos_show['impuesto']:.2f}")
                        if datos_show.get("comercio"):
                            st.markdown(f"**{t['comercio_detectado']}:** {datos_show['comercio'][:100]}")
                        monto_manual = 0.0
                        try:
                            mg = st.session_state.get("monto_g")
                            if mg is not None:
                                monto_manual = round(float(mg), 2) if isinstance(mg, (int, float)) else round(float((str(mg) or "").strip().replace(",", ".") or 0), 2)
                        except (ValueError, TypeError):
                            pass
                        if datos_show.get("total") is not None and monto_manual > 0 and abs(monto_manual - datos_show["total"]) > 0.01:
                            st.warning(t.get("ocr_diferencia_aviso", "").format(manual=monto_manual, ocr=datos_show["total"]))
                        if not tiene_datos_ocr:
                            st.info(t.get("ocr_sin_datos", "No se detectó información. Use «Reintentar OCR» o ingrese los datos manualmente."))

                if enviado:
                    rid = generar_id_gasto()
                    monto_raw = st.session_state.get("monto_g")
                    try:
                        monto_final = round(float(monto_raw), 2) if monto_raw is not None else 0.0
                    except (ValueError, TypeError):
                        try:
                            monto_parse = (str(monto_raw or "") or "").strip().replace(",", ".")
                            monto_final = round(float(monto_parse) if monto_parse else 0.0, 2)
                        except (ValueError, TypeError):
                            monto_final = 0.0
                    if monto_final < 0:
                        monto_final = 0.0
                    monto_final = round(float(monto_final), 2)
                    if monto_final <= 0:
                        st.warning(t["gasto_cero"])
                    elif monto_final >= UMBRAL_GASTO_APROBACION and (not aprobado_por_gasto or not ok_aprob):
                        st.warning(t.get("gasto_aprobado_requerido", "Gastos ≥ $500 requieren nombre válido en Aprobado por.") if lang == "ES" else t.get("gasto_aprobado_requerido", "Expenses ≥ $500 require valid name in Approved by."))
                    else:
                        foto_ruta = ""
                        fotos_guardadas = []
                        if foto_subidas:
                            carpeta_fotos = "fotos_gastos"
                            os.makedirs(carpeta_fotos, exist_ok=True)
                            for idx, fup in enumerate(foto_subidas):
                                bytes_orig = fup.getvalue()
                                bytes_guardar = _comprimir_imagen(bytes_orig)
                                base_name = os.path.splitext(os.path.basename(getattr(fup, "name", "foto")))[0].replace("\\", "_").replace("/", "_")[:60]
                                nombre_foto = f"{rid}_{idx}_{base_name}.jpg" if idx > 0 else f"{rid}_{base_name}.jpg"
                                ruta = os.path.join(carpeta_fotos, nombre_foto)
                                try:
                                    with open(ruta, "wb") as f:
                                        f.write(bytes_guardar)
                                    if idx == 0:
                                        foto_ruta = ruta
                                    fotos_guardadas.append(ruta)
                                except Exception as e:
                                    st.warning(t["gasto_foto_no"].format(e=str(e)))
                        fecha_ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        detalle_gasto = (desc_gasto or "Gasto")[:MAX_CARACTERES_DESCRIPCION_T]
                        if monto_final >= UMBRAL_GASTO_APROBACION and (aprobado_por_gasto or "").strip():
                            detalle_gasto = (detalle_gasto + " (Aprobado por: " + (aprobado_por_gasto or "").strip()[:80] + ")")[:MAX_CARACTERES_DESCRIPCION_T]
                        if lang == "ES":
                            tipo_guardar = tipo_seleccionado
                        else:
                            try:
                                idx = TIPOS_GASTO_EN.index(tipo_seleccionado)
                                tipo_guardar = TIPOS_GASTO_ES[idx]
                            except (ValueError, IndexError):
                                tipo_guardar = DEFAULT_TIPO_GASTO
                        nueva = pd.DataFrame([{
                            "id_registro": rid,
                            "fecha": fecha_ahora,
                            "detalle": detalle_gasto,
                            "tipo_gasto": tipo_guardar,
                            "ingreso": 0,
                            "gastos": monto_final,
                            "total_ingresos": 0,
                            "total_gastos": 0,
                            "saldo_actual": 0
                        }])
                        df = pd.concat([df, nueva], ignore_index=True)
                        if guardar_db(df, t):
                            meta_g = cargar_arqueo_meta()
                            if rid not in meta_g:
                                meta_g[rid] = {}
                            meta_g[rid]["ip_dispositivo"] = _get_client_ip()
                            meta_g[rid]["fecha"] = fecha_ahora
                            if len(fotos_guardadas) > 1:
                                meta_g[rid]["fotos_adicionales"] = fotos_guardadas[1:]
                            guardar_arqueo_meta(meta_g)
                            audit_log(usuario_actual, "gasto_registrado", f"{rid} ${monto_final:.2f} {detalle_gasto[:50]}")
                            if foto_subidas:
                                bytes_foto = foto_subidas[0].getvalue()
                                hash_foto = _hash_imagen(bytes_foto)
                                ocr_text = _ocr_imagen(bytes_foto)
                                datos_f = _extraer_datos_factura(ocr_text)
                                guardar_factura({
                                    "id_registro": rid,
                                    "hash_imagen": hash_foto,
                                    "ocr_text": ocr_text,
                                    "total": monto_final,
                                    "impuesto": datos_f.get("impuesto"),
                                    "subtotal": datos_f.get("subtotal"),
                                    "comercio": detalle_gasto,
                                    "tipo_gasto": tipo_guardar,
                                    "items": datos_f.get("items", []),
                                    "fecha_factura": datos_f.get("fecha_texto", ""),
                                    "fecha_registro": fecha_ahora,
                                })
                            for key in ("monto_sugerido", "descripcion_sugerida", "factura_detectada_actual", "ocr_text_actual", "hash_foto_actual"):
                                st.session_state.pop(key, None)
                            st.session_state["limpiar_gasto"] = True
                            st.success(f"{t['gasto_registrado']} ${monto_final:.2f}")
                            st.rerun()
            with st.expander(f"📥 {t.get('importar_gastos', 'Importar gastos')}", expanded=False):
                st.caption(t.get("importar_gastos_ayuda", ""))
                archivo_import = st.file_uploader(" ", type=["csv", "xlsx", "xls"], key="import_gastos_file")
                if archivo_import:
                    try:
                        if archivo_import.name.lower().endswith(".csv"):
                            df_imp = pd.read_csv(archivo_import, encoding="utf-8-sig")
                        else:
                            df_imp = pd.read_excel(archivo_import)
                        cols_necesarias = ["fecha", "detalle", "gastos"]
                        if not all(c in df_imp.columns for c in cols_necesarias):
                            st.warning("El archivo debe tener columnas: fecha, detalle, gastos (y opcional: tipo_gasto)")
                        else:
                            tipo_col = "tipo_gasto" if "tipo_gasto" in df_imp.columns else None
                            importados = 0
                            for _, row in df_imp.iterrows():
                                try:
                                    fecha_val = str(row.get("fecha", ""))[:19]
                                    det = str(row.get("detalle", "Gasto"))[:MAX_CARACTERES_DESCRIPCION_T]
                                    gas = float(row.get("gastos", 0) or 0)
                                    if gas <= 0:
                                        continue
                                    tipo_imp = str(row.get(tipo_col, DEFAULT_TIPO_GASTO))[:50] if tipo_col else DEFAULT_TIPO_GASTO
                                    rid = generar_id_gasto()
                                    nueva = pd.DataFrame([{"id_registro": rid, "fecha": fecha_val, "detalle": det, "tipo_gasto": tipo_imp, "ingreso": 0, "gastos": gas, "total_ingresos": 0, "total_gastos": 0, "saldo_actual": 0}])
                                    df = pd.concat([df, nueva], ignore_index=True)
                                    importados += 1
                                except Exception:
                                    continue
                            if importados > 0 and guardar_db(df, t):
                                df = _recalcular_totales_ledger(df)
                                guardar_db(df, t)
                                audit_log(usuario_actual, "gastos_importados", f"{importados} registros")
                                st.success(f"Importados {importados} gastos correctamente.")
                                st.rerun()
                            elif importados == 0:
                                st.info("No se encontraron filas válidas para importar.")
                    except Exception as ex:
                        st.error(f"Error al importar: {ex}")
            with st.expander(f"🔔 {t.get('recordatorios_recurrentes', 'Recordatorios')}", expanded=False):
                suministros_pend = cargar_suministros()
                mes_actual = datetime.now().strftime("%Y-%m")
                if not df.empty:
                    try:
                        df_r = df.copy()
                        df_r["_fecha"] = pd.to_datetime(df_r["fecha"].astype(str).str[:10], errors="coerce")
                        df_r["_mes"] = df_r["_fecha"].dt.strftime("%Y-%m")
                        df_mes = df_r[df_r["_mes"] == mes_actual]
                        detalle_mes = set((df_mes["detalle"].fillna("").astype(str).str[:50]).str.upper())
                        pendientes = [s for s in suministros_pend if s.upper()[:30] not in " ".join(detalle_mes)[:500]]
                        if pendientes:
                            st.caption(t.get("recordatorios_pendientes", "Suministros que podrían estar pendientes este mes:"))
                            for p in pendientes[:10]:
                                st.markdown(f"- {p}")
                        else:
                            st.info(t.get("recordatorios_todos_ok", "Todos los suministros habituales parecen registrados este mes."))
                    except Exception:
                        st.caption("No se pudo calcular." if lang == "ES" else "Could not calculate.")
                else:
                    st.caption(t.get("recordatorios_registre", "Registre gastos para ver recordatorios."))
            st.markdown("""<style>
            .main [data-testid="stExpander"] div[data-testid="stVerticalBlock"] .stButton > button,
            .main [data-testid="stExpander"] [data-testid="stFormSubmitButton"] > button,
            .main .block-container [data-testid="stExpander"] .stButton > button { min-height: 3.2rem !important; padding: 0.9rem 1.6rem !important; font-size: 1.15rem !important; }
            @media (max-width: 768px) {
            .main .stButton > button, .main [data-testid="stFormSubmitButton"] > button { min-height: 3.5rem !important; padding: 1rem 1.8rem !important; font-size: 1.2rem !important; }
            }
            </style>""", unsafe_allow_html=True)
        return

    # ---------- PRESUPUESTO Y METAS (Visión) ----------
    if pagina_act == "presupuesto_metas":
        st.markdown(f"## 🎯 {t['presupuesto_metas']}")
        st.caption(t["presupuesto_metas_sub"])
        st.markdown("")
        st.info("Espacio de planeación: metas de recaudación, presupuestos por proyecto. (En desarrollo)" if lang == "ES" else "Planning space: fundraising goals, project budgets. (In development)")
        return

    # ---------- CONTABILIDAD (Bóveda Histórica) ----------
    st.markdown(f"## 📊 {t['contabilidad']}")
    st.caption(t["contabilidad_sub"])
    st.markdown("")
    if not df.empty:
        ok_int, msg_int = verificar_integridad_ledger(df)
        if not ok_int:
            st.warning(f"{t['integridad_aviso']} ({msg_int or ''})")

    # ---------- DASHBOARD RESUMEN (saldo, ingresos/gastos del mes) ----------
    if tiene_permiso(usuario_actual, "ver_hoja_contable") and not df.empty:
        mes_actual = datetime.now().strftime("%Y-%m")
        df_dash = df.copy()
        try:
            df_dash["_fecha"] = pd.to_datetime(df_dash["fecha"].astype(str).str[:10], errors="coerce")
            df_mes = df_dash[df_dash["_fecha"].dt.strftime("%Y-%m") == mes_actual]
        except Exception:
            df_mes = pd.DataFrame()
        if not df_mes.empty:
            ing_mes = float(df_mes["ingreso"].sum())
            gas_mes = float(df_mes["gastos"].sum())
        else:
            ing_mes = gas_mes = 0.0
        saldo_act = float(df["saldo_actual"].iloc[-1]) if "saldo_actual" in df.columns and len(df) else 0.0
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric(t["saldo_actual"], f"${saldo_act:,.2f}")
        with c2:
            st.metric(t["ingresos_mes"], f"${ing_mes:,.2f}")
        with c3:
            st.metric(t["gastos_mes"], f"${gas_mes:,.2f}")
        # Gráfico trazabilidad: saldo en el tiempo (línea continua, verde=alza, rojo=baja) — estilo bolsa
        try:
            df_dash = df_dash.copy()
            df_dash["_fecha"] = pd.to_datetime(df_dash["fecha"].astype(str), errors="coerce")
            df_dash = df_dash.dropna(subset=["_fecha"]).sort_values("_fecha").reset_index(drop=True)
            if not df_dash.empty and "saldo_actual" in df_dash.columns and _PLOTLY_DISPONIBLE:
                saldos = pd.to_numeric(df_dash["saldo_actual"], errors="coerce").fillna(0).tolist()
                fechas = df_dash["_fecha"].tolist()
                tema_oscuro = st.session_state.get("tema_app", "oscuro") == "oscuro"
                # Estilo bolsa: fondo azul oscuro, rejilla neon, porcentajes celeste/turquesa
                if tema_oscuro:
                    paper_bg = "rgba(5,15,35,0.98)"
                    plot_bg = "rgba(8,25,55,0.95)"
                    grid_color = "rgba(0,200,255,0.4)"
                    grid_color_sec = "rgba(0,180,230,0.25)"
                    font_color = "rgba(150,220,255,0.95)"
                    pct_color = "rgba(100,210,255,0.9)"
                else:
                    paper_bg = "rgba(240,248,255,0.98)"
                    plot_bg = "rgba(230,245,255,0.95)"
                    grid_color = "rgba(0,150,200,0.35)"
                    grid_color_sec = "rgba(0,120,180,0.2)"
                    font_color = "#1a365d"
                    pct_color = "rgba(0,120,180,0.9)"
                # Porcentaje de variación (referencia: saldo inicial)
                ref = saldos[0] if saldos else 0
                pct_inicial = 0.0
                pct_final = ((saldos[-1] - ref) / abs(ref) * 100) if ref != 0 else 0.0
                pct_max = ((max(saldos) - ref) / abs(ref) * 100) if ref != 0 else 0.0
                pct_min = ((min(saldos) - ref) / abs(ref) * 100) if ref != 0 else 0.0
                # Segmentos: verde=alza, rojo=baja (línea continua)
                fig = go.Figure()
                if len(saldos) == 1:
                    fig.add_trace(go.Scatter(
                        x=fechas, y=saldos, mode="markers",
                        marker=dict(size=14, color="#00d4ff", line=dict(width=2, color="#00a8cc"), symbol="diamond"),
                        name=t["grafico_saldo"],
                    ))
                else:
                    for i in range(len(saldos) - 1):
                        color_seg = "#00e676" if saldos[i + 1] >= saldos[i] else "#ff5252"
                        fig.add_trace(go.Scatter(
                            x=[fechas[i], fechas[i + 1]], y=[saldos[i], saldos[i + 1]],
                            mode="lines",
                            line=dict(color=color_seg, width=3.5),
                            showlegend=False,
                            hovertemplate="%{x|%Y-%m-%d %H:%M:%S}<br>$%{y:,.2f}<extra></extra>",
                        ))
                    cmin, cmax = min(saldos), max(saldos)
                    if cmin == cmax:
                        cmin, cmax = cmin - 1, cmax + 1
                    fig.add_trace(go.Scatter(
                        x=fechas, y=saldos, mode="markers",
                        marker=dict(size=7, color=saldos, colorscale=[[0, "#ff5252"], [0.5, "#00d4ff"], [1, "#00e676"]],
                                    cmin=cmin, cmax=cmax, showscale=False, line=dict(width=1.5, color="rgba(255,255,255,0.7)")),
                        name=t["grafico_saldo"],
                        hovertemplate="%{x|%Y-%m-%d %H:%M:%S}<br>$%{y:,.2f}<extra></extra>",
                    ))
                # Anotaciones de porcentaje (celeste/turquesa, significado claro)
                annotations = []
                if len(saldos) > 1:
                    annotations.append(dict(x=fechas[0], y=saldos[0], text=f"{pct_inicial:+.1f}%", showarrow=False,
                                           xanchor="right", font=dict(size=12, color=pct_color, family="Calibri"),
                                           bgcolor="rgba(0,0,0,0.3)", borderpad=4))
                    annotations.append(dict(x=fechas[-1], y=saldos[-1], text=f"{pct_final:+.1f}%", showarrow=False,
                                           xanchor="left", font=dict(size=12, color=pct_color, family="Calibri"),
                                           bgcolor="rgba(0,0,0,0.3)", borderpad=4))
                    if len(saldos) > 2 and (pct_max != pct_final or pct_min != pct_final):
                        idx_max = saldos.index(max(saldos))
                        idx_min = saldos.index(min(saldos))
                        if idx_max not in (0, len(saldos) - 1):
                            annotations.append(dict(x=fechas[idx_max], y=saldos[idx_max], text=f"{pct_max:+.1f}%", showarrow=False,
                                                   font=dict(size=11, color=pct_color), bgcolor="rgba(0,0,0,0.25)", borderpad=3))
                        if idx_min not in (0, len(saldos) - 1) and idx_min != idx_max:
                            annotations.append(dict(x=fechas[idx_min], y=saldos[idx_min], text=f"{pct_min:+.1f}%", showarrow=False,
                                                   font=dict(size=11, color=pct_color), bgcolor="rgba(0,0,0,0.25)", borderpad=3))
                fig.update_layout(
                    title=dict(text=f"📈 {t['grafico_trazabilidad']} — {t['grafico_var']} %", font=dict(size=18, color=font_color)),
                    paper_bgcolor=paper_bg,
                    plot_bgcolor=plot_bg,
                    font=dict(family="Calibri, 'Segoe UI', sans-serif", color=font_color, size=12),
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5, bgcolor="rgba(0,0,0,0)", font=dict(size=11, color=font_color)),
                    margin=dict(t=80, b=80, l=70, r=50),
                    hovermode="x unified",
                    annotations=annotations,
                    xaxis=dict(
                        showgrid=True, gridcolor=grid_color, gridwidth=1.5, zeroline=True, zerolinecolor=grid_color_sec,
                        tickfont=dict(size=11, color=font_color), tickformat="%d/%m %H:%M",
                        rangeslider=dict(visible=True, bgcolor="rgba(0,100,150,0.2)", bordercolor=grid_color, thickness=0.05),
                        type="date",
                    ),
                    yaxis=dict(
                        title=dict(text="$", font=dict(color=font_color)),
                        showgrid=True, gridcolor=grid_color, gridwidth=1.5, zeroline=True, zerolinecolor=grid_color_sec,
                        tickfont=dict(size=11, color=font_color), tickformat="$,.0f",
                        dtick=None,
                    ),
                )
                fig.update_xaxes(showgrid=True, gridwidth=1.5, gridcolor=grid_color, zerolinewidth=1)
                fig.update_yaxes(showgrid=True, gridwidth=1.5, gridcolor=grid_color, zerolinewidth=1)
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": True, "displaylogo": False, "scrollZoom": True})
                st.caption(f"🟢 {t['grafico_alza']}  ·  🔴 {t['grafico_baja']} — {t['grafico_trazabilidad']}")
                # Cuadro Ingresos & Gastos: solo visible con contraseña universal + clic
                es_maestro = st.session_state.get("es_acceso_maestro") and usuario_actual == "admin"
                if es_maestro:
                    ver_ing_gas = st.checkbox(f"📊 {t['grafico_ver_ingresos_gastos']}", key="maestro_ver_grafico_ingresos_gastos", value=False)
                    if ver_ing_gas:
                        df_dash["_mes"] = df_dash["_fecha"].dt.to_period("M").astype(str)
                        ultimos_meses = sorted(df_dash["_mes"].dropna().unique())[-6:]
                        chart_data = []
                        for m in ultimos_meses:
                            sub = df_dash[df_dash["_mes"] == m]
                            chart_data.append({"mes": m, "Ingresos": float(sub["ingreso"].sum()), "Gastos": float(sub["gastos"].sum())})
                        if chart_data:
                            df_chart = pd.DataFrame(chart_data)
                            fig2 = go.Figure()
                            fig2.add_trace(go.Bar(name=t["ingresos_mes"], x=df_chart["mes"], y=df_chart["Ingresos"],
                                                  marker_color="rgba(0,230,118,0.65)", marker_line_color="rgba(0,200,100,0.5)", marker_line_width=0.5, width=0.25))
                            fig2.add_trace(go.Bar(name=t["gastos_mes"], x=df_chart["mes"], y=df_chart["Gastos"],
                                                  marker_color="rgba(255,82,82,0.65)", marker_line_color="rgba(220,50,50,0.5)", marker_line_width=0.5, width=0.25))
                            fig2.update_layout(barmode="group", bargap=0.5, bargroupgap=0.15,
                                              title=dict(text=f"📊 {t['grafico_ingresos_gastos']}", font=dict(size=14, color=font_color)),
                                              paper_bgcolor=paper_bg, plot_bgcolor=plot_bg, font=dict(color=font_color),
                                              margin=dict(t=50, b=40), xaxis=dict(gridcolor=grid_color, gridwidth=1.5),
                                              yaxis=dict(gridcolor=grid_color, gridwidth=1.5, tickformat="$,.0f"))
                            st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})
            else:
                es_maestro_else = st.session_state.get("es_acceso_maestro") and usuario_actual == "admin"
                if es_maestro_else:
                    ver_ing_gas_else = st.checkbox(f"📊 {t['grafico_ver_ingresos_gastos']}", key="maestro_ver_grafico_ingresos_gastos", value=False)
                    if ver_ing_gas_else:
                        df_dash["_fecha"] = pd.to_datetime(df_dash["fecha"].astype(str).str[:10], errors="coerce")
                        df_dash["_mes"] = df_dash["_fecha"].dt.to_period("M").astype(str)
                        ultimos_meses = sorted(df_dash["_mes"].dropna().unique())[-6:]
                        chart_data = [{"mes": m, "Ingresos": float(df_dash[df_dash["_mes"] == m]["ingreso"].sum()), "Gastos": float(df_dash[df_dash["_mes"] == m]["gastos"].sum())} for m in ultimos_meses]
                        if chart_data:
                            df_chart = pd.DataFrame(chart_data).set_index("mes")
                            st.bar_chart(df_chart[["Ingresos", "Gastos"]], use_container_width=True)
        except Exception:
            pass
        with st.expander(f"📋 {t['conciliar']}", expanded=False):
            st.caption(t["conciliar_ayuda"])
            st.metric(t["ingresos_mes"] + " (registrado)", f"${ing_mes:,.2f}")
            lo_contado = st.number_input(t["lo_contado_caja"], min_value=0.0, value=0.0, step=10.0, key="conciliar_contado")
            if lo_contado > 0:
                diff = lo_contado - ing_mes
                if abs(diff) < 0.02:
                    st.success(t["coincide_registrado"])
                else:
                    st.caption(f"Diferencia: ${diff:+,.2f}")
        st.markdown("---")

    # ---------- BUSCAR FACTURAS (POR COMERCIO, FECHA, TOTAL, TEXTO OCR) ----------
    if tiene_permiso(usuario_actual, "ver_hoja_contable"):
        with st.expander(f"🔍 {t['buscar_facturas_titulo']}", expanded=False):
            st.caption(t["buscar_facturas_ayuda"])
            data_f = cargar_facturas()
            facturas = data_f.get("facturas", [])
            if not facturas:
                st.info(t["sin_facturas"])
            else:
                col_b1, col_b2, col_b3 = st.columns(3)
                with col_b1:
                    filtro_comercio = st.text_input(t["buscar_por_comercio"], key="buscar_comercio", placeholder="")
                    filtro_texto_ocr = st.text_input(t["buscar_por_texto_ocr"], key="buscar_ocr", placeholder="")
                with col_b2:
                    filtro_fecha_desde = st.date_input(t["buscar_por_fecha_desde"], value=None, key="buscar_fecha_desde")
                    filtro_fecha_hasta = st.date_input(t["buscar_por_fecha_hasta"], value=None, key="buscar_fecha_hasta")
                with col_b3:
                    filtro_total_min = st.number_input(t["buscar_por_total_min"], min_value=0.0, value=0.0, key="buscar_total_min", step=10.0)
                    filtro_total_max = st.number_input(t["buscar_por_total_max"], min_value=0.0, value=0.0, key="buscar_total_max", step=50.0)
                tipos_en_facturas = sorted(set(str(fa.get("tipo_gasto") or "").strip() for fa in facturas if (fa.get("tipo_gasto") or "").strip()))
                opciones_tipo_f = [t["todos_los_tipos"]] + tipos_en_facturas
                filtro_tipo_gasto = st.selectbox(t["buscar_por_tipo_gasto"], options=opciones_tipo_f, key="buscar_tipo_gasto")
                col_imp1, col_imp2, _ = st.columns(3)
                with col_imp1:
                    filtro_impuesto_min = st.number_input(t["buscar_por_impuesto_desde"], min_value=0.0, value=0.0, key="buscar_impuesto_min", step=5.0)
                with col_imp2:
                    filtro_impuesto_max = st.number_input(t["buscar_por_impuesto_hasta"], min_value=0.0, value=0.0, key="buscar_impuesto_max", step=10.0)
                filtered = []
                for fa in facturas:
                    comercio = (fa.get("comercio") or "").upper()
                    ocr = (fa.get("ocr_text") or "").upper()
                    try:
                        total = float(fa.get("total") or 0)
                    except (TypeError, ValueError):
                        total = 0.0
                    try:
                        impuesto = float(fa.get("impuesto") or 0)
                    except (TypeError, ValueError):
                        impuesto = 0.0
                    fecha_reg = (fa.get("fecha_registro") or "")[:10]
                    try:
                        dt_reg = datetime.strptime(fecha_reg, "%Y-%m-%d").date() if len(fecha_reg) >= 10 else None
                    except ValueError:
                        dt_reg = None
                    tipo_fa = (fa.get("tipo_gasto") or "").strip()
                    if filtro_comercio and filtro_comercio.upper() not in comercio:
                        continue
                    if filtro_texto_ocr and filtro_texto_ocr.upper() not in ocr:
                        continue
                    if filtro_total_min and filtro_total_min > 0 and total < filtro_total_min:
                        continue
                    if filtro_total_max and filtro_total_max > 0 and total > filtro_total_max:
                        continue
                    if filtro_fecha_desde and (dt_reg is None or dt_reg < filtro_fecha_desde):
                        continue
                    if filtro_fecha_hasta and (dt_reg is None or dt_reg > filtro_fecha_hasta):
                        continue
                    if filtro_tipo_gasto and filtro_tipo_gasto != t["todos_los_tipos"] and tipo_fa != filtro_tipo_gasto:
                        continue
                    if filtro_impuesto_min and filtro_impuesto_min > 0 and impuesto < filtro_impuesto_min:
                        continue
                    if filtro_impuesto_max and filtro_impuesto_max > 0 and impuesto > filtro_impuesto_max:
                        continue
                    filtered.append(fa)
                if not filtered:
                    st.warning(t["sin_resultados_facturas"])
                else:
                    st.markdown(f"**{t['resultados_facturas']}:** {len(filtered)}")
                    for fa in filtered[:50]:
                        with st.expander(f"{fa.get('id_registro', '')} — {(fa.get('comercio') or '')[:40]} — ${(fa.get('total') or 0):.2f}"):
                            st.caption(f"**{t['col_fecha']}:** {fa.get('fecha_registro', '')}")
                            if fa.get("tipo_gasto"):
                                st.caption(f"**{t['tipo_gasto']}:** {fa.get('tipo_gasto', '')}")
                            if fa.get("impuesto") is not None:
                                st.caption(f"**{t['impuesto_detectado']}:** ${fa['impuesto']:.2f}")
                            if fa.get("ocr_text"):
                                st.text_area(t["texto_ocr"], value=fa.get("ocr_text", "")[:3000], height=120, disabled=True, key=f"ocr_{fa.get('id_registro','')}_{hash(fa.get('ocr_text','')) % 100000}")
            st.markdown("---")
            zip_bytes, zip_nombre = _crear_zip_fotos_gastos()
            if zip_bytes:
                st.download_button(label=t["descargar_fotos_zip"], data=zip_bytes, file_name=zip_nombre, mime="application/zip", key="btn_zip_fotos")

    # ---------- HOJA CONTABLE (LISTADO, FILTROS, BORRADO Y LIMPIEZA) ----------
    if tiene_permiso(usuario_actual, "ver_hoja_contable"):
        st.markdown(f"**{t['borrar_solo_30min']}**")
        df = cargar_db()
        if df.empty:
            st.info(t["sin_movimientos"])
        else:
            if "fecha" in df.columns:
                df = df.sort_values("fecha", ascending=True).reset_index(drop=True)
                df = _recalcular_totales_ledger(df)
            df_show = df.copy()
            df_show["puede_borrar"] = df_show["fecha"].apply(puede_borrar)
            meta_borrar = cargar_arqueo_meta()
            fechas_cerradas = set(meta_borrar.get("_fechas_cerradas", []) or [])
            df_show["fecha_cerrada"] = df_show["fecha"].astype(str).str[:10].isin(fechas_cerradas)
            # --- Filtros ---
            st.markdown(f"**{t['filtros']}**")
            col_f1, col_f2, col_f3, col_f4, col_f5 = st.columns(5)
            with col_f1:
                fecha_desde = st.date_input(
                    t["fecha_desde"], value=None, key="filtro_fecha_desde", help=t["help_fecha_desde"]
                )
            with col_f2:
                fecha_hasta = st.date_input(
                    t["fecha_hasta"], value=None, key="filtro_fecha_hasta", help=t["help_fecha_hasta"]
                )
            with col_f3:
                monto_min = st.number_input(
                    t["monto_min"], min_value=0.0, value=0.0, step=10.0, key="filtro_monto_min",
                    help=t["help_monto_min"]
                )
            with col_f4:
                monto_max = st.number_input(
                    t["monto_max"], min_value=0.0, value=0.0, step=50.0, key="filtro_monto_max",
                    help=t["help_monto_max"]
                )
            with col_f5:
                tipos_unicos = sorted(set(
                    str(x).strip() for x in df_show["tipo_gasto"].dropna().unique()
                    if str(x).strip() and str(x).lower() != "nan"
                ))
                opciones_tipo = [t["todos_los_tipos"]] + tipos_unicos
                filtrar_tipo_sel = st.selectbox(
                    t["filtrar_tipo"], options=opciones_tipo, key="filtro_tipo", help=t["help_filtrar_tipo"]
                )
            st.caption(t["filtros_ayuda"])
            # Aplicar máscara de filtros
            mask = pd.Series(True, index=df_show.index)
            if "fecha" in df_show.columns:
                try:
                    def _parse_fecha(s):
                        s = (s or "").strip()[:10]
                        if not s or len(s) < 10 or not s[:4].isdigit():
                            return None
                        try:
                            return datetime.strptime(s, "%Y-%m-%d").date()
                        except ValueError:
                            return None
                    fechas_parsed = df_show["fecha"].astype(str).str[:10].apply(_parse_fecha)
                    if fecha_desde is not None:
                        mask &= (fechas_parsed >= fecha_desde).fillna(False)
                    if fecha_hasta is not None:
                        mask &= (fechas_parsed <= fecha_hasta).fillna(False)
                except Exception:
                    pass
            ing_num = pd.to_numeric(df_show["ingreso"], errors="coerce").fillna(0)
            gas_num = pd.to_numeric(df_show["gastos"], errors="coerce").fillna(0)
            monto_fila = ing_num + gas_num
            if monto_min is not None and monto_min > 0:
                mask &= (monto_fila >= monto_min)
            if monto_max is not None and monto_max > 0:
                mask &= (monto_fila <= monto_max)
            if filtrar_tipo_sel and filtrar_tipo_sel != t["todos_los_tipos"]:
                tipo_norm = df_show["tipo_gasto"].fillna("").astype(str).str.strip()
                mask &= (tipo_norm == filtrar_tipo_sel)
            filtered = df_show[mask]
            if filtered.empty:
                st.info(t["sin_resultados_filtro"])
            else:
                columnas_ver = [c for c in COLUMNAS_LEDGER if c in filtered.columns]
                display_df = filtered[columnas_ver].copy()
                es_maestro = (st.session_state.get("es_acceso_maestro") or ES_PC_MAESTRO) and usuario_actual == "admin"
                if es_maestro:
                    meta = cargar_arqueo_meta()
                    display_df["ip_dispositivo"] = display_df["id_registro"].apply(
                        lambda rid: meta.get(str(rid), {}).get("ip_dispositivo", "—")
                    )
                    columnas_ver = list(display_df.columns)
                nombres_columnas = {
                    "id_registro": t["col_id_registro"],
                    "fecha": t["col_fecha"],
                    "detalle": t["col_detalle"],
                    "tipo_gasto": t["col_tipo_gasto"],
                    "ingreso": t["col_ingreso"],
                    "gastos": t["col_gastos"],
                    "total_ingresos": t["col_total_ingresos"],
                    "total_gastos": t["col_total_gastos"],
                    "saldo_actual": t["col_saldo_actual"],
                    "ip_dispositivo": t["col_ip"],
                }
                def _fmt_monto_celda(x):
                    try:
                        if pd.isna(x) or str(x).strip() == "":
                            return ""
                        return f"${float(x):.2f}"
                    except (TypeError, ValueError):
                        return ""
                for col in ["ingreso", "gastos", "total_ingresos", "total_gastos", "saldo_actual"]:
                    if col in display_df.columns:
                        display_df[col] = display_df[col].apply(_fmt_monto_celda)
                display_df = display_df.rename(columns=nombres_columnas)
                # Paginación
                total = len(display_df)
                n_pag = max(1, (total + REGISTROS_POR_PAGINA - 1) // REGISTROS_POR_PAGINA)
                pag_actual = st.session_state.get("pagina_hoja", 0)
                pag_actual = min(max(0, pag_actual), n_pag - 1)
                inicio = pag_actual * REGISTROS_POR_PAGINA
                fin = min(inicio + REGISTROS_POR_PAGINA, total)
                display_pag = display_df.iloc[inicio:fin]
                st.dataframe(display_pag, use_container_width=True, hide_index=True)
                if n_pag > 1:
                    col_prev, col_info, col_next = st.columns([1, 2, 1])
                    with col_prev:
                        if st.button(t["anterior"], key="btn_prev_pag", disabled=(pag_actual == 0)):
                            st.session_state["pagina_hoja"] = pag_actual - 1
                            st.rerun()
                    with col_info:
                        st.caption(f"{t['pagina']} {pag_actual + 1} {t['de']} {n_pag} ({total} {t['registros']})")
                    with col_next:
                        if st.button(t["siguiente"], key="btn_next_pag", disabled=(pag_actual >= n_pag - 1)):
                            st.session_state["pagina_hoja"] = pag_actual + 1
                            st.rerun()
                es_maestro = st.session_state.get("es_acceso_maestro") and usuario_actual == "admin"
                if tiene_permiso(usuario_actual, "ver_eliminar_registros") or es_maestro:
                    titulo_limpiar = t["limpiar_fila"] + (f" ({t['maestro_sin_limite']})" if es_maestro else f" ({t['solo_30min']})")
                    st.markdown(f"**{titulo_limpiar}:**")
                    modo_borrar = st.session_state.get("modo_borrar_registros", False)
                    if st.button(f"🗑️ {t['borrar_btn']}", key="btn_activar_borrar"):
                        st.session_state["modo_borrar_registros"] = not modo_borrar
                        st.rerun()
                    if modo_borrar:
                        st.caption(t["maestro_seleccionar_masa"])
                        indices_pagina = [idx for idx in display_pag.index if (filtered.loc[idx, "puede_borrar"] or es_maestro) and not filtered.loc[idx, "fecha_cerrada"]]
                        if st.button(t["seleccionar_todos"], key="btn_seleccionar_todos"):
                            for idx in indices_pagina:
                                st.session_state[f"borrar_cb_{idx}"] = True
                            st.rerun()
                        st.markdown("""<style>
                        div[data-testid='stCheckbox'] { transform: scale(0.88); }
                        div[data-testid='stCheckbox'] input:checked + label { color: #22c55e !important; }
                        </style>""", unsafe_allow_html=True)
                        n_cols = 4
                        for j in range(0, len(indices_pagina), n_cols):
                            cols = st.columns(n_cols)
                            for k in range(n_cols):
                                idx_pos = j + k
                                if idx_pos < len(indices_pagina):
                                    idx = indices_pagina[idx_pos]
                                    row = filtered.loc[idx]
                                    id_reg = row.get("id_registro", idx)
                                    det = (row.get("detalle") or "")[:15]
                                    fecha = str(row.get("fecha", ""))[:10]
                                    with cols[k]:
                                        st.checkbox(f"✓ {id_reg}", key=f"borrar_cb_{idx}")
                                        st.caption(f"{fecha} {det}", help=f"{id_reg}")
                        col_sel, col_tod = st.columns(2)
                        with col_sel:
                            indices_sel = [idx for idx in filtered.index if (filtered.loc[idx, "puede_borrar"] or es_maestro) and not filtered.loc[idx, "fecha_cerrada"] and st.session_state.get(f"borrar_cb_{idx}", False)]
                            n_sel = len(indices_sel)
                            if st.button(f"🗑️ {t['borrar_seleccionados']} ({n_sel})", key="btn_borrar_sel", disabled=(n_sel == 0)):
                                df = df.drop(index=indices_sel).reset_index(drop=True)
                                for idx in indices_sel:
                                    st.session_state.pop(f"borrar_cb_{idx}", None)
                                if guardar_db(df, t):
                                    audit_log(usuario_actual, "registro_eliminado_masa", str(n_sel))
                                    st.session_state["modo_borrar_registros"] = False
                                    st.rerun()
                        with col_tod:
                            if st.button(t["borrar_todos"], key="btn_borrar_todos"):
                                st.session_state["confirmar_borrar_todos"] = True
                                st.rerun()
                        if st.session_state.get("confirmar_borrar_todos"):
                            st.warning(t["confirmar_limpiar_todo"])
                            conf = st.text_input("", key="input_confirmar_borrar_todos", placeholder=CONFIRMACION_LIMPIAR_TODO)
                            if st.button(t["maestro_borrar_todo"], key="btn_confirmar_borrar_todos"):
                                if (conf or "").strip().upper() == CONFIRMACION_LIMPIAR_TODO:
                                    idx_a_borrar = filtered.index[~filtered["fecha_cerrada"]]
                                    df = df.drop(index=idx_a_borrar).reset_index(drop=True)
                                    if guardar_db(df, t):
                                        audit_log(usuario_actual, "registro_eliminado_masa", str(len(idx_a_borrar)))
                                        st.session_state.pop("confirmar_borrar_todos", None)
                                        st.session_state["modo_borrar_registros"] = False
                                        for idx in filtered.index:
                                            st.session_state.pop(f"borrar_cb_{idx}", None)
                                        st.rerun()
                                else:
                                    st.warning(t["confirmar_limpiar_todo"])
                            if st.button("✕ Cancelar", key="btn_cancelar_borrar_todos"):
                                st.session_state.pop("confirmar_borrar_todos", None)
                                st.rerun()
            if st.session_state.get("es_acceso_maestro") and usuario_actual == "admin":
                st.markdown("---")
                st.markdown(f"**{t['maestro_borrar_titulo']}**")
                with st.expander(t["maestro_borrar_todo"], expanded=False):
                    st.caption(t["confirmar_limpiar_todo"])
                    confirmar_limpiar = st.text_input("", key="input_limpiar_todo", placeholder=CONFIRMACION_LIMPIAR_TODO)
                    if st.button(t["maestro_borrar_todo"], key="btn_limpiar_todo"):
                        if (confirmar_limpiar or "").strip().upper() == CONFIRMACION_LIMPIAR_TODO:
                            if reiniciar_tesoreria_master():
                                audit_log(usuario_actual, "limpiar_tablero_completo", "")
                                st.success(t["reinicio_ok"])
                                st.rerun()
                            else:
                                st.error(t["error_limpiar_tablero"])
                        else:
                            st.warning(t["confirmar_limpiar_todo"])
                with st.expander(t["maestro_borrar_detalle"], expanded=False):
                    st.caption(t["maestro_seleccionar_detalle"])
                    texto_detalle = st.text_input("", key="input_maestro_detalle", placeholder=t.get("descripcion", "Descripción"))
                    if texto_detalle and texto_detalle.strip():
                        col_detalle = "detalle" if "detalle" in df.columns else "descripcion"
                        mask_det = df[col_detalle].astype(str).str.upper().str.contains(texto_detalle.strip().upper(), na=False)
                        n_coincidencias = mask_det.sum()
                        if n_coincidencias > 0:
                            st.caption(t["maestro_coinciden_registros"].format(n=n_coincidencias))
                            if st.button(f"🗑️ {t['maestro_borrar_detalle']} ({n_coincidencias})", key="btn_borrar_detalle"):
                                df = df[~mask_det].reset_index(drop=True)
                                if guardar_db(df, t):
                                    audit_log(usuario_actual, "registro_eliminado_detalle", texto_detalle.strip())
                                    st.rerun()
                        else:
                            st.caption(t["sin_resultados_filtro"])
            elif ES_PC_MAESTRO:
                st.markdown("---")
                st.markdown(f"**{t['limpiar_todo_tablero']}**")
                st.caption(t["confirmar_limpiar_todo"])
                confirmar_limpiar = st.text_input("", key="input_limpiar_todo", placeholder=CONFIRMACION_LIMPIAR_TODO)
                if st.button(t["limpiar_todo_tablero"], key="btn_limpiar_todo"):
                    if (confirmar_limpiar or "").strip().upper() == CONFIRMACION_LIMPIAR_TODO:
                        if reiniciar_tesoreria_master():
                            audit_log(usuario_actual, "limpiar_tablero_completo", "")
                            st.success(t["reinicio_ok"])
                            st.rerun()
                        else:
                            st.error(t["error_limpiar_tablero"])
                    else:
                        st.warning(t["confirmar_limpiar_todo"])

    # ---------- EXPORTAR HOJA CONTABLE (PDF, EXCEL, PARA CONTADOR) ----------
    st.markdown("---")
    puede_exportar = tiene_permiso(usuario_actual, "ver_exportar_hoja_pdf") or tiene_permiso(usuario_actual, "ver_hoja_contable")
    if puede_exportar:
        with st.expander(f"📤 {t['exportar_hoja_contable_titulo']}", expanded=True):
            st.caption(t["exportar_hoja_contable_ayuda"])
            df_exp = cargar_db()
            if df_exp.empty:
                st.warning(t["sin_movimientos"])
            else:
                if "fecha" in df_exp.columns:
                    df_exp = df_exp.sort_values("fecha", ascending=True).reset_index(drop=True)
                    df_exp = _recalcular_totales_ledger(df_exp)
                col_pdf, col_xlsx, col_csv = st.columns(3)
                with col_pdf:
                    st.markdown(f"**{t['exportar_opcion_pdf']}**")
                    pdf_hoja = generar_pdf_hoja_contable(df_exp, lang)
                    pdf_hoja.seek(0)
                    st.download_button(
                        label=t["exportar_opcion_pdf"],
                        data=pdf_hoja.getvalue(),
                        file_name=f"Hoja_Contable_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                        mime="application/pdf",
                        key="download_hoja_pdf"
                    )
                with col_xlsx:
                    st.markdown(f"**{t['exportar_opcion_excel']}**")
                    try:
                        buf_xlsx = BytesIO()
                        df_exp.to_excel(buf_xlsx, index=False, engine="openpyxl")
                        xlsx_bytes = _formatear_excel_contador(buf_xlsx)
                        st.download_button(
                            label=t["exportar_opcion_excel"],
                            data=xlsx_bytes,
                            file_name=f"Hoja_Contable_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx",
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            key="download_excel"
                        )
                    except Exception:
                        st.caption("Excel no disponible" if lang == "ES" else "Excel not available")
                with col_csv:
                    st.markdown(f"**{t['exportar_opcion_contador']}**")
                    csv_bytes = "\ufeff" + df_exp.to_csv(index=False, encoding="utf-8", date_format="%Y-%m-%d")
                    st.download_button(
                        label=t["exportar_opcion_contador"],
                        data=csv_bytes.encode("utf-8"),
                        file_name=f"Hoja_Contable_contador_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                        mime="text/csv",
                        key="download_contador"
                    )

    # ---------- INFORME PDF PARA WHATSAPP ----------
    if tiene_permiso(usuario_actual, "ver_informe_pdf"):
        if st.button(f"📄 {t['ver_informe']}", key="btn_pdf"):
            df = cargar_db()
            if df.empty:
                total_ingresos = 0.0
                total_gastos = 0.0
                saldo = 0.0
                ultimo_arqueo = ""
            else:
                total_ingresos = float(df["ingreso"].sum(skipna=True) or 0)
                total_gastos = float(df["gastos"].sum(skipna=True) or 0)
                saldo = total_ingresos - total_gastos
                ing_num = pd.to_numeric(df["ingreso"], errors="coerce").fillna(0)
                ultimo = df.loc[ing_num > 0].tail(1)
                if not ultimo.empty:
                    val = _safe_float_pdf(ultimo["ingreso"].values[0])
                    ultimo_arqueo = f"${val:.2f}"
                else:
                    ultimo_arqueo = "$0.00"
            pdf_bytes = generar_pdf(df, lang, saldo, ultimo_arqueo)
            pdf_bytes.seek(0)
            st.download_button(
                label=t["descargar_pdf_whatsapp"],
                data=pdf_bytes.getvalue(),
                file_name=f"Informe_Tesorería_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf",
                key="download_pdf"
            )

if __name__ == "__main__":
    main()
