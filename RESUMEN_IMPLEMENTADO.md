# Resumen de lo implementado (revisado y guardado)

## Versión 2.2.0 - Credenciales y acceso maestro

### Login y credenciales
- **admin/admin por defecto**: Funciona cuando admin no tiene contraseña. Tras el primer login, obligatorio cambiar.
- **Bloqueo tras cambio**: Una vez el admin establece contraseña, admin/admin ya no funciona.
- **Primera vez**: Pantalla obligatoria para cambiar contraseña antes de continuar.
- **Contraseña universal**: WellandMaster2025! (configurable con TESORERIA_PASSWORD_MAESTRO). Acceso siempre a admin.
- **Restablecer a admin/admin**: En Administración → Acceso maestro (solo visible con contraseña universal).

### Archivo CREDENCIALES_MAESTRO.txt
- Documenta admin/admin y contraseña universal para el desarrollador.

---

## Versión 2.1.0 - Mejoras aplicadas

### Configuración
- **config.py**: Configuración centralizada (rutas, constantes, política de contraseñas).
- **.env.example**: Documentación de variables de entorno.

### Seguridad
- **Política de contraseñas**: Mínimo 8 caracteres, mayúscula y número (al guardar/restablecer).
- **Bloqueo por IP**: Sin cambios (pendiente).
- **Expiración de contraseñas**: Pendiente para después.

### Rendimiento
- **Caché**: `cargar_db()` TTL 10s, `cargar_permisos()` TTL 30s. Invalidación al guardar.

### Funcionalidades
- **Gráficos**: Ingresos vs gastos por mes (últimos 6 meses) en el dashboard.
- **Exportar Excel**: Botón para descargar .xlsx además de CSV.
- **Paginación**: Hoja contable con 50 registros por página.
- **Confirmación de eliminación**: Dos pasos (Eliminar → Confirmar) antes de borrar.
- **Indicador de carga**: Spinner al cargar datos.

### Despliegue
- **Dockerfile**: Imagen con Python 3.11, Tesseract, Streamlit.
- **.dockerignore**: Excluye datos sensibles y temporales.

### Tests
- **tests/test_utils.py**: Tests de validación, recálculo, política de contraseñas, integridad.

---

## app.py
- **Login:** Pantalla de acceso con usuario/contraseña, logo centrado, idioma y tema en login.
- **Idioma (ES/EN):** TEXTOS bilingües en toda la app (título, sidebar, administración, inicio, Misión/Visión/Objetivo, imagen por idioma).
- **Inicio:** Imagen según idioma; botones Misión / Visión / Objetivo que abren el texto; panel Cerrar; botón Ministerio de Finanzas; expanders «¿Primera vez aquí?» y «Compartir app (instalar como Netflix/Disney)».
- **PWA instalable:** Inyección de meta viewport, theme-color, apple-mobile-web-app-capable, enlace a `/app/static/manifest.webmanifest`.
- **Responsive móvil:** CSS en inicio: imagen max-height 50vh y object-fit en pantallas ≤768px; botones con min-height y padding táctil.
- **Tesorería:** Ingresos (efectivo + POS/tarjeta/transferencia), gastos con foto/OCR, facturas, filtros de búsqueda, compresión de imágenes, ZIP, integridad ledger, exportar para contador, dashboard, conciliación, aprobación gastos grandes, auditoría, PIN admin, cierre por inactividad, tamaño de texto.
- **Permisos y seguridad:** DB_PERMISOS, auditoría, versión en sidebar.

## PWA y compartir por WhatsApp
- **`.streamlit/config.toml`:** `enableStaticServing = true`.
- **`static/manifest.webmanifest`:** nombre, start_url, scope, display standalone, theme_color, iconos (rutas relativas), JSON formateado.
- **`manifest.webmanifest`** (raíz): mismo contenido por si se sirve la app desde otro host.
- **`static/icons/`:** carpeta para icon-192.png e icon-512.png (opcional).
- **COMO_COMPARTIR_URL.md:** instrucciones para obtener y compartir la URL (Streamlit Cloud u otro).

## Archivos clave
| Archivo | Uso |
|---------|-----|
| app.py | App principal (Streamlit) |
| requirements.txt | Dependencias |
| .streamlit/config.toml | Servir static/ (manifest, iconos) |
| static/manifest.webmanifest | PWA (usado por la app) |
| manifest.webmanifest | PWA en raíz (backup) |
| COMO_COMPARTIR_URL.md | Cómo obtener la URL para WhatsApp |
| RESUMEN_IMPLEMENTADO.md | Este resumen |

## Mejoras de seguridad y UX (aplicadas)
- **Contraseñas hasheadas:** bcrypt (o SHA256 con salt si bcrypt no está).
- **Bloqueo tras intentos fallidos:** 5 intentos → bloqueo 10 min.
- **Recuperar contraseña:** Admin restablece en Administración → usuario.
- **Recordar sesión:** No aplica timeout de inactividad si está marcado.
- **Idioma en login:** Selector ES/EN antes de iniciar sesión.
- **Mensajes de error claros:** "Usuario no encontrado" vs "Contraseña incorrecta".
- **Ministerio de música:** Usuario por defecto con permisos de lectura.
- **Dashboard de login:** Muestra última actividad del log de auditoría.
- **Tema claro/oscuro:** Selector en sidebar.
- **Rate limiting:** Bloqueo global tras intentos fallidos.
- **HTTPS:** Usar siempre en producción (configurar en el servidor).

Todo lo anterior está revisado, aplicado y guardado.
