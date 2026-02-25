# Informe: Error "The window terminated unexpectedly (reason: 'oom')"

## 1. Diagnóstico

**Error mostrado:** "The window terminated unexpectedly (reason: 'oom', code: '-536870904')"

**Causa:** `oom` = **Out of Memory** (memoria insuficiente). El editor **Cursor IDE** se queda sin RAM y se cierra.

**Importante:** Este error **NO proviene de la aplicación Streamlit** (app.py). Ocurre en el propio Cursor IDE al editar el proyecto.

---

## 2. Por qué aparece cada vez más seguido

- Cursor consume más memoria con el tiempo (pestañas abiertas, historial, IA)
- Archivos grandes (como app.py con miles de líneas) aumentan el uso de RAM
- Extensiones y funciones de IA (Composer, Chat) consumen memoria adicional

---

## 3. Soluciones recomendadas (rigurosas)

### A) Reducir uso de memoria en Cursor

| Acción | Efecto |
|--------|--------|
| Cerrar pestañas que no uses | Menos RAM |
| Cerrar proyectos que no estés usando | Menos RAM |
| Reiniciar Cursor cada cierto tiempo | Libera memoria acumulada |
| Desactivar extensiones que no necesites | Menos RAM |

### B) Ajustar configuración de Cursor

En **Configuración** (Ctrl+,) o `settings.json`:

```json
{
  "files.autoSave": "afterDelay",
  "files.autoSaveDelay": 30000,
  "editor.largeFileOptimizations": true,
  "search.maxResults": 10000
}
```

### C) Aumentar memoria disponible

- Cerrar navegador, Discord, etc. mientras usas Cursor
- Si usas WSL o Docker, reducir contenedores en ejecución
- En equipos con poca RAM (8 GB o menos), considerar cerrar otras apps

### D) Alternativa: usar otro editor para este proyecto

- **VS Code** (sin IA) suele usar menos memoria
- **PyCharm Community** es otra opción más ligera para Python

---

## 4. Lo que NO se puede hacer desde app.py

El error OOM ocurre en **Cursor IDE**, no en la app Streamlit. No hay cambios en `app.py` que puedan evitar este mensaje.

---

## 5. Resumen

| Aspecto | Detalle |
|---------|---------|
| Origen | Cursor IDE (editor), no la app |
| Causa | Falta de memoria RAM |
| Solución en código | No aplica |
| Acciones recomendadas | Cerrar pestañas, reiniciar Cursor, reducir extensiones, liberar RAM |
