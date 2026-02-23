# -*- coding: utf-8 -*-
"""Tests unitarios - Iglesia Pentecostal de Welland - Sistema de Tesorería"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
from datetime import datetime


def test_validar_datos():
    """Prueba validación de datos del ledger."""
    from app import validar_datos, COLUMNAS_LEDGER

    # DataFrame vacío
    df_vacio = pd.DataFrame(columns=COLUMNAS_LEDGER)
    ok, _ = validar_datos(df_vacio)
    assert ok is True

    # DataFrame con datos válidos
    df_ok = pd.DataFrame([{
        "id_registro": "T-001",
        "fecha": "2024-01-15 10:00:00",
        "detalle": "Arqueo General",
        "tipo_gasto": "",
        "ingreso": 100.0,
        "gastos": 0.0,
        "total_ingresos": 100.0,
        "total_gastos": 0.0,
        "saldo_actual": 100.0,
    }])
    ok, _ = validar_datos(df_ok)
    assert ok is True

    # Valores negativos
    df_neg = df_ok.copy()
    df_neg.loc[0, "ingreso"] = -50
    ok, msg = validar_datos(df_neg)
    assert ok is False
    assert "negativos" in msg.lower() or "negative" in msg.lower()


def test_recalcular_totales():
    """Prueba recálculo de totales acumulados."""
    from app import _recalcular_totales_ledger, COLUMNAS_LEDGER

    df = pd.DataFrame([
        {"id_registro": "1", "fecha": "2024-01-01", "detalle": "A", "tipo_gasto": "", "ingreso": 100, "gastos": 0},
        {"id_registro": "2", "fecha": "2024-01-02", "detalle": "B", "tipo_gasto": "", "ingreso": 0, "gastos": 30},
    ])
    for c in ["total_ingresos", "total_gastos", "saldo_actual"]:
        df[c] = 0
    result = _recalcular_totales_ledger(df)
    assert float(result.iloc[0]["total_ingresos"]) == 100
    assert float(result.iloc[0]["total_gastos"]) == 0
    assert float(result.iloc[0]["saldo_actual"]) == 100
    assert float(result.iloc[1]["total_ingresos"]) == 100
    assert float(result.iloc[1]["total_gastos"]) == 30
    assert float(result.iloc[1]["saldo_actual"]) == 70


def test_politica_contrasena():
    """Prueba validación de política de contraseña."""
    from app import _validar_politica_contrasena

    # Muy corta
    ok, msg = _validar_politica_contrasena("Ab1")
    assert ok is False

    # Sin mayúscula (si REQUIERE_MAYUSCULA)
    from config import REQUIERE_MAYUSCULA
    if REQUIERE_MAYUSCULA:
        ok, _ = _validar_politica_contrasena("password123")
        assert ok is False

    # Sin número (si REQUIERE_NUMERO)
    from config import REQUIERE_NUMERO
    if REQUIERE_NUMERO:
        ok, _ = _validar_politica_contrasena("Password")
        assert ok is False

    # Válida
    ok, _ = _validar_politica_contrasena("Password1")
    assert ok is True


def test_verificar_integridad_ledger():
    """Prueba verificación de integridad del ledger."""
    from app import verificar_integridad_ledger, _recalcular_totales_ledger

    df = pd.DataFrame([
        {"id_registro": "1", "fecha": "2024-01-01", "detalle": "A", "tipo_gasto": "", "ingreso": 100, "gastos": 0},
        {"id_registro": "2", "fecha": "2024-01-02", "detalle": "B", "tipo_gasto": "", "ingreso": 0, "gastos": 30},
    ])
    df = _recalcular_totales_ledger(df)
    ok, _ = verificar_integridad_ledger(df)
    assert ok is True


if __name__ == "__main__":
    test_validar_datos()
    test_recalcular_totales()
    test_politica_contrasena()
    test_verificar_integridad_ledger()
    print("Todos los tests pasaron.")
