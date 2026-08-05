# ForensIQ — Memory Forensics & Threat Hunting Platform

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

ForensIQ analiza volcados de memoria RAM de Windows para detectar **malware sin archivo** y **amenazas residentes en memoria**. Carga el dump, extrae artefactos con Volatility 3, clasifica cada proceso con un modelo XGBoost entrenado en CIC-MalMem2022, genera reglas YARA mediante un LLM local (Ollama / Mistral 7B) y produce un reporte HTML, JSON y un bundle STIX 2.1 — sin ninguna llamada a APIs externas.

**¿Qué resultados esperar?**
- Lista de procesos ordenados por probabilidad de ser maliciosos, con score y atribución SHAP.
- Línea de tiempo de eventos mapeados a técnicas MITRE ATT&CK.
- Reglas YARA listas para importar en tu SIEM o EDR.
- Reporte HTML autocontenido y JSON estructurado para integración con SOAR.

---

## Arquitectura

```
Volcado de memoria (.raw / .dmp / .vmem)
          │
          ▼
┌─────────────────────────────────────────────────────────┐
│  Extracción — Volatility 3                              │
│  pslist · pstree · cmdline · netscan · dlllist          │
│  vadinfo · malfind · handles · services                 │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Ingeniería de características (20 por proceso)         │
│  Entropía de Shannon · profundidad de ruta              │
│  Heurísticas padre-hijo · DLLs sospechosas             │
│  Anomalías VAD · comportamiento de red                  │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Clasificación ML                                       │
│  XGBoost + CalibratedClassifierCV (CIC-MalMem2022)     │
│  ROC-AUC 1.000 · F1 0.9999 · 11 612 muestras de test  │
│  SHAP TreeExplainer — atribución por proceso            │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Generación de reglas YARA (Ollama / Mistral 7B local) │
│  Extracción de IOC → prompt Jinja2 → validación YARA   │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Reporte (HTML + JSON + STIX 2.1)                      │
│  Ranking de procesos · línea de tiempo MITRE ATT&CK     │
│  Historial SQLite · exportación STIX bundle             │
└─────────────────────────────────────────────────────────┘
```

---

## Requisitos

| Componente | Versión |
|---|---|
| Python | 3.12+ |
| YARA (sistema) | cualquier versión reciente |
| Volatility 3 | 2.28.0 (instalado vía pip) |
| Ollama + mistral:7b | opcional — solo para YARA |

**Arch Linux:**
```bash
sudo pacman -S yara python python-pip
```

**Ubuntu / Debian:**
```bash
sudo apt-get install yara libyara-dev python3-pip python3-venv
```

---

## Instalación

```bash
git clone https://github.com/Dacr2153/ForensIQ.git
cd ForensIQ

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .
```

**Verificar instalación:**
```bash
sudo .venv/bin/forensiq check
```

**Ollama (opcional — para generación de YARA):**
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull mistral:7b
ollama serve &
```

---

## Modelo ML

Pre-entrenado en **CIC-MalMem2022** (Universidad de New Brunswick).
Archivo incluido en `ml/data/forensiq_model.joblib`.

| Métrica | Valor |
|---|---|
| ROC-AUC | 1.000 |
| Precisión | 0.9998 |
| Recall | 1.0000 |
| F1 | 0.9999 |
| Muestras de test | 11 612 |

---

## Uso

```bash
# Menú interactivo (recomendado)
sudo .venv/bin/forensiq menu

# Analizar un volcado directamente
sudo .venv/bin/forensiq analyze /ruta/al/dump.raw

# Sin generación de YARA (más rápido, no requiere Ollama)
sudo .venv/bin/forensiq analyze /ruta/al/dump.raw --no-yara

# Ajustar umbral de clasificación (por defecto 0.65)
sudo .venv/bin/forensiq analyze /ruta/al/dump.raw --threshold 0.75

# Verificar dependencias
sudo .venv/bin/forensiq check
```

> `sudo` es necesario porque Volatility 3 requiere acceso directo a los archivos del sistema para cargar símbolos de depuración.

**Códigos de salida:**

| Código | Significado |
|---|---|
| `0` | Análisis completo — sin amenazas |
| `1` | Análisis completo — **procesos maliciosos detectados** |
| `2` | Error en el análisis (revisar logs) |

---

## Salidas

Todos los archivos se guardan en `reports/`:

```
reports/
├── forensiq_20260507_123456.html      ← reporte visual (abrir en navegador)
├── forensiq_20260507_123456.json      ← datos estructurados para SIEM/SOAR
└── forensiq_20260507_123456.stix.json ← bundle STIX 2.1 para intercambio de inteligencia
```

**HTML** — autocontenido, sin dependencias externas:
- Resumen ejecutivo con nivel de amenaza y duración del análisis
- Tabla de procesos ordenada por score de amenaza con atribución SHAP
- Línea de tiempo MITRE ATT&CK
- Reglas YARA generadas y validadas

**JSON** — ejemplo de estructura:
```json
{
  "threat_level": "CRITICAL",
  "total_processes": 87,
  "malicious_count": 2,
  "ranked_processes": [...],
  "timeline": [...],
  "yara_results": [...]
}
```

**Reglas YARA** generadas en `yara_rules/`:
```yara
rule forensiq_payload_3388 {
    meta:
        author       = "ForensIQ / Mistral 7B"
        threat_level = "critical"
        mitre        = "T1055"
    strings:
        $proc = "payload.exe" nocase
        $mz   = { 4D 5A }
    condition:
        $proc and $mz
}
```

---

## Licencia y Uso Ético

MIT License — ver [LICENSE](LICENSE).

Esta herramienta está diseñada exclusivamente para **análisis forense defensivo** en sistemas propios o bajo autorización escrita explícita. Queda prohibido su uso para:

- Analizar sistemas sin autorización del propietario.
- Evadir controles de seguridad en entornos de producción ajenos.
- Cualquier actividad que viole leyes locales o internacionales de ciberseguridad.

El autor no se hace responsable del uso indebido de esta herramienta.
