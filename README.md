# ForensIQ — Memory Forensics & Threat Hunting Platform

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.0.0-brightgreen.svg)](https://github.com/Dacr2153/ForensIQ)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-orange.svg)](.github/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-885%20passed-success.svg)](tests/)
[![Volatility 3](https://img.shields.io/badge/Volatility%203-2.28.0-blueviolet.svg)](https://github.com/volatilityfoundation/volatility3)
[![XGBoost](https://img.shields.io/badge/XGBoost-3.2.0-4B0082.svg)](https://github.com/dmlc/xgboost)

**ForensIQ** es una plataforma de **análisis forense de memoria RAM** y **caza de amenazas** diseñada para detectar **malware sin archivo** (*fileless*) y amenazas residentes en memoria. Analiza volcados de memoria de Windows (`.raw`, `.dmp`, `.vmem`) **100% offline** y produce reportes accionables — sin enviar datos a ninguna API externa.

> **ADVERTENCIA:** Para uso forense defensivo únicamente. Analice únicamente sistemas propios o con autorización escrita explícita del propietario.

---

## Tabla de Contenidos

- [Descripción](#descripción)
- [Características](#características)
- [Arquitectura](#arquitectura)
- [Requisitos Previos](#requisitos-previos)
- [Instalación](#instalación)
- [Uso](#uso)
- [Comandos CLI](#comandos-cli)
- [Modo Live (Linux)](#modo-live-linux)
- [Configuración](#configuración)
- [Modelo ML](#modelo-ml)
- [Salidas y Reportes](#salidas-y-reportes)
- [Desarrollo](#desarrollo)
- [Guía de Contribución](#guía-de-contribución)
- [Licencia y Uso Ético](#licencia-y-uso-ético)
- [Contacto](#contacto)

---

## Descripción

Cuando un equipo Windows es comprometido, el malware **sin archivo** opera únicamente en memoria RAM y desaparece al reiniciar. Los volcados de memoria contienen la evidencia — pero extraer y clasificar cientos de procesos manualmente es inviable.

ForensIQ automatiza todo el flujo:

1. **Extracción de artefactos** del volcado mediante **Volatility 3** (`pslist`, `netscan`, `dlllist`, `malfind`, `vadinfo`, etc.).
2. **Ingeniería de características** — calcula 20 características por proceso (entropía de Shannon, heurísticas padre-hijo, anomalías VAD, comportamiento de red, etc.).
3. **Clasificación** de cada proceso con un conjunto **XGBoost + IsolationForest** entrenado en CIC-MalMem2022 y generación de explicaciones **SHAP**.
4. **Detección** de patrones de ataque con 7 plugins de detección (rootkits DKOM, mutex maliciosos, servicios anómalos, inyección PE, IOCs en strings, inteligencia de amenazas).
5. **Generación de reglas YARA** asistida por un LLM local (**Ollama**), auto-detectado y sin coste por API.
6. **Reporte** en HTML autocontenido, JSON estructurado y bundle **STIX 2.1**.

**Resultados obtenidos:**
- Ranking de procesos por probabilidad de ser maliciosos, con score y atribución SHAP.
- Línea de tiempo de eventos mapeados a técnicas **MITRE ATT&CK**.
- Reglas YARA validadas listas para su SIEM/EDR.
- Reporte HTML navegable y JSON para integración con SOAR.

---

## Características

| Área | Capacidad |
|---|---|
| **Extracción** | Volatility 3 integrado: procesos, red, DLLs, inyección, VAD, handles, servicios |
| **Clasificación ML** | XGBoost + IsolationForest + SHAP, entrenado en CIC-MalMem2022 (ROC-AUC 1.000) |
| **Detección** | 7 plugins: anomalías de proceso, *cross-view* DKOM, mutex, servicios, PE headers, strings/IOC, threat intel |
| **Reglas YARA** | Generación y validación automática vía LLM local (Ollama, auto-detecta el modelo instalado) |
| **Memoria en vivo** | Análisis de RAM Linux en vivo vía `/proc/kcore` o **LiME**, con construcción automática del ISF |
| **Diff de dumps** | Compara dos volcados: procesos nuevos/desaparecidos/cambiados, conexiones, DLLs e inyecciones |
| **Reportes** | HTML autocontenido + JSON estructurado + exportación **STIX 2.1** |
| **Threat Intel** | Lookup de hashes en **VirusTotal** / **MalwareBazaar** (opcional, con caché local y rate-limit) |
| **Historial** | Persistencia SQLite del historial de análisis y caché de inteligencia |
| **TUI** | Menú interactivo asistido con *questionary* |
| **Offline-first** | Funciona sin conexión; la IA y el threat intel son opcionales y degradan con elegancia |

---

## Arquitectura

```
Volcado de memoria (.raw / .dmp / .vmem)   o   RAM Linux en vivo (/proc/kcore · LiME)
          |
          v
+-----------------------------------------------------------+
|  EXTRACCION — Volatility 3                                 |
|  pslist · pstree · cmdline · netscan · dlllist             |
|  vadinfo · malfind · handles · services                    |
+----------------------------+------------------------------+
                             |
                             v
+-----------------------------------------------------------+
|  INGENIERIA DE CARACTERISTICAS (20 por proceso)            |
|  Entropia de Shannon · profundidad de ruta · heuristicas   |
|  padre-hijo · DLLs sospechosas · anomalias VAD · red       |
+----------------------------+------------------------------+
                             |
                             v
+-----------------------------------------------------------+
|  CLASIFICACION ML                                          |
|  XGBoost + IsolationForest (CIC-MalMem2022)                |
|  SHAP TreeExplainer — atribucion por proceso               |
+--------------+------------------------------+--------------+
              |                              |
              v                              v
+-----------------------------+  +--------------------------+
|  DETECTORES (plugins)       |  |  REGLAS YARA (LLM local)  |
|  anomalias · cross-view ·   |  |  Ollama auto-detectado →   |
|  mutex · servicios · PE ·   |  |  prompt Jinja2 → validacion|
|  strings/IOC · threat intel |  |  yara-python               |
+-----------------------------+  +--------------------------+
              |                              |
              +---------------+--------------+
                              v
+-----------------------------------------------------------+
|  REPORTE — HTML + JSON + STIX 2.1                          |
|  Ranking de procesos · linea de tiempo MITRE ATT&CK        |
|  Historial SQLite · exportacion STIX bundle                |
+-----------------------------------------------------------+
```

**Detectores incluidos** (`forensiq/detectors/`):

| Detector | Qué detecta |
|---|---|
| `ProcessAnomalyDetector` | Umbral adaptativo, *masquerading*, relaciones padre-hijo anómalas |
| `CrossViewDetector` | DKOM / rootkits: `psscan` vs `pslist` (procesos ocultos) |
| `HandlesMutexDetector` | Mutex y handles de registro maliciosos |
| `ServicesScanDetector` | Servicios maliciosos vía `windows.svcscan` |
| `MalfindStringsDetector` | Extracción de strings + parseo de IOCs en regiones inyectadas |
| `PEHeaderDetector` | Análisis PE de regiones de memoria inyectadas |
| `ThreatIntelDetector` | Lookup de hashes en VirusTotal / MalwareBazaar (opcional) |

---

## Requisitos Previos

| Componente | Versión / Nota |
|---|---|
| Python | **3.12+** |
| YARA (librería de sistema) | Cualquier versión reciente (`libyara-dev` / paquete `yara`) |
| Volatility 3 | 2.28.0 (se instala vía pip) |
| Ollama + modelo | **Opcional** — solo para generación de YARA (recomendado `mistral:7b`) |
| Modelo ML | Incluido en el repositorio (`ml/data/`) |
| Hardware | 4 GB+ de RAM; GPU acelerada opcionalmente para la IA |

### Dependencias del sistema

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

### 1. Clonar el repositorio

```bash
git clone https://github.com/Dacr2153/ForensIQ.git
cd ForensIQ
```

### 2. Crear y activar el entorno virtual

```bash
python -m venv .venv
source .venv/bin/activate
```

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
pip install -e .
```

> **Nota:** `make setup` ejecuta los pasos 2 y 3 automáticamente (ver [Makefile](Makefile)).

### 4. Verificar la instalación

```bash
sudo .venv/bin/forensiq check
```

### 5. (Opcional) Ollama para generación de reglas YARA

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull mistral:7b
ollama serve &
```

---

## Uso

### Menú interactivo (recomendado)

```bash
sudo .venv/bin/forensiq menu
```

### Analizar un volcado de memoria

```bash
# Análisis completo
sudo .venv/bin/forensiq analyze /ruta/al/dump.raw

# Sin generación de YARA (más rápido, no requiere Ollama)
sudo .venv/bin/forensiq analyze /ruta/al/dump.raw --no-yara

# Ajustar el umbral de clasificación (por defecto 0.65)
sudo .venv/bin/forensiq analyze /ruta/al/dump.raw --threshold 0.75

# Exportar además un bundle STIX 2.1
sudo .venv/bin/forensiq analyze /ruta/al/dump.raw --output-stix ./stix

# Stream de resultados en vivo + forzar re-análisis
sudo .venv/bin/forensiq analyze /ruta/al/dump.raw --stream --force
```

> `sudo` es necesario porque Volatility 3 requiere acceso a los símbolos del sistema y a los archivos del volcado.

### Comparar dos volcados (diff)

```bash
sudo .venv/bin/forensiq diff --before /ruta/base.raw --after /ruta/post_incidente.raw
```

### Analizar RAM Linux en vivo

```bash
# Vía /proc/kcore (kernels estándar)
sudo .venv/bin/forensiq live

# Vía LiME (kernels hardened sin /proc/kcore)
sudo .venv/bin/forensiq live --lime
sudo .venv/bin/forensiq live --build-lime   # auto-compila lime.ko
sudo .venv/bin/forensiq live --build-isf    # genera el ISF de Volatility 3
```

### Entrenar el modelo

```bash
sudo .venv/bin/forensiq train --data /ruta/al/dataset.parquet
```

### Códigos de salida

| Código | Significado |
|---|---|
| `0` | Análisis completado — **sin amenazas** |
| `1` | Análisis completado — **procesos maliciosos detectados** |
| `2` | Error crítico en el análisis (revisar logs) |
| `3` | Análisis degradado (ML no disponible, resultados incompletos) |

---

## Comandos CLI

```
forensiq [GRUPO] [COMANDO]
```

| Comando | Descripción |
|---|---|
| `analyze` | Analiza un volcado de memoria de Windows de extremo a extremo |
| `train` | Entrena el clasificador XGBoost sobre CIC-MalMem2022 |
| `check` | Verifica los requisitos del sistema y las herramientas disponibles |
| `live` | Analiza la RAM de Linux en vivo (`/proc/kcore` o LiME) |
| `diff` | Compara dos volcados de memoria |
| `menu` | Lanza el menú TUI interactivo |
| `version` | Muestra la versión e información de componentes |

### Opciones principales de `analyze`

| Opción | Descripción |
|---|---|
| `-d, --dump` | Ruta al volcado de memoria (requerido) |
| `-o, --output` | Directorio de salida (por defecto `./reports`) |
| `-t, --threshold` | Umbral de amenaza `0.0–1.0` (anula `FORENSIQ_THREAT_THRESHOLD`) |
| `--no-yara` | Omite la generación de reglas YARA |
| `--no-html` | Omite el reporte HTML |
| `--stream` | Stream de resultados incrementales por fase |
| `--force` | Re-analiza aunque el dump esté en caché |
| `--output-stix` | Exporta un bundle STIX 2.1 al directorio indicado |
| `-l, --log-level` | Nivel de log: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `--log-format` | Formato: `console` o `json` |

Ejecute `forensiq <comando> --help` para la lista completa de opciones.

---

## Modo Live (Linux)

ForensIQ puede analizar la memoria de un sistema Linux **en funcionamiento** mediante dos vías de adquisición:

| Vía | Uso | Requisito |
|---|---|---|
| `/proc/kcore` | Por defecto | `CONFIG_PROC_KCORE=y` (kernels estándar) |
| **LiME** | `--lime` | Módulo `lime.ko` compilado para el kernel actual (necesario en `linux-hardened`) |

Automatización incluida:

- `--build-lime` clona el repositorio LiME y compila `lime.ko` automáticamente (requiere `git`, `make`, `gcc` y las cabeceras del kernel).
- `--build-isf` genera el símbolo ISF de Volatility 3 para Linux usando BTF + System.map (requiere Go, que se auto-instala).

```bash
forensiq check                                   # diagnóstico previo
sudo forensiq live                               # /proc/kcore
sudo forensiq live --lime                        # usar lime.ko ya compilado
sudo forensiq live --lime-module /ruta/lime.ko   # ruta explícita al módulo
```

---

## Configuración

ForensIQ se configura mediante variables de entorno o un archivo `.env`:

```bash
cp .env.example .env
```

### Variables principales

| Variable | Por defecto | Descripción |
|---|---|---|
| `FORENSIQ_VOLATILITY_PATH` | `vol` | Ruta al ejecutable de Volatility 3 |
| `FORENSIQ_OLLAMA_BASE_URL` | `http://localhost:11434` | URL de la API de Ollama |
| `FORENSIQ_OLLAMA_MODEL` | `mistral:latest` | Modelo preferido (fallback automático a cualquier modelo instalado) |
| `FORENSIQ_OLLAMA_TIMEOUT` | `120` | Timeout en segundos para respuestas del LLM |
| `FORENSIQ_MODEL_PATH` | `./ml/data/forensiq_model.joblib` | Ruta al modelo XGBoost |
| `FORENSIQ_REPORTS_DIR` | `./reports` | Directorio de reportes HTML/JSON |
| `FORENSIQ_YARA_RULES_DIR` | `./yara_rules` | Directorio de reglas YARA |
| `FORENSIQ_DB_PATH` | `~/.forensiq/forensiq.db` | Base de datos SQLite de historial |
| `FORENSIQ_MAX_PROCESSES_ANALYZE` | `500` | Máximo de procesos a analizar |
| `FORENSIQ_THREAT_THRESHOLD` | `0.65` | Umbral de clasificación malicioso |
| `FORENSIQ_YARA_GENERATE` | `true` | Activa/desactiva la generación de YARA |
| `FORENSIQ_DLL_ROOT` | *(vacío)* | Directorio raíz de DLLs del sistema sospechoso (para hashing de contenido) |
| `FORENSIQ_VT_API_KEY` | *(vacío)* | API key de VirusTotal (threat intel opcional) |
| `FORENSIQ_LOG_LEVEL` | `INFO` | Nivel de log |
| `FORENSIQ_LOG_FORMAT` | `console` | `console` o `json` (estructurado para ELK/Splunk) |

> **Seguridad:** nunca suba su `.env` al control de versiones — está ignorado en `.gitignore`.

---

## Modelo ML

ForensIQ incluye un modelo pre-entrenado en **CIC-MalMem2022** (Universidad de New Brunswick), almacenado en `ml/data/forensiq_model.joblib` con su metadato JSON y el aislamiento acompañante (`forensiq_isolation.joblib`).

| Métrica | Valor |
|---|---|
| ROC-AUC | 1.000 |
| Precisión | 0.9998 |
| Recall | 1.0000 |
| F1 | 0.9999 |
| Muestras de test | 11 612 |

El modelo se entrena con el comando `forensiq train --data <dataset>` y su integridad se verifica antes de cargarlo (incluye un hash de esquema de características para detectar desalineaciones silenciosas).

---

## Salidas y Reportes

Todos los archivos se guardan en `reports/` (configurable):

```
reports/
├── forensiq_20260507_123456.html      <- reporte visual (abrir en navegador)
├── forensiq_20260507_123456.json      <- datos estructurados para SIEM/SOAR
└── forensiq_20260507_123456.stix.json <- bundle STIX 2.1 (si se usó --output-stix)
```

**HTML** — autocontenido (sin dependencias externas):

- Resumen ejecutivo con nivel de amenaza y duración del análisis
- Tabla de procesos ordenada por score de amenaza con atribución SHAP
- Línea de tiempo MITRE ATT&CK
- Reglas YARA generadas y validadas

**JSON** — estructura de alto nivel:

```json
{
  "threat_level": "CRITICAL",
  "total_processes": 87,
  "malicious_count": 2,
  "ranked_processes": [],
  "timeline": [],
  "yara_results": []
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

## Desarrollo

### Herramientas y estándares

| Herramienta | Configuración |
|---|---|
| Ruff | Lint + formato (límite 100 cols) |
| MyPy | Modo estricto |
| Pytest | Suite completa (unit + integration), `asyncio_mode=auto` |
| Coverage | `fail_under = 50` (baseline actual, subiendo a 80 % en Q3 2026) |
| Bandit | Auditoría de seguridad |
| pip-audit | Auditoría de dependencias (CVE) |

### Makefile

```bash
make setup          # Instala todas las dependencias
make check          # Verifica los componentes
make train DATA=/path/to/dataset.parquet
make analyze DUMP=/path/to/dump.raw OPTS='--no-yara'
make test           # Suite completa con cobertura (>=90 % requerido)
make lint           # ruff + mypy
make security       # bandit
make demo           # Demo end-to-end con un dump público
make clean          # Limpia artefactos generados
```

### Ejecutar tests

```bash
.venv/bin/python -m pytest tests/ -q          # suite completa
make test-unit                                 # solo unitarios
make test-fast                                 # sin cobertura (dev)
```

### Calidad de código

```bash
.venv/bin/python -m ruff check src/ tests/
.venv/bin/python -m mypy src/
```

---

## Guía de Contribución

Las contribuciones son bienvenidas. Siga estos pasos:

### Reportar un bug

1. Revise los [issues existentes](https://github.com/Dacr2153/ForensIQ/issues) para evitar duplicados.
2. Abra un issue con:
   - Versión de ForensIQ y del sistema (`forensiq version`).
   - Comando ejecutado y salida completa.
   - Logs (use `--log-level DEBUG --log-format json` si es posible).
   - Descripción del comportamiento esperado frente al real.

### Enviar un Pull Request

1. **Fork** el repositorio y cree una rama: `feature/mi-cambio` o `fix/descripcion`.
2. Asegúrese de que el código pase el toolchain completo:

   ```bash
   make lint        # ruff + mypy
   make test-fast   # pytest sin cobertura
   make security    # bandit
   ```

3. Escriba tests para el cambio (si aplica) y actualice la documentación.
4. Envíe el PR contra la rama `main` describiendo el *qué* y el *por qué* del cambio.

### Convenciones

- Estilo: PEP 8, `snake_case` para funciones y variables, `CamelCase` para clases.
- Type hints completos en todas las interfaces públicas (MyPy estricto).
- Docstrings en estilo Google para módulos, clases y funciones públicas.
- Sin código muerto: use `ruff`, `mypy` y revise los imports sin uso.

---

## Licencia y Uso Ético

**MIT License** — ver [LICENSE](https://opensource.org/licenses/MIT).

Esta herramienta está diseñada **exclusivamente** para **análisis forense defensivo** en sistemas propios o bajo autorización escrita explícita del propietario. Queda prohibido su uso para:

- Analizar sistemas sin autorización del propietario.
- Evadir controles de seguridad en entornos de producción ajenos.
- Cualquier actividad que viole leyes locales o internacionales de ciberseguridad.

> El autor no se hace responsable del uso indebido de esta herramienta. El usuario es responsable de cumplir con la legislación aplicable en su jurisdicción.

---

## Contacto

| Recurso | Enlace |
|---|---|
| Repositorio | [github.com/Dacr2153/ForensIQ](https://github.com/Dacr2153/ForensIQ) |
| Issues | [github.com/Dacr2153/ForensIQ/issues](https://github.com/Dacr2153/ForensIQ/issues) |
| Documentación del dataset | [CIC-MalMem2022 (UNB)](https://www.unb.ca/cic/datasets/malmem-2022.html) |
| Volatility 3 | [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) |
| Ollama | [ollama.com](https://ollama.com) |
