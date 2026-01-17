# 📚 SIEM Anomaly Detector - Documentación

Esta carpeta contiene toda la documentación del proyecto, organizada por audiencia y propósito.

---

## 📄 Documentos Disponibles

### Para Management / Executives

#### **📊 EXECUTIVE_OVERVIEW (HTML + PDF)**
> **Audiencia:** Directors, VPs, C-level, Decision makers  
> **Propósito:** Presentación ejecutiva con business value, ROI, comparativas

**Contenido:**
- Executive Summary
- Business Value & ROI ($310k/año ahorro)
- Use Cases empresariales (brute force, insider threats, SQL injection)
- Arquitectura del sistema (explicada para no-técnicos)
- ML Architecture (ensemble de 3 modelos)
- Comparativa con competidores (Splunk, QRadar, Elastic)
- Security & Compliance (GDPR, PCI-DSS, SOC 2)
- Deployment options
- FAQ para decision makers

**Archivos:**
- `EXECUTIVE_OVERVIEW.html` - Documento HTML completo con imágenes
- `SIEM_Executive_Overview.pdf` - PDF generado (1.1 MB) **← LISTO PARA IMPRIMIR**

**Cómo usar:**

```bash
# Ver HTML en navegador
open EXECUTIVE_OVERVIEW.html

# Ver PDF
open SIEM_Executive_Overview.pdf

# Regenerar PDF (si modificas el HTML)
./generate_pdf.sh
```

**Para presentaciones:**
- Imprimir PDF para reuniones ejecutivas
- Compartir PDF por email como adjunto
- Mostrar HTML en proyector (mejor resolución)

---

### Para Equipos Técnicos

#### **🏗️ ARCHITECTURE.md**
> **Audiencia:** Developers, DevOps, Infrastructure teams  
> **Propósito:** Arquitectura técnica del sistema completo

**Contenido:**
- Diagramas de componentes (Mermaid)
- Data flow diagrams
- ML Ensemble architecture
- Docker services architecture
- Feature engineering (21 features)
- Technology stack
- Security boundaries
- Deployment options
- File structure

**Uso:**
```bash
# Ver con syntax highlighting
bat ARCHITECTURE.md

# O en GitHub (renderiza diagramas Mermaid)
```

---

#### **🧠 ML_ARCHITECTURE.md**
> **Audiencia:** Data Scientists, ML Engineers, Security Researchers  
> **Propósito:** Detalles profundos de los modelos ML

**Contenido:**
- Feature Engineering detallado (21 features)
- ML Ensemble (Isolation Forest + DBSCAN + GMM)
- Training process
- Inference pipeline
- Evaluation metrics (precision, recall, F1)
- Model retraining
- Feature importance
- Configuration & hyperparameters
- Referencias a notebooks de entrenamiento

**Uso:**
```bash
# Leer con paginación
less ML_ARCHITECTURE.md

# Buscar configuración específica
grep -i "contamination" ML_ARCHITECTURE.md
```

---

#### **📥 LOG_INGESTION.md**
> **Audiencia:** Security Engineers, SOC Analysts, SysAdmins  
> **Propósito:** Guía completa de integración de logs

**Contenido:**
- Generador continuo de logs (demo mode)
- rsyslog configuration
- Filebeat integration
- Fluentd setup
- Logstash pipelines
- Nginx/Apache direct logging
- Python application integration
- Webhook integration
- Troubleshooting

**Uso:**
```bash
# Ver sección específica
grep -A 20 "rsyslog" LOG_INGESTION.md

# Copiar configuración de ejemplo
grep -A 30 "filebeat.yml" LOG_INGESTION.md
```

---

### Capturas de Pantalla

#### **Imágenes de la Interfaz**

| Archivo | Descripción |
|---------|-------------|
| `01-Dashboard.png` | Dashboard en tiempo real con métricas |
| `02-ML-ModelArchitecture.png` | Arquitectura del ensemble ML |
| `03-ModelPipeline.png` | Pipeline completo de predicción |
| `04-RecentAnomalies.png` | Lista de anomalías detectadas |

**Uso en presentaciones:**
- Ya incluidas en `EXECUTIVE_OVERVIEW.html/pdf`
- Puedes usarlas individualmente en slides
- Alta resolución para impresión

---

### Diagramas

#### **architecture.excalidraw**
> Diagrama editable de arquitectura (formato Excalidraw)

**Cómo editar:**
1. Abrir https://excalidraw.com
2. File → Open → Seleccionar `architecture.excalidraw`
3. Editar y exportar PNG/SVG

---

## 🎯 Flujos de Uso Recomendados

### Escenario 1: Presentación a C-Level

```bash
# 1. Abrir PDF ejecutivo
open SIEM_Executive_Overview.pdf

# 2. Imprimir para reunión
lp -o sides=two-sided-long-edge SIEM_Executive_Overview.pdf

# 3. Enviar por email
# Adjuntar: SIEM_Executive_Overview.pdf (1.1 MB)
```

**Secciones clave:**
- Executive Summary (página 1)
- Business Value & ROI (página 3) → **Destacar $310k ahorro**
- Comparativa con Splunk (página 9) → **78% reducción TCO**
- Next Steps (página 13)

---

### Escenario 2: Evaluación Técnica

```bash
# 1. Revisar arquitectura
bat ARCHITECTURE.md

# 2. Entender ML models
bat ML_ARCHITECTURE.md

# 3. Planificar integración
bat LOG_INGESTION.md

# 4. Ver código
cd ../backend && fd -e py | head -10
```

---

### Escenario 3: Integrar Logs Reales

```bash
# 1. Leer guía de ingestion
open LOG_INGESTION.md

# 2. Configurar rsyslog (ejemplo)
sudo nano /etc/rsyslog.d/50-siem.conf
# Copiar config de LOG_INGESTION.md

# 3. Reiniciar rsyslog
sudo systemctl restart rsyslog

# 4. Verificar que llegan logs
docker exec siem-postgres psql -U siem_user -d siem_db -c \
  "SELECT COUNT(*) FROM logs WHERE created_at > NOW() - INTERVAL '1 minute';"
```

---

### Escenario 4: Demo para Clientes

```bash
# 1. Iniciar generador continuo
docker compose --profile demo up -d

# 2. Abrir frontend
open http://localhost:5173

# 3. Mostrar dashboard con datos en tiempo real
# (logs fluyendo cada 3 segundos)

# 4. Explicar con PDF ejecutivo abierto en segunda pantalla
open SIEM_Executive_Overview.pdf
```

---

## 🛠️ Mantenimiento de Documentación

### Actualizar Executive Overview

```bash
# 1. Editar HTML
nano EXECUTIVE_OVERVIEW.html

# 2. Regenerar PDF
./generate_pdf.sh

# 3. Verificar cambios
open SIEM_Executive_Overview.pdf

# 4. Commit
git add EXECUTIVE_OVERVIEW.html SIEM_Executive_Overview.pdf
git commit -m "docs: update executive overview with new metrics"
```

### Actualizar Imágenes

```bash
# 1. Tomar nueva captura (frontend debe estar corriendo)
# 2. Guardar como 01-Dashboard.png (o número correspondiente)
# 3. Optimizar tamaño
pngquant 01-Dashboard.png --output 01-Dashboard-optimized.png
mv 01-Dashboard-optimized.png 01-Dashboard.png

# 4. Regenerar PDF (incluirá nueva imagen)
./generate_pdf.sh
```

---

## 📊 Estadísticas de Documentación

```bash
# Tamaño total
du -sh .
# 1.5M (incluyendo PDF + imágenes)

# Líneas de documentación
wc -l *.md
#   443 ARCHITECTURE.md
#   510 ML_ARCHITECTURE.md
#   350 LOG_INGESTION.md
#   100 README.md (este archivo)
# 1,403 TOTAL

# Imágenes
ls -lh *.png
# 75K  01-Dashboard.png
# 87K  02-ML-ModelArchitecture.png
# 95K  03-ModelPipeline.png
# 125K 04-RecentAnomalies.png
```

---

## 🔗 Enlaces Útiles

### Documentos Relacionados

- **Quick Start:** [`../QUICK_START.md`](../QUICK_START.md) - Guía rápida de instalación
- **README principal:** [`../README.md`](../README.md) - Descripción del proyecto
- **Notebooks ML:** `../notebooks/03-clustering/` - Jupyter notebooks de entrenamiento

### Recursos Externos

- **Mermaid Diagrams:** https://mermaid.js.org/ (para editar diagramas en ARCHITECTURE.md)
- **Excalidraw:** https://excalidraw.com (para editar architecture.excalidraw)
- **Markdown Guide:** https://www.markdownguide.org/

---

## 📞 Contacto

Para preguntas sobre documentación:

- **Email:** adrian.infantes@tu-empresa.com
- **Slack:** #siem-ml-docs
- **Issues:** https://github.com/tu-org/SIEM-ML/issues

---

**Última actualización:** Enero 2026  
**Mantenido por:** Adrian Infantes Romero
