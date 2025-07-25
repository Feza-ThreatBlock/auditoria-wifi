# auditoria-wifi
# Script para Auditoria Wifi 802.11
# ===========================================
#  Script de Análisis de Vulnerabilidades WiFi
# ===========================================

# Autor:  FezaThreatBlock
# Versión: 1.0
# Repositorio:

# -------------------------------------------
# 📌 DESCRIPCIÓN GENERAL
# -------------------------------------------

Este script realiza una auditoría automática de redes WiFi a partir de archivos de captura en formato CSV (exportados con herramientas como `airodump-ng`). Analiza únicamente los puntos de acceso (Access Points), sin incluir dispositivos clientes.

Incorpora modelos de machine learning (Random Forest) para:
- Evaluar el nivel de seguridad de cada red.
- Identificar redes sospechosas o mal configuradas.
- Calcular un puntaje de seguridad (`security_score`) para cada BSSID.
- Exportar informes detallados y rankings.

---

# -------------------------------------------
# 📂 REQUISITOS
# -------------------------------------------

- Python 3.8 o superior
- Librerías necesarias:
  - pandas
  - numpy
  - scikit-learn
  - matplotlib
  - colorama
  - seaborn
  - tabulate

⚠ *No se incluye aquí el archivo CSV de captura. El usuario debe proporcionar uno con los puntos de acceso.*

---

# -------------------------------------------
# 📄 FORMATO DEL ARCHIVO CSV DE ENTRADA
# -------------------------------------------

El archivo de entrada (`captura.csv`) **debe contener únicamente Access Points** y tener al menos las siguientes columnas:

- `bssid`
- `essid`
- `channel`
- `speed`
- `power`
- `# beacons`
- `# iv`
- `privacy`
- `authentication`

🔹 Ejemplo de nombre de archivo: `captura_wifi.csv`

---

# -------------------------------------------
# ▶ INSTRUCCIONES DE USO
# -------------------------------------------

1. Coloca tu archivo CSV con los datos de captura en el mismo directorio del script.
2. Ejecuta el script desde la terminal:

python auditoria_wifi.py captura.csv

3. El script:
   - Limpiará los datos.
   - Clasificará redes sospechosas.
   - Entrenará dos modelos Random Forest.
   - Comparará la precisión de ambos.
   - Calculará el `security_score`.
   - Imprimirá resultados y exportará informes.

---

# -------------------------------------------
# 📁 SALIDAS GENERADAS
# -------------------------------------------

- `resultados_wifi/forecast.png`.
- `resultados_wifi/cluster.png`
- `resultados_wifi/anomaly_overlay.png`.
- `resultados_wifi/confusion_matrices.png`: matriz de confusión.
- `resultados_wifi/rf_features_model2.png`.
- `resultados_wifi/rf_features_model2.png`.
- `resumen_seguridad_rf.csv`.

---

# -------------------------------------------
# 🔐 NOTAS DE SEGURIDAD
# -------------------------------------------

- Este script no ataca ni manipula redes. Su objetivo es educativo y para fines de auditoría.
- No incluye análisis de clientes conectados. Está enfocado únicamente en Access Points.

---

# -------------------------------------------
# 📣 CONTACTO Y SOPORTE
# -------------------------------------------

¿Dudas o sugerencias?
Contáctame vía GitHub o en mi canal de YouTube: Feza ThreatBlock

-------------------------------------------
