#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ANÁLISIS AVANZADO DE REDES WiFi PARA PENTESTING CON IA
v5.0 EXTENDIDO
Incluye:
- Carga robusta desde CSV de airodump-ng
- Predicción de vulnerabilidades con Random Forest
- Series temporales con Prophet
- Clustering dinámico con KneeLocator
- Detección de anomalías con Isolation Forest
- Recomendaciones tácticas
- Estadísticas avanzadas
- Diccionario WPA con Cadenas de Markov
- Generación de gráficas complementarias
- Búsqueda y puntuación de seguridad por BSSID
- Exportación de una copia del script
"""

# IMPORTACIONES
import datetime
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import random
import re
import os
import warnings
import platform
from colorama import Fore, Style
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.cluster import KMeans
from prophet import Prophet
from kneed import KneeLocator
from collections import defaultdict
from sklearn.impute import SimpleImputer
warnings.filterwarnings("ignore")

# CONFIGURACIÓN
WEIGHTS = {'power': 0.6, 'traffic': 0.25, 'ivs': 0.1, 'security': 0.05}
THRESHOLDS = {'high_power': -60, 'high_traffic': 50, 'wep_ivs': 5000}

# Limpiar pantalla según el sistema operativo
def limpiar_consola():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

# Llamar la función al inicio
limpiar_consola()


# FUNCIONES
def load_data(file_path):
    try:
        df = pd.read_csv(
            file_path,
            header=0,
            names=[
                'bssid', 'first time seen', 'last time seen', 'channel', 'speed',
                'privacy', 'cipher', 'authentication', 'power', '# beacons',
                '# iv', 'lan ip', 'id-length', 'essid', 'key'
            ],
            skip_blank_lines=True,
            engine='python'
        )

        df.columns = df.columns.str.strip().str.lower()
        df['time'] = pd.to_datetime(df['first time seen'], errors='coerce')
        df['time'].fillna(df['time'].median(), inplace=True)
        numeric_cols = ['power', '# beacons', '# iv', 'channel', 'speed']
        for col in numeric_cols:
            df[col] = pd.to_numeric(df[col], errors='coerce')

        df['# beacons_adjusted'] = df['# beacons'] * 1000
        df['authentication'] = df.get('authentication', 'UNKNOWN').fillna('UNKNOWN').str.strip()
        df['privacy'] = df.get('privacy', '').str.strip()
        df['bssid'] = df['bssid'].str.strip()
        df['essid'] = df['essid'].str.strip()
        df['security_score'] = df.apply(estimate_security_advanced, axis=1)

        df['capture_second'] = (df['time'] - df['time'].min()).dt.total_seconds()
        df['capture_window'] = (df['capture_second'] // 60).astype(int)

        return df

    except Exception as e:
        print(f"❌ Error al cargar datos: {e}")
        return pd.DataFrame()

    # Crear máscaras para sospechosas y válidas
    incomplete_mask = df_raw['motivo_sospecha'].str.strip() != ''
    df_suspicious = df_raw[incomplete_mask].copy()
    df_valid = df_raw[~incomplete_mask].copy()

def mostrar_redes_sospechosas(df_suspicious):
    from colorama import Fore, Style, init
    init(autoreset=True)

    columnas = ['bssid', 'channel', 'speed', 'power']
    headers = ['BSSID              ', 'Channel ', 'Speed   ', 'Power   ', 'Motivos']
    print("\n🔎 Resumen de redes sospechosas con campos inválidos:")
    print(" " + "  ".join(headers))
    print("-" * (len(headers) * 18))

    for _, row in df_suspicious.iterrows():
        bssid_valor = str(row.get('bssid', '')).ljust(18)

        fila = [bssid_valor]  # Primera columna: el BSSID real

        for col in ['channel', 'speed', 'power']:
            valor = row.get(col)
            invalido = (valor == -1 or pd.isna(valor))

            if invalido:
                simbolo = Fore.RED + "x" + Style.RESET_ALL
            else:
                simbolo = Fore.GREEN + "V" + Style.RESET_ALL

            fila.append(f"{simbolo:^16}")

        # Columna final con motivos
        motivo = str(row.get('motivo_sospecha', '')).strip()
        fila.append(motivo)

        print(" " + "  ".join(fila))

   # A partir de aquí, continuar solo con redes limpias


def estimate_security_advanced(row):
    privacy = str(row.get('privacy', '')).strip().upper()
    authentication = str(row.get('authentication', '')).strip().upper()
    ivs = row.get('# iv', 0)
    power = row.get('power', -100)
    channel = row.get('channel', 0)
    essid = str(row.get('essid', '')).strip().lower()
    bssid = str(row.get('bssid', '')).strip().upper()
    duration_minutes = row.get('duration_minutes', 60)
    base = 0.0

    # Seguridad base según el cifrado
    # Interpretar múltiples esquemas de cifrado
    if not privacy or privacy in ['UNKNOWN', '']:
        base = 0.0
    else:
        methods = privacy.split()  # separa por espacios
        scores = []
        for method in methods:
            if 'WPA3' in method:
                scores.append(0.9)
            elif 'WPA2' in method:
                scores.append(0.7)
            elif 'WPA' in method:
                scores.append(0.6)
            elif 'WEP' in method:
                scores.append(0.3 if ivs < 500 else 0.05)
            elif 'OPN' in method or 'NONE' in method:
                scores.append(0.0)
            else:
                scores.append(0.2)  # método desconocido

        # Usamos el valor más bajo entre los métodos listados (más inseguro prevalece)
        base = min(scores)

    # Ajustes por autenticación
    if 'PSK' in authentication:
        base -= 0.05
    elif 'EAP' in authentication:
        base += 0.05

    # Penalización por señal excesivamente fuerte (posible AP falso)
    if power > -50:
        base -= 0.05

    # Penalización si el ESSID es sospechoso o vacío
    default_names = ['default', 'linksys', 'dlink', 'netgear', 'wifi']
    if essid == '':
        base -= 0.05
    elif any(name in essid for name in default_names):
        base -= 0.05

    # Penalización si la MAC parece falsa o nula
    if bssid.startswith("00:00") or bssid == "FF:FF:FF:FF:FF:FF":
        base -= 0.1

    # Penalización si la duración de la red es muy breve (sospechosa)
    if duration_minutes < 10:
        base -= 0.05

    final_score = round(max(min(base, 1.0), 0.0), 3)
    return final_score

def train_vulnerability_model(df):
    #Elegir características relevantes
    features = ['power', '# beacons', '# iv', 'channel', 'speed']
    df_model = df.dropna(subset=features + ['security_score']).copy()

    X = df_model[features]
    y = (df_model['security_score'] < 0.5).astype(int)  # 1 = vulnerable, 0 = no vulnerable

    # Entrenar modelo
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)

    return rf, features, X_test, y_test

def train_vulnerability_model_with_suspects(df_valid, df_suspicious):
    print("\n🌐 Entrenando modelo con redes válidas + sospechosas (tratadas)...")

    # === Preparación ===
    combined = pd.concat([df_valid.copy(), df_suspicious.copy()], ignore_index=True)

    # Normalizar valores sospechosos: tratar -1 como nulos
    for col in ['power', 'channel', 'speed']:
        combined[col] = combined[col].replace(-1, np.nan)

    # Agregar flags de valores faltantes
    combined['power_missing'] = combined['power'].isna().astype(int)
    combined['channel_missing'] = combined['channel'].isna().astype(int)
    combined['speed_missing'] = combined['speed'].isna().astype(int)

    # Campos requeridos para el modelo
    features = ['power', '# beacons', '# iv', 'channel', 'speed',
                'power_missing', 'channel_missing', 'speed_missing']

    # Eliminar filas sin score
    combined = combined.dropna(subset=['security_score'])

    # Objetivo binario: vulnerable si el score es bajo
    combined['vulnerable'] = (combined['security_score'] < 0.5).astype(int)

    # === Imputación ===
    imputer = SimpleImputer(strategy='median')
    X = imputer.fit_transform(combined[features])
    y = combined['vulnerable']

    # === Entrenamiento ===
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)

    # === Evaluación ===
    y_pred = rf.predict(X_test)
    #print("\n📊 Reporte de desempeño del modelo (con sospechosas):")
    #print(classification_report(y_test, y_pred))

    return rf, features, X_test, y_test

def comparar_modelos(df_valid, df_suspicious):
    print("\n📊 Comparación entre modelo redes validas vs. modelo completo")

    # ==== MODELO 1: Solo redes válidas ====
    print("\n🔹 MODELO 1: Entrenamiento solo con redes válidas")
    modelo1, features1, X_test1, y_test1 = train_vulnerability_model(df_valid)

    # Preparar datos
    df_test1 = df_valid.dropna(subset=features1 + ['security_score'])
    X1 = df_test1[features1]
    y1 = (df_test1['security_score'] < 0.5).astype(int)
    y_pred1 = modelo1.predict(X1)

    print("🔬 Resultados MODELO 1:")
    print(classification_report(y1, y_pred1, zero_division=0))
    acc1 = modelo1.score(X_test1, y_test1)


    # ==== MODELO 2: Con redes sospechosas ====
    print("\n🔹 MODELO 2: Entrenamiento con redes válidas + sospechosas")
    modelo2, features2, X_test2, y_test2 = train_vulnerability_model_with_suspects(df_valid, df_suspicious)

    # Preparar datos
    df_comb = pd.concat([df_valid.copy(), df_suspicious.copy()], ignore_index=True)
    df_comb[["power", "channel", "speed"]] = df_comb[["power", "channel", "speed"]].replace(-1, np.nan)
    df_comb["power_missing"] = df_comb["power"].isna().astype(int)
    df_comb["channel_missing"] = df_comb["channel"].isna().astype(int)
    df_comb["speed_missing"] = df_comb["speed"].isna().astype(int)
    df_comb = df_comb.dropna(subset=["security_score"])
    y2 = (df_comb["security_score"] < 0.5).astype(int)

    from sklearn.impute import SimpleImputer
    imp = SimpleImputer(strategy="median")
    X2 = imp.fit_transform(df_comb[features2])
    y_pred2 = modelo2.predict(X2)

    print("🔬 Resultados MODELO 2:")
    print(classification_report(y2, y_pred2, zero_division=0))
    acc2 = modelo2.score(X_test2, y_test2)

    # === COMPARACIÓN FINAL ===
    print("\n📈 Comparativa general de precisión:")

    print(f"  - Precisión MODELO 1 (solo válidas): {acc1:.4f}")
    print(f"  - Precisión MODELO 2 (válidas + sospechosas): {acc2:.4f}")

    return modelo1, features1, X_test1, y_test1, modelo2, features2, X_test2, y_test2


def evaluar_modelos(rf1, rf2, X_test1, y_test1, X_test2, y_test2):
    print("\n📊 Evaluación detallada del MODELO 1 (solo redes válidas):\n")
    y_pred1 = rf1.predict(X_test1)
    print(confusion_matrix(y_test1, y_pred1))
    print(classification_report(y_test1, y_pred1, digits=4))

    print("\n📊 Evaluación detallada del MODELO 2 (válidas + sospechosas):\n")
    y_pred2 = rf2.predict(X_test2)
    print(confusion_matrix(y_test2, y_pred2))
    print(classification_report(y_test2, y_pred2, digits=4))


def find_and_score_bssid(df, bssid_input):
    # Normalizar formato
    bssid_input = bssid_input.strip().upper()

    # Buscar BSSID en el dataframe
    row = df[df['bssid'] == bssid_input].head(1)

    if row.empty:
        print(f"❌ No se encontró el BSSID {bssid_input} en los datos.")
        return

    row = row.iloc[0]
    score = estimate_security_advanced(row)
    essid = row.get('essid', 'Desconocido')

    print("\n🔍 Resultado de análisis para el BSSID solicitado:")
    print(f"📡 BSSID: {bssid_input}")
    print(f"🆔 ESSID: {essid}")
    print(f"🔐 Puntuación de seguridad: {score:.2f}")

    if score < 0.3:
        print(Fore.RED + "❗ Esta red es altamente vulnerable." + Style.RESET_ALL)
    elif score < 0.6:
        print(Fore.YELLOW + "⚠ Nivel medio de vulnerabilidad." + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "✅ Red con buena configuración de seguridad." + Style.RESET_ALL)


def explain_security(score):
    if score >= 0.9:
        return "Cifrado WPA3 - Muy seguro"
    elif score >= 0.6:
        return "Cifrado WPA2/WPA - Medianamente seguro"
    elif score >= 0.3:
        return "Cifrado WEP - Débil"
    elif score > 0.0:
        return "Cifrado WEP - Muy débil"
    else:
        return "Sin cifrado - Inseguro"

    # Normalizar el BSSID de entrada (quitar espacios y convertir a mayúsculas)
    bssid = bssid.strip().upper()

    # Validar formato del BSSID
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', bssid):
        print(f"❌ Error: '{bssid}' no es un BSSID válido. Debe tener el formato XX:XX:XX:XX:XX:XX.")
        return

    # Buscar el BSSID en el DataFrame
    ap = df[df['bssid'].str.upper() == bssid]

    if ap.empty:
        print(f"❌ No se encontró el BSSID '{bssid}' en los datos.")
        return

    # Obtener la primera fila (en caso de múltiples coincidencias, tomar la primera)
    ap_row = ap.iloc[0]
    security_score = ap_row['security_score']
    essid = ap_row['essid']
    privacy = ap_row['privacy']

    # Mostrar resultados
    print(f"\n🔎 Resultado para BSSID: {bssid}")
    print(f"ESSID: {essid}")
    print(f"Cifrado: {privacy}")
    print(f"Puntuación de Seguridad: {security_score:.3f}")
    print(f"Explicación: {explain_security(security_score)}")

def plot_confusion_matrices(y_test1, y_pred1, y_test2, y_pred2, output_dir="resultados_wifi"):
    labels = ['No Vulnerable', 'Vulnerable']

    # Crear matrices de confusión
    cm1 = confusion_matrix(y_test1, y_pred1)
    cm2 = confusion_matrix(y_test2, y_pred2)

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Matriz modelo 1
    sns.heatmap(cm1, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels, ax=axes[0])
    axes[0].set_title("Matriz de Confusión - Modelo 1 (solo válidas)")
    axes[0].set_xlabel("Predicción")
    axes[0].set_ylabel("Real")

    # Matriz modelo 2
    sns.heatmap(cm2, annot=True, fmt="d", cmap="Greens", xticklabels=labels, yticklabels=labels, ax=axes[1])
    axes[1].set_title("Matriz de Confusión - Modelo 2 (válidas + sospechosas)")
    axes[1].set_xlabel("Predicción")
    axes[1].set_ylabel("Real")

    plt.tight_layout()
    output_path = os.path.join(output_dir, "confusion_matrices.png")
    plt.savefig(output_path)
    plt.close()  # ✅ Cierra la figura para evitar que se muestre o quede en memoria
    print(f"\n📌 Matrices de confusión guardadas en: {output_path}")

def train_rf_model(df):
    df['vulnerable'] = (df['# beacons_adjusted'] > df['# beacons_adjusted'].quantile(0.75)).astype(int)
    X = df[['power', '# beacons_adjusted', '# iv', 'security_score']]
    y = df['vulnerable']
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    print(classification_report(y_test, model.predict(X_test)))
    df['vulnerability_probability'] = model.predict_proba(scaler.transform(X))[:, 1]
    return df, model

def forecast_beacons(df_valid, exclude_minutes=50, output_dir=None):
    #print(f\"🔢 Redes válidas en esta etapa: {len(df)}\")
    df_prophet = df_valid[['time', '# beacons_adjusted']].rename(columns={'time': 'ds', '# beacons_adjusted': 'y'})
    df_prophet['y'] = df_prophet['y'].ewm(span=60).mean()

    # Excluir primeras capturas
    exclude_minutes = int(exclude_minutes)  # Ensure exclude_minutes is an integer
    start_time = df_prophet['ds'].min() + pd.Timedelta(minutes=exclude_minutes)
    df_prophet = df_prophet[df_prophet['ds'] > start_time]

    model = Prophet(daily_seasonality=False, seasonality_mode='multiplicative', seasonality_prior_scale=0.1)
    model.add_seasonality(name='hourly', period=24, fourier_order=6)
    model.fit(df_prophet)
    future = model.make_future_dataframe(periods=24, freq='H')
    forecast = model.predict(future)

    # Gráfico personalizado
    fig = model.plot(forecast)
    ax = fig.gca()
    fig.suptitle("📡 Predicción de Actividad de Redes WiFi", fontsize=14)
    ax.set_xlabel("Tiempo (ds)")
    ax.set_ylabel("Beacons Ajustados")
    fig.tight_layout()
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, "forecast.png")
        fig.savefig(filepath)
        print(f"[✓] Gráfico de forecast personalizado guardado como {filepath}")
    else:
        fig.savefig("forecast.png")
        print(f"[✓] Gráfico de forecast personalizado guardado como forecast.png")

def elbow_kmeans(df_valid):
    #print(f\"🔢 Redes válidas en esta etapa: {len(df)}\")
    # Filtrar filas con valores válidos de potencia y beacons
    df_clean = df_valid[
        df_valid['power'].notna() &
        (df_valid['power'] >= -100) &
        (df_valid['power'] <= -10) &
        df_valid['# beacons_adjusted'].notna()
    ].copy()

    #print("🧪 Valores únicos de potencia en clustering:", df_clean['power'].unique())
    print(df_raw[df_raw['power'] == 0][['bssid', 'essid', 'power']])

    if df_clean.empty:
        print("❌ No hay suficientes datos válidos para clustering.")
        return df_valid, None, 0

    X = df_clean[['power', '# beacons_adjusted']]
    X_scaled = StandardScaler().fit_transform(X)

    # Determinar el número óptimo de clusters
    inertias = [KMeans(n_clusters=k).fit(X_scaled).inertia_ for k in range(1, 10)]
    elbow = KneeLocator(range(1, 10), inertias, curve='convex', direction='decreasing').elbow or 3

    # Entrenar modelo KMeans final
    kmeans_model = KMeans(n_clusters=elbow, random_state=42)
    df_clean['cluster'] = kmeans_model.fit_predict(X_scaled)

    # Asignar cluster de vuelta a df_valid basado en BSSID
    df_valid = df_valid.merge(df_clean[['bssid', 'cluster']], on='bssid', how='left')

    return df_valid, kmeans_model, elbow

def plot_clusters(df_valid, kmeans_model, n_clusters, output_dir=None):
    import os

    # 1) Scatter de los puntos
    plt.figure(figsize=(8, 6))
    sns.scatterplot(
        data=df_valid,
        x='power', y='# beacons_adjusted',
        hue='cluster',
        palette='viridis',
        legend='full',
        alpha=0.6
    )

    # 2) Calcular y dibujar centroides en espacio original
    
    centroids = df_valid.groupby('cluster')[['power', '# beacons_adjusted']].mean()

    plt.scatter(
        centroids['power'], centroids['# beacons_adjusted'],
        marker='X', s=80, c=centroids.index, cmap='viridis', edgecolors='black', label='Centroides'
    )

    # 3) Anotar cada centroide con su id y valores
    for cluster_id, (px, py) in centroids.iterrows():
        plt.text(px, py,
                 f" C{cluster_id}\n({px:.1f}, {py:.0f})",
                 fontsize=9, weight='bold',
                 ha='left', va='bottom', color='black')

    # 4) Etiquetas y leyenda
    plt.title("🔐 Clustering de Redes WiFi (Potencia vs Beacons)")
    plt.xlabel("Potencia de Señal (dBm)")
    plt.ylabel("Beacons Ajustados")
    plt.legend(title="Cluster", loc="upper right")
    plt.tight_layout()

    # 5) Guardar o mostrar
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "clusters.png")
        plt.savefig(path)
        print(f"[✓] Gráfico de clustering guardado como {path}")
    else:
        plt.show()

    # 6) Resumen estadístico en consola
    print("\n📊 Resumen de Clusters:")
    for cid, group in df_valid.groupby('cluster'):
        cnt = len(group)
        mean_pwr = group['power'].mean()
        mean_bea = group['# beacons_adjusted'].mean()
        print(f" • Cluster {cid}: {cnt} APs — Potencia media {mean_pwr:.1f} dBm, Beacons ajust. medio {mean_bea:.0f}")

    return df_valid

def detect_isolation_anomalies(df, exclude_minutes=50):
    #print(f\"🔢 Redes válidas en esta etapa: {len(df)}\")
    # Asumimos que capture_second y capture_window ya están en df
    df_filtered = df[df['capture_window'] >= exclude_minutes].copy()

    # Filtrar redes con # beacons_adjusted por encima del percentil 75
    q3 = df_filtered['# beacons_adjusted'].quantile(0.75)
    print(f"📊 Umbral de filtrado (# beacons_adjusted > {q3})")
    df_filtered = df_filtered[df_filtered['# beacons_adjusted'] > q3]

    # Agrupar por BSSID, tomando el promedio de características numéricas y la primera entrada para otras columnas
    agg_dict = {
        'power': 'mean',
        '# beacons_adjusted': 'mean',
        '# iv': 'mean',
        'time': 'first',
        'essid': 'first',
        'privacy': 'first',
        'authentication': 'first',
        'security_score': 'first',
        'capture_window': 'first',
        'capture_second': 'first'
    }
    df_filtered = df_filtered.groupby('bssid').agg(agg_dict).reset_index()

    X = df_filtered[['power', '# beacons_adjusted', '# iv']].dropna()
    print(f"📊 Tamaño de df_filtered después de agrupar por BSSID: {len(df_filtered)}")

    if len(X) == 0:
        print("❌ No hay datos válidos para detectar anomalías después de filtrar y agrupar.")
        df['Anomaly'] = 0
        df[df['Anomaly'] == 1].to_csv('anomalies.csv', index=False)
        print(f"[✓] Anomalías detectadas fuera del periodo inicial: 0 (ver anomalies.csv)")
        return df

    iso = IsolationForest(contamination=0.1, random_state=42)
    iso.fit(X)  # Fit the model before computing anomaly scores
    df_filtered['Anomaly_Score'] = iso.decision_function(X)
    df_filtered['Anomaly'] = 0  # Inicializar todos como no anómalos

    # Seleccionar los 5 puntos más anómalos (menores puntajes)
    if len(df_filtered) >= 5:
        top_anomalies = df_filtered.nsmallest(5, 'Anomaly_Score')
        df_filtered.loc[top_anomalies.index, 'Anomaly'] = 1
    else:
        # Si hay menos de 5 puntos, marcar todos los detectados por IsolationForest
        df_filtered['Anomaly'] = iso.fit_predict(X)
        df_filtered['Anomaly'] = df_filtered['Anomaly'].map({1: 0, -1: 1})

    # Imprimir estadísticas de # beacons_adjusted para depuración
    print("\n📊 Estadísticas de # beacons_adjusted para redes anómalas:")
    anomalies = df_filtered[df_filtered['Anomaly'] == 1]
    if not anomalies.empty:
        print(f"  Mínimo: {anomalies['# beacons_adjusted'].min()}")
        print(f"  Máximo: {anomalies['# beacons_adjusted'].max()}")
        print(f"  Promedio: {anomalies['# beacons_adjusted'].mean():.2f}")
    else:
        print("  No se encontraron anomalías.")
    print("\n📊 Estadísticas de # beacons_adjusted para redes normales:")
    normals = df_filtered[df_filtered['Anomaly'] == 0]
    if not normals.empty:
        print(f"  Mínimo: {normals['# beacons_adjusted'].min()}")
        print(f"  Máximo: {normals['# beacons_adjusted'].max()}")
        print(f"  Promedio: {normals['# beacons_adjusted'].mean():.2f}")
    else:
        print("  No se encontraron redes normales.")

    # Fusionar etiquetas al original
    df = df.drop(columns=['Anomaly'], errors='ignore')  # Eliminar columna Anomaly existente si la hay
    df = df.merge(df_filtered[['bssid', 'Anomaly']], on='bssid', how='left')
    df['Anomaly'].fillna(0, inplace=True)
    df['Anomaly'] = df['Anomaly'].astype(int)

    df[df['Anomaly'] == 1].to_csv('anomalies.csv', index=False)
    print(f"[✓] Anomalías detectadas fuera del periodo inicial: {df['Anomaly'].sum()} (ver anomalies.csv)")
    return df

def threat_prioritization(df):
    df['attack_score'] = (
        (df['power'] / -100 * WEIGHTS['power']) +
        (df['# beacons_adjusted'] / (df['# beacons_adjusted'].max() + 1e-5) * WEIGHTS['traffic']) +
        (df['# iv'] / (df['# iv'].max() + 1e-5) * WEIGHTS['ivs']) +
        ((1 - df['security_score']) * WEIGHTS['security']) +
        (df['vulnerability_probability'] * 0.5)
    )
    df['attack_score'] = (df['attack_score'] - df['attack_score'].min()) / \
                         (df['attack_score'].max() - df['attack_score'].min()) * 100
    top10 = df.nlargest(10, 'attack_score')
    print(top10[['essid', 'bssid', 'attack_score', 'vulnerability_probability']].to_markdown(index=False))
    return top10

def generate_dictionary(essids, output="wpa_dict_markov.txt"):
    print("[🔐] Generando diccionario inteligente con Markov Chains")
    model = defaultdict(list)
    for word in essids:
        word = re.sub(r'[^a-zA-Z0-9]', '', word)
        for i in range(len(word) - 2):
            prefix = word[i:i+2]
            model[prefix].append(word[i+2])

def generate():
    seed = random.choice(list(model.keys()))
    result = seed
    for _ in range(6):
        next_chars = model.get(result[-2:], ['a'])
        result += random.choice(next_chars)
    return result

    samples = [generate() for _ in range(100)]
    with open(output, 'w') as f:
        f.write("\n".join(samples))
    print(f"[✓] Diccionario generado: {output}")
    return samples


def plot_feature_importance(model, feature_names, output="rf_feature_importance.png", titulo="Importancia de Características (Random Forest)"):
    import matplotlib.pyplot as plt

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]

    plt.figure(figsize=(8, 5))
    plt.title(titulo)
    plt.bar(range(len(importances)), importances[indices], color="teal", align="center")
    plt.xticks(range(len(importances)), [feature_names[i] for i in indices], rotation=45)
    plt.tight_layout()
    plt.savefig(output)
    plt.close()

    print(f"[✓] Gráfico de importancia de características guardado como: {output}")


def plot_anomaly_overlay(df, exclude_minutes=50, output_dir=None, output="anomaly_overlay.png"):
    import matplotlib.patches as mpatches
    from matplotlib.dates import DateFormatter

    df['Anomaly'] = df['Anomaly'].astype(int)
    df['time'] = pd.to_datetime(df['time'])

    # Filtrar datos para incluir solo aquellos con capture_window >= exclude_minutes
    df_filtered = df[df['capture_window'] >= exclude_minutes].copy()

    plt.figure(figsize=(12, 6))
    palette = {0: 'darkblue', 1: 'red'}
    ax = sns.scatterplot(data=df_filtered, x='time', y='# beacons_adjusted', hue='Anomaly', palette=palette, s=20, edgecolor='black', linewidth=0.5)

    # Etiquetar los puntos anómalos con su ESSID
    for _, row in df_filtered[df_filtered['Anomaly'] == 1].iterrows():
        ax.text(row['time'], row['# beacons_adjusted'] + 100, row['essid'], fontsize=9, color='red', ha='left')

    min_time = df['time'].min()
    cutoff = min_time + pd.Timedelta(minutes=exclude_minutes)
    plt.axvspan(min_time, cutoff, color='gray', alpha=0.2, label=f"{exclude_minutes} min ignorados")

    normal_patch = mpatches.Patch(color='darkblue', label='Normal')
    anomaly_patch = mpatches.Patch(color='red', label='Anómala')
    exclude_patch = mpatches.Patch(color='gray', alpha=0.2, label='Inicio excluido')
    plt.legend(handles=[normal_patch, anomaly_patch, exclude_patch], title="Actividad")

    ax.xaxis.set_major_formatter(DateFormatter('%H:%M'))
    plt.title("⚠️ Actividad de Redes con Detección de Anomalías")
    plt.xlabel("Time")
    plt.ylabel("Beacons Ajustados")
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, output)
        plt.savefig(filepath)
        print(f"[✓] Gráfico de anomalías guardado como {filepath}")
    else:
        plt.savefig(output)
        print(f"[✓] Gráfico de anomalías guardado como {output}")

def plot_dictionary_samples(samples, output="dictionary_preview.png"):
    plt.figure(figsize=(8, 5))
    plt.title("Ejemplos de Claves Generadas con Markov")
    text = "\n".join(samples[:10])
    plt.text(0.01, 0.9, text, fontsize=12, family="monospace")
    plt.axis("off")
    plt.savefig(output)
    print(f"[✓] Vista previa del diccionario guardada: {output}")

def export_security_summary(df, output="wifi_summary.csv"):
    def explain_security(score):
        if score >= 0.9:
            return "Cifrado WPA3 - Muy seguro"
        elif score >= 0.6:
            return "Cifrado WPA2/WPA - Medianamente seguro"
        elif score >= 0.3:
            return "Cifrado WEP - Débil"
        elif score > 0.0:
            return "Cifrado WEP - Muy débil"
        else:
            return "Sin cifrado - Inseguro"

    summary = df[['bssid', 'essid', 'privacy', 'security_score']].copy()
    summary['explicación'] = summary['security_score'].apply(explain_security)
    summary.sort_values(by='security_score', inplace=True)
    summary.to_csv(output, index=False)
    print ()
    print(f"[✓] Resumen de seguridad exportado en: {output}")

def print_security_summary(df):
    def classify_level(score):
        if score >= 0.9:
            return "Muy seguro (score >= 0.9)"
        elif score >= 0.6:
            return "Seguro (score >= 0.6)"
        elif score >= 0.3:
            return "Débil (score >= 0.3)"
        elif score > 0.0:
            return "Muy débil (score > 0.0)"
        else:
            return "Inseguro (score = 0)"

    df['nivel'] = df['security_score'].apply(classify_level)

    print("\n📊 Recuento de APs por nivel de seguridad:\n")
    niveles_deseados = [
        "Muy seguro (score >= 0.9)",
        "Seguro (score >= 0.6)",
        "Débil (score >= 0.3)",
        "Muy débil (score > 0.0)",
        "Inseguro (score = 0)"
    ]
    counts = df['nivel'].value_counts().reindex(niveles_deseados, fill_value=0)
    for nivel, count in counts.items():
        barra = '█' * min(count, 40)
        print(f"{nivel:<30} | {barra} ({count})")

    print("\n🔥 Top 3 redes más inseguras por cada tipo (excluyendo ESSID vacío):\n")
    for tipo in niveles_deseados:
        sub = df[(df['nivel'] == tipo) & (df['essid'] != '')].nsmallest(100, 'security_score')
        if not sub.empty:
            print(f"\n🛑 {tipo}:\n")
            print(sub[['bssid', 'essid', 'privacy', 'security_score']].to_markdown(index=False))

# MAIN
if __name__ == "__main__":
    # === CONFIGURACIÓN ===
    input_file = "beacons-02.csv"  # Cambia este nombre si es necesario
    output_dir = "resultados_wifi"
    os.makedirs(output_dir, exist_ok=True)

    # === CARGA DE DATOS ===
    print("📥 Cargando datos...")
    df_raw = load_data(input_file)

    if df_raw.empty:
        print("❌ No se pudo cargar el archivo.")
        exit()

    print(f"✅ Datos cargados: {len(df_raw)} registros procesados.")

    # --- Separación de redes sospechosas con motivos ---
    required_fields = ['bssid', 'channel', 'speed', 'power']
    df_raw['motivo_sospecha'] = ''

    # 1. Campos nulos
    null_mask = df_raw[required_fields].isnull().any(axis=1)
    df_raw.loc[null_mask, 'motivo_sospecha'] += 'Campos nulos; '

    # 2. Canal inválido (0 o -1)
    canal_invalido = df_raw['channel'].isin([0, -1])
    df_raw.loc[canal_invalido, 'motivo_sospecha'] += 'Canal inválido; '

    # 3. Speed inválida (-1 o negativa)
    speed_invalida = df_raw['speed'] <= -1
    df_raw.loc[speed_invalida, 'motivo_sospecha'] += 'Speed inválida; '

    # 4. Potencia inválida (-1 o mayor a 0)
    potencia_invalida = (df_raw['power'] == -1) | (df_raw['power'] > 0)
    df_raw.loc[potencia_invalida, 'motivo_sospecha'] += 'Potencia inválida; '

    # 5. Crear máscara de redes sospechosas
    incomplete_mask = df_raw['motivo_sospecha'].str.strip() != ''

    # 6. Filtrar
    df_suspicious = df_raw[incomplete_mask].copy()
    df_valid = df_raw[~incomplete_mask].copy()
    df_suspicious['privacy'] = df_suspicious['privacy'].replace('', 'UNKNOWN')
    df_suspicious['security_score'] = df_suspicious.apply(estimate_security_advanced, axis=1)


    # Mostrar en consola la tabla de redes sospechosas
    mostrar_redes_sospechosas(df_suspicious)

    print(f"\n🛡️ Redes válidas: {len(df_valid)}")
    print(f"⚠️ Redes sospechosas: {len(df_suspicious)}")
    print ()

    # === ANÁLISIS 1: PREDICCIÓN DE VULNERABILIDADES ===
    print("\n🔍 Entrenando modelo Random Forest para vulnerabilidades...")
    #comparar_modelos(df_valid, df_suspicious)

    # Después de comparar_modelos
    modelo1, features1, X_test1, y_test1, modelo2, features2, X_test2, y_test2 = comparar_modelos(df_valid, df_suspicious)

    evaluar_modelos(modelo1, modelo2, X_test1, y_test1, X_test2, y_test2)

    y_pred1 = modelo1.predict(X_test1)
    y_pred2 = modelo2.predict(X_test2)

    plot_confusion_matrices(y_test1, y_pred1, y_test2, y_pred2, output_dir=output_dir)

    # === GRAFICAR IMPORTANCIA DE CARACTERÍSTICAS PARA AMBOS MODELOS ===
    plot_feature_importance(modelo1, features1, output=os.path.join(output_dir, "rf_features_model1.png"), titulo="Importancia de Caracteristicas - Randon Forest (Modelo solo válidas)")
    plot_feature_importance(modelo2, features2, output=os.path.join(output_dir, "rf_features_model2.png"), titulo="Importancia de Caracteristicas - Randon Forest (Modelo con sospechosas)")


    # --- Aplicar modelo 2 (válidas + sospechosas) para generar security_score global ---
    df_completo = pd.concat([df_valid, df_suspicious], ignore_index=True)

    # Añadir flags binarios como en el entrenamiento
    df_completo['power_missing'] = (df_completo['power'] == -1).astype(int)
    df_completo['speed_missing'] = (df_completo['speed'] == -1).astype(int)
    df_completo['channel_missing'] = (df_completo['channel'] <= 0).astype(int)

    # Imputar datos
    X_completo = df_completo[features2]
    imputer = SimpleImputer(strategy='mean')
    X_completo_imputed = imputer.fit_transform(X_completo)

    # Predecir score
    df_completo['vulnerable_rf'] = modelo2.predict(X_completo_imputed)
    df_completo['proba_rf'] = modelo2.predict_proba(X_completo_imputed)[:, 1]
    df_completo['security_score_rf'] = 1 - df_completo['proba_rf']

    # Imprimir resumen actualizado y exportar CSV
    df_temp = df_completo.copy()
    df_temp['security_score'] = df_temp['security_score_rf']
    print_security_summary(df_temp)

    export_security_summary(df_completo, output=os.path.join(output_dir, "resumen_seguridad_rf.csv"))

   # === ANÁLISIS 6: RESUMEN DE SEGURIDAD ===
    print("\n🧠 Resumen y ranking de redes WiFi inseguras:")
    print_security_summary(df_valid)

    # === ANÁLISIS 2: SERIES TEMPORALES CON PROPHET ===
    print("\n📈 Generando forecast de actividad...")
    forecast_beacons(df_valid, exclude_minutes=10, output_dir=output_dir)

    # === ANÁLISIS 3: CLUSTERING CON MÉTODO DEL CODO ===
    print("\n📊 Ejecutando clustering dinámico...")
    df_valid, kmeans_model, k = elbow_kmeans(df_valid)
    plot_clusters(df_valid, kmeans_model, k, output_dir)

    # === ANÁLISIS 4: DETECCIÓN DE ANOMALÍAS CON ISOLATION FOREST ===
    print("\n🚨 Detectando anomalías en la actividad...")
    df_valid = detect_isolation_anomalies(df_valid)
    plot_anomaly_overlay(df_valid, output_dir=output_dir)

    # === ANÁLISIS 5: GENERACIÓN INTELIGENTE DE DICCIONARIOS (MARKOV) ===
    print("\n📚 Generando diccionario predictivo con Markov Chains...")
    generate_dictionary(df_raw['essid'], output=os.path.join(output_dir, "wpa_dict_markov.txt"))

    # === BÚSQUEDA DE BSSID ===
    print("\n🔍 Búsqueda de BSSID específico")
    bssid_input = input("Introduce un BSSID (formato XX:XX:XX:XX:XX:XX) o presiona Enter para continuar: ").strip()
    if bssid_input:
       find_and_score_bssid(df_valid, bssid_input)

    print("\n✅ Análisis completo terminado. Archivos listos en:", output_dir)

