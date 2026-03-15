import json
import os
import requests
import pandas as pd
import matplotlib.pyplot as plt
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VULNERS_API_KEY")

try:
    # -----------------------------
    # 1. Загрузка Suricata логов
    # -----------------------------
    with open("eve.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    print("Тип данных:", type(data))
    print("Количество записей:", len(data))

    if not isinstance(data, list) or len(data) == 0:
        print("Это не JSON-массив или он пустой")
        raise SystemExit

    df = pd.json_normalize(data)

    required_columns = [
        "timestamp",
        "event_type",
        "src_ip",
        "dest_ip",
        "alert.signature",
        "alert.severity"
    ]

    available_columns = [col for col in required_columns if col in df.columns]
    analysis_df = df[available_columns].copy()

    print("\nТаблица для анализа создана")
    print("Размер analysis_df:", analysis_df.shape)

    alerts_df = analysis_df[analysis_df["event_type"] == "alert"].copy()
    print("Количество alert-событий:", len(alerts_df))

    # -----------------------------
    # 2. Анализ Suricata
    # -----------------------------
    ip_counts = alerts_df["src_ip"].value_counts()
    signature_counts = alerts_df["alert.signature"].value_counts()

    print("\nТоп-5 src_ip по числу alert-событий:")
    print(ip_counts.head(5))

    print("\nТоп-5 alert.signature:")
    print(signature_counts.head(5))

    high_severity_df = alerts_df[alerts_df["alert.severity"] <= 2].copy()
    print("\nКоличество событий с severity <= 2:", len(high_severity_df))

    suspicious_ips = ip_counts[ip_counts >= 5].index.tolist()
    print("\nПодозрительные IP (>= 5 alert-событий):")
    print(suspicious_ips if suspicious_ips else "Не найдены")

    print("\n=== Реакция на угрозы ===")
    if suspicious_ips:
        for ip in suspicious_ips:
            print(f"Simulated block for IP: {ip}")
    else:
        print("Угрозы для simulated block не найдены")

    # -----------------------------
    # 3. Проверка Vulners API
    # -----------------------------
    print("\n=== Проверка Vulners API ===")

    url = "https://vulners.com/api/v3/search/id"
    headers = {
        "X-Api-Key": API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "id": ["CVE-2025-7775", "CVE-2025-10585"],
        "fields": ["*"],
        "references": True
    }

    response = requests.post(url, headers=headers, json=payload, timeout=20)
    print("HTTP статус Vulners:", response.status_code)

    vulners_rows = []

    if response.status_code == 200:
        vulners_data = response.json()
        print("Ответ Vulners успешно получен")

        documents = vulners_data.get("data", {}).get("documents", {})
        print("Количество найденных документов:", len(documents))

        for cve_id, doc in documents.items():
            title = doc.get("title")
            doc_type = doc.get("type")

            cvss = None
            if isinstance(doc.get("cvss"), dict):
                cvss = doc.get("cvss", {}).get("score")
            elif "cvss" in doc:
                cvss = doc.get("cvss")

            print(f"\n{cve_id}")
            print("Title:", title)
            print("Type:", doc_type)
            print("CVSS:", cvss)

            vulners_rows.append({
                "source": "vulners",
                "indicator_type": "cve",
                "indicator": cve_id,
                "severity_or_score": cvss,
                "details": title,
                "action": "notify_admin" if cvss is not None and float(cvss) >= 7.0 else "monitor"
            })

    else:
        print("Ошибка при обращении к Vulners API:")
        print(response.text)

    # -----------------------------
    # 4. Формирование отчёта
    # -----------------------------
    os.makedirs("output", exist_ok=True)

    report_rows = []

    # Строки по Suricata suspicious IP
    for ip, count in ip_counts.items():
        if count >= 5:
            report_rows.append({
                "source": "suricata",
                "indicator_type": "src_ip",
                "indicator": ip,
                "severity_or_score": count,
                "details": "Suspicious IP by alert frequency (>= 5 alerts)",
                "action": "simulated_block"
            })

    # Строки по Suricata high severity events
    for _, row in high_severity_df.iterrows():
        report_rows.append({
            "source": "suricata",
            "indicator_type": "alert_signature",
            "indicator": row["alert.signature"],
            "severity_or_score": row["alert.severity"],
            "details": f"{row['src_ip']} -> {row['dest_ip']}",
            "action": "alert"
        })

    # Строки по Vulners
    report_rows.extend(vulners_rows)

    report_df = pd.DataFrame(report_rows)
    report_path = os.path.join("output", "report.csv")
    report_df.to_csv(report_path, index=False, encoding="utf-8-sig")

    print(f"\nОтчёт сохранён: {report_path}")
    print("Размер отчёта:", report_df.shape)

    # -----------------------------
    # 5. Построение графика
    # -----------------------------
    top5_ips = ip_counts.head(5)

    plt.figure(figsize=(10, 6))
    top5_ips.plot(kind="bar")
    plt.title("Top-5 source IP by alert count")
    plt.xlabel("Source IP")
    plt.ylabel("Alert count")
    plt.xticks(rotation=45)
    plt.tight_layout()

    chart_path = os.path.join("output", "chart.png")
    plt.savefig(chart_path)
    plt.close()

    print(f"График сохранён: {chart_path}")

except FileNotFoundError:
    print("Ошибка: файл eve.json не найден")
except json.JSONDecodeError:
    print("Ошибка: файл eve.json повреждён или содержит невалидный JSON")
except requests.exceptions.RequestException as e:
    print("Ошибка сети/API:", e)
except Exception as e:
    print("Неожиданная ошибка:", e)