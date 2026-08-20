"""
analyze.py — Log Anomaly Detector
==================================
SSH auth.log fayllaridan "Failed password" hodisalarini o'qib,
IP bo'yicha 5 daqiqalik oynada urinishlar sonini hisoblaydi va
statistik (z-score) usul bilan brute-force anomaliyalarini topadi.

Ishlatish:
    python3 analyze.py

Chiqish:
    output/timeline.png          - vaqt bo'yicha failed login'lar grafigi
    output/top_offenders.png     - eng ko'p urinish qilgan IP'lar
    output/anomaly_report.csv    - aniqlangan anomaliyalar ro'yxati
"""

import re
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

LOG_PATH = "data/auth.log"
WINDOW = "5min"      # agregatsiya oynasi
Z_THRESHOLD = 3.0     # anomaliya chegarasi (necha standart og'ishdan yuqori)

LOG_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port"
)


def parse_logs(path: str) -> pd.DataFrame:
    records = []
    with open(path) as f:
        for line in f:
            m = LOG_PATTERN.match(line)
            if not m:
                continue
            ts = datetime.strptime(m.group("ts"), "%b %d %H:%M:%S").replace(year=2026)
            records.append({"timestamp": ts, "ip": m.group("ip"), "user": m.group("user")})
    df = pd.DataFrame(records)
    if df.empty:
        raise ValueError("Log faylida mos qatorlar topilmadi — LOG_PATTERN'ni tekshiring.")
    return df


def detect_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    # Har bir IP uchun WINDOW oynasida nechta failed urinish borligini hisoblash
    counts = (
        df.set_index("timestamp")
          .groupby("ip")
          .resample(WINDOW)
          .size()
          .reset_index(name="attempts")
    )
    counts = counts[counts["attempts"] > 0]

    # Har bir IP o'zining o'rtacha va std'iga nisbatan z-score olinadi
    stats = counts.groupby("ip")["attempts"].agg(["mean", "std"]).rename(
        columns={"mean": "ip_mean", "std": "ip_std"}
    )
    counts = counts.merge(stats, on="ip")
    counts["ip_std"] = counts["ip_std"].fillna(0).replace(0, 1e-6)
    counts["z_score"] = (counts["attempts"] - counts["ip_mean"]) / counts["ip_std"]

    # Qo'shimcha oddiy qoida: 5 daqiqada 15+ urinish — shubhali, deb belgilanadi
    counts["is_anomaly"] = (counts["z_score"] > Z_THRESHOLD) | (counts["attempts"] >= 15)
    return counts


def plot_timeline(counts: pd.DataFrame, out_path: str):
    fig, ax = plt.subplots(figsize=(12, 5))
    for ip, grp in counts.groupby("ip"):
        ax.plot(grp["timestamp"], grp["attempts"], marker="o", markersize=3, label=ip, linewidth=1)

    anomalies = counts[counts["is_anomaly"]]
    ax.scatter(anomalies["timestamp"], anomalies["attempts"], color="red", s=60,
               zorder=5, label="Anomaliya", marker="x")

    ax.set_title("Vaqt bo'yicha 'Failed Password' urinishlari (5 daqiqalik oyna)")
    ax.set_xlabel("Vaqt")
    ax.set_ylabel("Urinishlar soni")
    ax.legend(fontsize=8, loc="upper left")
    fig.autofmt_xdate()
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()


def plot_top_offenders(df: pd.DataFrame, out_path: str):
    top = df["ip"].value_counts().head(10)
    fig, ax = plt.subplots(figsize=(8, 5))
    colors = ["#d62728" if v >= 30 else "#1f77b4" for v in top.values]
    ax.barh(top.index[::-1], top.values[::-1], color=colors[::-1])
    ax.set_title("Eng ko'p 'Failed Password' yuborgan IP manzillar")
    ax.set_xlabel("Jami urinishlar soni")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()


def main():
    df = parse_logs(LOG_PATH)
    print(f"Jami 'Failed password' hodisalari: {len(df)}")
    print(f"Noyob IP manzillar: {df['ip'].nunique()}")

    counts = detect_anomalies(df)
    anomalies = counts[counts["is_anomaly"]].sort_values("attempts", ascending=False)

    print(f"\nAniqlangan anomaliya oynalari: {len(anomalies)}")
    if not anomalies.empty:
        print(anomalies[["timestamp", "ip", "attempts", "z_score"]].to_string(index=False))

    anomalies.to_csv("output/anomaly_report.csv", index=False)
    plot_timeline(counts, "output/timeline.png")
    plot_top_offenders(df, "output/top_offenders.png")

    print("\nNatijalar saqlandi:")
    print("  output/anomaly_report.csv")
    print("  output/timeline.png")
    print("  output/top_offenders.png")


if __name__ == "__main__":
    main()
