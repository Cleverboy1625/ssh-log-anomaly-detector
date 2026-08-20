# 🛡️ SSH Log Anomaly Detector

SSH `auth.log` fayllaridan brute-force login urinishlarini **statistik usul (z-score)**
va oyna-asosli agregatsiya orqali aniqlaydigan Python vositasi. Cybersecurity + Data
Science kesishmasidagi portfolio loyiha — SOC/Blue Team ishida qo'llaniladigan
log-tahlil yondashuvining soddalashtirilgan namunasi.

## 📊 Natijalar namunasi

| Timeline | Top offenders |
|---|---|
| ![timeline](output/timeline.png) | ![top](output/top_offenders.png) |

## ⚙️ Qanday ishlaydi

1. **Parsing** — regex yordamida `sshd` failed password qatorlari `timestamp / ip / user`
   ga ajratiladi.
2. **Agregatsiya** — har bir IP uchun 5 daqiqalik oynada urinishlar soni hisoblanadi
   (`pandas.resample`).
3. **Anomaliya aniqlash** — har bir IP o'zining tarixiy o'rtacha (mean) va standart
   og'ishiga (std) nisbatan **z-score** bilan baholanadi; shuningdek oddiy qoida
   sifatida 5 daqiqada ≥15 urinish ham "shubhali" deb belgilanadi.
4. **Vizualizatsiya** — vaqt bo'yicha grafik va eng faol IP'lar reytingi chiqariladi.

## 🚀 Ishga tushirish

```bash
pip install -r requirements.txt

# 1. Sintetik test log yaratish (real log bo'lmasa)
python3 generate_sample_logs.py

# 2. Tahlil qilish
python3 analyze.py
```

Chiqish: `output/timeline.png`, `output/top_offenders.png`, `output/anomaly_report.csv`

## 🔌 Real loglar bilan ishlatish

`data/auth.log` o'rniga o'zingizning haqiqiy `/var/log/auth.log` faylingizni
(yoki Wazuh `archives.log`dan filtrlangan qismini) qo'ying — format bir xil bo'lsa
(`sshd[...]: Failed password ...`), skript o'zgarishsiz ishlaydi.

Wazuh SIEM bilan integratsiya uchun: Wazuh manager'dan `alerts.json` eksport qilib,
`parse_logs()` funksiyasini JSON formatga moslab qayta yozish kifoya (`rule.id: 5710`
— SSHD authentication failed — filtri orqali).

## 🧠 Keyingi qadamlar (v2 g'oyalari)

- [ ] `IsolationForest` (scikit-learn) bilan ko'p o'lchamli anomaliya aniqlash
- [ ] GeoIP orqali hujum manbai davlatini aniqlash va xaritada ko'rsatish
- [ ] Real-time rejim: `tail -f` + streaming tahlil
- [ ] Slack/Telegram bot orqali anomaliya haqida darhol xabar yuborish

## 🗂️ Tuzilma

```
log-anomaly-detector/
├── data/auth.log              # kiruvchi log (sintetik yoki real)
├── generate_sample_logs.py    # test ma'lumot generatori
├── analyze.py                 # asosiy tahlil skripti
├── output/                    # grafiklar va CSV hisobot
├── requirements.txt
└── README.md
```

---
*Muallif: Oyatillo — Cybersecurity student @ IDU Tashkent | SOC/Blue Team yo'nalishi*
