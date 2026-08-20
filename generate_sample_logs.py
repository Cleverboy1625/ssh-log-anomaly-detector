"""
generate_sample_logs.py
Sintetik SSH auth.log faylini yaratadi: oddiy foydalanuvchi xatolari +
bir nechta brute-force hujum "burst"lari (yuqori chastotali failed login).

Haqiqiy loyihada bu yerga o'zingizning /var/log/auth.log yoki Wazuh
alerts.json faylingizni qo'yasiz — parser strukturasi bir xil qoladi.
"""

import random
from datetime import datetime, timedelta

random.seed(42)

USERNAMES_NORMAL = ["oyatillo", "admin", "backup", "deploy", "test"]
USERNAMES_ATTACK = ["root", "admin", "administrator", "user", "guest",
                     "ubuntu", "oracle", "postgres", "test", "ftpuser"]

NORMAL_IPS = ["10.0.0.15", "10.0.0.22", "192.168.1.44"]
ATTACKER_IPS = ["185.220.101.45", "45.155.204.12", "194.87.31.9"]

start_time = datetime(2026, 8, 18, 0, 0, 0)
lines = []

def fmt(ts):
    return ts.strftime("%b %d %H:%M:%S")

# 1) Bir hafta davomida normal (kam sonli) failed login'lar
t = start_time
while t < start_time + timedelta(days=2):
    if random.random() < 0.15:  # kamdan-kam xato parol
        ip = random.choice(NORMAL_IPS)
        user = random.choice(USERNAMES_NORMAL)
        lines.append(f"{fmt(t)} server sshd[{random.randint(1000,9999)}]: "
                      f"Failed password for {user} from {ip} port {random.randint(30000,60000)} ssh2")
    t += timedelta(minutes=random.randint(20, 90))

# 2) 3 ta brute-force burst — qisqa vaqt ichida ko'p urinish
burst_starts = [
    start_time + timedelta(hours=10, minutes=5),
    start_time + timedelta(hours=27, minutes=40),
    start_time + timedelta(hours=41, minutes=10),
]

for burst_start in burst_starts:
    ip = random.choice(ATTACKER_IPS)
    bt = burst_start
    for _ in range(random.randint(40, 90)):  # bitta burst ichida urinishlar
        user = random.choice(USERNAMES_ATTACK)
        lines.append(f"{fmt(bt)} server sshd[{random.randint(1000,9999)}]: "
                      f"Failed password for invalid user {user} from {ip} port {random.randint(30000,60000)} ssh2")
        bt += timedelta(seconds=random.randint(1, 4))  # juda tez-tez

lines.sort(key=lambda l: datetime.strptime(l[:15], "%b %d %H:%M:%S").replace(year=2026))

with open("data/auth.log", "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"Yaratildi: data/auth.log ({len(lines)} qator)")
print(f"Brute-force IP'lar: {ATTACKER_IPS}")
