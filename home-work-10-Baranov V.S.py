import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
# Загрузка данных
# data = {
#   "events": [
#     {"timestamp": "2023-08-21T08:00:00", "signature": "MALWARE-CNC Win.Trojan.Jadtre variant outbound connection"},
#     # Добавьте остальные события аналогично
#   ]
# }

file_path = "events.json"
with open(file_path) as f:
    data = json.load(f)

# Преобразование в DataFrame
df = pd.DataFrame(data["events"])

# Визуализация
plt.figure(figsize=(10, 6))
sns.countplot(data=df, x="signature")


plt.title("Распределение типов событий безопасности")
plt.xticks(rotation=90)  # Поворот подписей оси X для лучшей читаемости
plt.show()
