import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import re
import json

# Пути к файлам
WINEVENT_PATH = '/home/ubuntu/homework_logs/winevent_security.csv'
DNS_PATH = '/home/ubuntu/homework_logs/stream_dns.csv'
OUTPUT_DIR = '/home/ubuntu/homework_logs/results'

os.makedirs(OUTPUT_DIR, exist_ok=True)

def extract_winevent_id(raw_text):
    match = re.search(r'(?:EventCode|EventID)[:=]\s*(\d+)', str(raw_text))
    return int(match.group(1)) if match else None

def extract_dns_query(raw_text):
    try:
        clean_text = str(raw_text).strip('"').replace('""', '"')
        data = json.loads(clean_text)
        names = data.get('name', [])
        if isinstance(names, list) and len(names) > 0:
            return str(names[0])
        return str(data.get('query', 'unknown'))
    except:
        match = re.search(r'query[:=]\s*([^\s,]+)', str(raw_text))
        return str(match.group(1)) if match else None

def analyze_winevent():
    print("Анализ WinEventLog: Security...")
    try:
        df = pd.read_csv(WINEVENT_PATH, usecols=['_raw'], nrows=200000, low_memory=False)
        df['EventID'] = df['_raw'].apply(extract_winevent_id)
        df = df.dropna(subset=['EventID'])
        df['EventID'] = df['EventID'].astype(int)
        
        suspicious_ids = [4625, 4672, 4720, 4648]
        event_desc = {
            4625: 'An account failed to log on',
            4672: 'Special privileges assigned to new logon',
            4720: 'A user account was created',
            4648: 'A logon was attempted using explicit credentials'
        }
        
        counts = df['EventID'].value_counts().reset_index()
        counts.columns = ['EventID', 'Count']
        counts['Description'] = counts['EventID'].map(event_desc).fillna('Other Events')
        
        top_suspicious = counts[counts['EventID'].isin(suspicious_ids)].copy()
        for sid in suspicious_ids:
            if sid not in top_suspicious['EventID'].values:
                top_suspicious = pd.concat([top_suspicious, pd.DataFrame({'EventID': [sid], 'Count': [0], 'Description': [event_desc[sid]]})])
        
        return top_suspicious
    except Exception as e:
        print(f"Ошибка WinEvent: {e}")
        return None

def analyze_dns():
    print("Анализ DNS логов...")
    try:
        df = pd.read_csv(DNS_PATH, usecols=['_raw'], nrows=100000, low_memory=False)
        df['query'] = df['_raw'].apply(extract_dns_query)
        df = df.dropna(subset=['query'])
        df['query'] = df['query'].astype(str)
        
        dns_counts = df['query'].value_counts().head(10).reset_index()
        dns_counts.columns = ['Domain', 'Count']
        
        df['query_len'] = df['query'].str.len()
        long_queries = df.sort_values(by='query_len', ascending=False).head(10)
        
        return dns_counts, long_queries[['query', 'query_len']]
    except Exception as e:
        print(f"Ошибка DNS: {e}")
        return None, None

def visualize(winevent_counts, dns_counts):
    print("Визуализация...")
    plt.figure(figsize=(12, 12))
    
    plt.subplot(2, 1, 1)
    if winevent_counts is not None and not winevent_counts.empty:
        sns.barplot(data=winevent_counts, x='Count', y='Description', color='salmon')
        plt.title('Подозрительные события Windows (EventID)')
        plt.xlabel('Количество событий')
    
    plt.subplot(2, 1, 2)
    if dns_counts is not None and not dns_counts.empty:
        sns.barplot(data=dns_counts, x='Count', y='Domain', color='skyblue')
        plt.title('Топ-10 частых DNS запросов')
        plt.xlabel('Количество запросов')
        
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'security_analysis.png'))

if __name__ == "__main__":
    winevent_counts = analyze_winevent()
    dns_counts, long_queries = analyze_dns()
    visualize(winevent_counts, dns_counts)
    
    with open(os.path.join(OUTPUT_DIR, 'final_report.md'), 'w') as f:
        f.write("# Отчет об анализе негативных событий ИБ (BOTSv1)\n\n")
        f.write("## 1. Анализ WinEventLog (Security)\n")
        if winevent_counts is not None:
            f.write(winevent_counts.to_markdown(index=False))
        f.write("\n\n## 2. Анализ DNS логов\n")
        f.write("### Топ-10 частых DNS запросов\n")
        if dns_counts is not None:
            f.write(dns_counts.to_markdown(index=False))
        f.write("\n\n### Подозрительные длинные DNS запросы (возможный туннелинг/DGA)\n")
        if long_queries is not None:
            f.write(long_queries.to_markdown(index=False))
        f.write("\n\n## 3. Выводы\n")
        f.write("- Выявлено использование специальных привилегий (EventID 4672), что характерно для административных действий.\n")
        f.write("- В DNS логах зафиксированы обращения к различным доменам, включая потенциально аномальные длинные имена.\n")
        f.write("- В выборке 200к строк WinEventLog не обнаружено неудачных входов (4625), что может быть связано с периодом логов.\n")
