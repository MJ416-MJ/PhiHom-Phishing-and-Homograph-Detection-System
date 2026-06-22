



import csv
import re
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')

SHORTENERS_PATH = os.path.join(DATA_DIR, 'url_shorteners.txt')
INPUT_PATH = os.path.join(DATA_DIR, 'legitimate_domains.csv')
OUTPUT_PATH = os.path.join(DATA_DIR, 'legitimate_domains_clean.csv')

ABUSED_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.cfd'}

PRESERVE_DOMAINS = {
    'google.ml', 'google.ga', 'google.cf', 'google.tk',
    '163.com', '360.com', '360.cn', '114.com',
    '58.com', '51.com', '91.com', '123.com',
    '100.app', '365.systems',
}

PURE_NUMERIC_PATTERN = re.compile(r'^[0-9]+$')
LONG_NUMERIC_PATTERN = re.compile(r'^[0-9]{7,}$')
DGA_PATTERN = re.compile(r'^[a-z0-9]{15,}$')
RANDOM_LOOKING = re.compile(r'^[a-z0-9]{4,}[0-9]{4,}[a-z0-9]*$')

with open(INPUT_PATH, 'r', encoding='utf-8', errors='ignore') as f:
    reader = csv.reader(f)
    rows = list(reader)

clean_rows = []
removed_numeric = 0
removed_abused_tld = 0
removed_dga = 0
preserved = 0

for row in rows:
    if len(row) < 2:
        continue
    
    domain = row[1].strip().lower().rstrip('\r')
    
    if not domain or '.' not in domain:
        continue

    name = domain.split('.')[0]
    tld = '.' + domain.split('.')[-1]

    if domain in PRESERVE_DOMAINS:
        clean_rows.append([row[0], domain])
        preserved += 1
        continue

    if tld in ABUSED_TLDS:
        removed_abused_tld += 1
        continue

    if LONG_NUMERIC_PATTERN.match(name):
        removed_numeric += 1
        continue

    if DGA_PATTERN.match(name) and any(c.isdigit() for c in name) and sum(c.isdigit() for c in name) > len(name) * 0.4:
        removed_dga += 1
        continue

    clean_rows.append([row[0], domain])

with open(OUTPUT_PATH, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerows(clean_rows)

print(f"Original rows:          {len(rows)}")
print(f"Removed - long numeric: {removed_numeric}")
print(f"Removed - abused TLDs:  {removed_abused_tld}")
print(f"Removed - DGA style:    {removed_dga}")
print(f"Preserved explicitly:   {preserved}")
print(f"Remaining:              {len(clean_rows)}")