# מדריך מלא – PCAP Analyzer
### הסבר שורה-שורה לקראת ראיון עבודה

---

## תוכן עניינים
1. [מה זה בכלל הפרויקט הזה?](#1-מה-זה-בכלל-הפרויקט-הזה)
2. [requirements.txt – מה מתקינים ולמה](#2-requirementstxt)
3. [main.py – הקוד הראשי שורה-שורה](#3-mainpy)
4. [docker-compose.yml – Elasticsearch ו-Kibana](#4-docker-composeyml)
5. [Dockerfile – איך בונים את הקונטיינר](#5-dockerfile)
6. [Helm Chart – Kubernetes](#6-helm-chart)
7. [tests/test_parser.py – בדיקות](#7-teststest_parserpy)
8. [שאלות ראיון + תשובות מוכנות](#8-שאלות-ראיון)

---

## 1. מה זה בכלל הפרויקט הזה?

### רקע – מה זה PCAP?
דמיין שאתה עומד ליד כביש מהיר ומצלם כל מכונית שעוברת.
**PCAP** זה אותו דבר רק לרשת מחשבים — זה קובץ שמקליט את כל ה"מכוניות" (packets) שעוברות ברשת.

כל packet = חבילת מידע שנשלחת ברשת. למשל כשאתה פותח אתר, המחשב שולח ומקבל אלפי חבילות כאלה.

### מה הפרויקט עושה?
```
קובץ PCAP (הקלטת רשת)
        ↓
   Python קורא כל packet
        ↓
   ┌────────────────────────┐
   │  Elasticsearch         │  ← שומר כל packet כרשומה לחיפוש
   └────────────────────────┘
        ↓
   ┌────────────────────────┐
   │  Prometheus /metrics   │  ← מונה סטטיסטיקות בזמן אמת
   └────────────────────────┘
```

### למה SRE בונה דבר כזה?
SRE (Site Reliability Engineer) אחראי על כך שהמערכת **תעבוד ותישאר יציבה**.
כלי כזה עוזר לו:
- לראות **מה קורה ברשת** (מי מדבר עם מי)
- לזהות **חריגות** (למשל: פתאום הרבה מאוד traffic ל-IP מסוים)
- לחקור **תקלות** ("למה השרת היה איטי בשעה 3 לפנות בוקר?")

---

## 2. requirements.txt

```
dpkt==1.9.8
elasticsearch==8.13.0
prometheus_client==0.20.0
pytest==8.2.0
```

זה כמו **רשימת קניות** של הפרויקט. לפני שמריצים, מתקינים הכל עם:
```bash
pip install -r requirements.txt
```

| ספרייה | מה היא עושה | דוגמה מהחיים |
|--------|-------------|--------------|
| `dpkt` | קוראת קבצי PCAP וחולצת מידע מכל packet | כמו מי שפותח מעטפות ומוציא את התוכן |
| `elasticsearch` | שולחת נתונים ל-Elasticsearch | כמו דואר שמביא את המכתב ליעד |
| `prometheus_client` | יוצרת endpoint של מטריקות | כמו לוח מחוונים שמציג מספרים |
| `pytest` | מריצה בדיקות אוטומטיות | כמו בודק איכות שבודק שהכל עובד |

---

## 3. main.py

### חלק א׳ – ה-imports (שורות 1-12)

```python
import os
import sys
import time
import socket
import logging
import datetime
```

**מה זה imports?**
Python לא יודעת לעשות הכל לבד. היא מייבאת "כלים" ממאגר ספריות.

| import | מה הוא נותן לנו |
|--------|----------------|
| `os` | גישה למשתני סביבה (`ELASTIC_URL` וכו׳) |
| `sys` | קריאת ארגומנטים מה-CLI (מה כתבת אחרי `python main.py`) |
| `time` | להמתין בין ניסיונות חיבור (retry) |
| `socket` | להמיר כתובת IP מבינארי לטקסט (192.168.1.1) |
| `logging` | הדפסת לוגים מסודרים עם זמן ורמת חומרה |
| `datetime` | המרת timestamp למספר לתאריך קריא |

```python
import dpkt
from elasticsearch import Elasticsearch
from prometheus_client import Counter, start_http_server
```

אלה הספריות שהתקנו ב-requirements.txt.

---

### חלק ב׳ – הגדרת לוגים (שורות 14-19)

```python
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)
```

**מה זה לוגים?**
לוגים = יומן אירועים של התוכנה. במקום `print("משהו קרה")` שנראה גס, logging נותן:
```
2026-05-16 10:23:45 [INFO] Processed 1000 packets so far …
2026-05-16 10:23:46 [WARNING] ES write attempt 1/3 failed: Connection refused
2026-05-16 10:23:48 [ERROR] All 3 write attempts failed – document dropped.
```

**למה זה חשוב לSRE?**
בפרודקשן אין לך מסך לצפות בו. הלוגים הם העיניים שלך — הם נשמרים ואפשר לחפש בהם אחרי כן.

`level=logging.INFO` = הצג הודעות מסוג INFO ומעלה (INFO → WARNING → ERROR → CRITICAL).

---

### חלק ג׳ – קונפיגורציה ממשתני סביבה (שורות 21-26)

```python
ELASTIC_URL      = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_INDEX    = os.getenv("ELASTIC_INDEX", "pcap-packets")
ELASTIC_USERNAME = os.getenv("ELASTIC_USERNAME")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD")
METRICS_PORT     = int(os.getenv("METRICS_PORT", "9100"))
```

**מה זה משתני סביבה?**
במקום לכתוב בקוד `url = "http://localhost:9200"` (שזה קשיח ולא גמיש),
אנחנו אומרים: "תקרא את הערך מבחוץ".

`os.getenv("ELASTIC_URL", "http://localhost:9200")` אומר:
- תחפש משתנה סביבה בשם `ELASTIC_URL`
- אם לא מצאת — השתמש בברירת מחדל `http://localhost:9200`

**למה זה עקרון חשוב?**
אותה תוכנה רצה ב-3 סביבות שונות:
```
פיתוח:    ELASTIC_URL=http://localhost:9200
Staging:  ELASTIC_URL=http://staging-es:9200
פרודקשן:  ELASTIC_URL=http://prod-es-cluster:9200
```
אין צורך לשנות קוד — רק משתני סביבה. זה נקרא עקרון **12-Factor App**.

---

### חלק ד׳ – מטריקות Prometheus (שורות 28-44)

```python
packets_total = Counter(
    "pcap_packets_total",
    "Total packets processed, by L4 protocol",
    ["protocol"],
)
bytes_total = Counter(
    "pcap_bytes_total",
    "Total bytes of all packets processed, by L4 protocol",
    ["protocol"],
)
elastic_writes = Counter(
    "pcap_elastic_write_total",
    "Elasticsearch write attempts",
    ["status"],
)
```

**מה זה Counter?**
Counter = מונה שרק עולה. מושלם לספור "כמה פעמים X קרה".

כל Counter מקבל:
1. **שם** — `pcap_packets_total` (זה מה שמופיע ב-Prometheus)
2. **תיאור** — לבני אדם שיקראו את המטריקה
3. **labels** — קטגוריות שמאפשרות לסנן

**דוגמה לשימוש:**
```python
packets_total.labels(protocol="tcp").inc()   # מוסיף 1 ל-TCP
packets_total.labels(protocol="udp").inc()   # מוסיף 1 ל-UDP
```

**מה Prometheus רואה:**
```
pcap_packets_total{protocol="tcp"}   10815.0
pcap_packets_total{protocol="udp"}   10660.0
pcap_packets_total{protocol="icmp"}    242.0
```

**למה זה חשוב לSRE?**
מטריקות = נתונים מספריים בזמן אמת. עם זה:
- בונים גרפים ב-Grafana
- מגדירים **alerts** ("שלח לי SMS אם יש יותר מ-100 כשלים ב-Elasticsearch")

---

### חלק ה׳ – פונקציית parse_packet (שורות 47-90)

```python
def parse_packet(ts: float, raw: bytes) -> dict:
```

**מה זה הפונקציה הזאת?**
קולטת packet "גולמי" (bytes — בינארי טהור) ומחזירה dict פשוט עם שדות שאפשר לקרוא.

```python
    doc = {
        "timestamp":     datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "packet_length": len(raw),
        "src_ip":        None,
        "dst_ip":        None,
        "src_port":      None,
        "dst_port":      None,
        "l4_protocol":   "other",
    }
```

יוצרים מסמך ריק עם ברירות מחדל. כך אפילו packet שאי אפשר לנתח לא יגרום לקריסה.

**timestamp:**
`ts` הוא מספר כמו `1716000000.525` (שניות מאז 1/1/1970).
`utcfromtimestamp` הופך אותו ל-`"2026-05-16T06:09:25.525000Z"` — תאריך קריא.

```python
    try:
        eth = dpkt.ethernet.Ethernet(raw)
    except Exception:
        return doc
```

`try/except` = "נסה לעשות X, ואם נכשל — אל תקרוס, תמשיך".
אם ה-packet לא תקין, מחזירים את ה-doc הריק במקום להתרסק.

```python
    if not isinstance(eth.data, dpkt.ip.IP):
        return doc
```

בודקים: האם תוכן ה-Ethernet הוא IPv4?
אם לא (למשל ARP) — מחזירים doc עם `l4_protocol: "other"`.

**מה זה שכבות הרשת?**
```
┌─────────────────────────────────────┐
│  Ethernet (Layer 2)  — מי שולח למי  │
│  ┌───────────────────────────────┐  │
│  │  IP (Layer 3)  — כתובת IP     │  │
│  │  ┌─────────────────────────┐  │  │
│  │  │  TCP/UDP (Layer 4) — פורט│  │  │
│  │  │  ┌───────────────────┐  │  │  │
│  │  │  │  Data (payload)   │  │  │  │
│  │  │  └───────────────────┘  │  │  │
│  │  └─────────────────────────┘  │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

```python
    ip = eth.data
    doc["src_ip"] = _safe_inet(ip.src)
    doc["dst_ip"] = _safe_inet(ip.dst)
```

מוציאים את כתובות ה-IP המקור והיעד.
`ip.src` הוא בינארי (4 bytes), `_safe_inet` הופך אותו ל-"192.168.1.1".

```python
    if isinstance(ip.data, dpkt.tcp.TCP):
        doc["l4_protocol"] = "tcp"
        doc["src_port"]    = ip.data.sport
        doc["dst_port"]    = ip.data.dport
    elif isinstance(ip.data, dpkt.udp.UDP):
        doc["l4_protocol"] = "udp"
        doc["src_port"]    = ip.data.sport
        doc["dst_port"]    = ip.data.dport
    elif isinstance(ip.data, dpkt.icmp.ICMP):
        doc["l4_protocol"] = "icmp"
```

בודקים מה ה-protocol ב-Layer 4:
- **TCP** — פרוטוקול אמין (דואר רשום): HTTP, HTTPS, SSH
- **UDP** — פרוטוקול מהיר ללא אישור (גלויה): DNS, וידאו, גיימינג
- **ICMP** — הודעות מערכת: ping, "שרת לא נמצא"

---

### חלק ו׳ – write_to_elastic עם retry (שורות 93-113)

```python
def write_to_elastic(es: Elasticsearch, index: str, doc: dict, max_retries: int = 3) -> bool:
    for attempt in range(1, max_retries + 1):
        try:
            es.index(index=index, document=doc)
            elastic_writes.labels(status="success").inc()
            return True
        except Exception as exc:
            log.warning("ES write attempt %d/%d failed: %s", attempt, max_retries, exc)
            if attempt < max_retries:
                time.sleep(2 ** (attempt - 1))

    elastic_writes.labels(status="fail").inc()
    log.error("All %d write attempts failed – document dropped.", max_retries)
    return False
```

**מה זה retry עם exponential back-off?**
אם Elasticsearch לא מגיב, לא נוותר מיד. ננסה שוב עם המתנה גדלה:

```
ניסיון 1 → נכשל → ממתין 1 שניה  (2^0 = 1)
ניסיון 2 → נכשל → ממתין 2 שניות (2^1 = 2)
ניסיון 3 → נכשל → מוותרים, מתעדים כ-"fail"
```

**למה exponential (מעריכי) ולא המתנה קבועה?**
אם 1000 clients מנסים כל שניה = מציפים את השרת.
אם כל אחד ממתין קצת יותר = השרת מתאושש.

`es.index(index=index, document=doc)` = שולח את ה-dict שלנו ל-Elasticsearch כ-JSON.

---

### חלק ז׳ – open_reader (שורות 116-122)

```python
def open_reader(f):
    magic = f.read(4)
    f.seek(0)
    if magic == b"\x0a\x0d\x0d\x0a":
        return dpkt.pcapng.Reader(f)
    return dpkt.pcap.Reader(f)
```

**מה זה "magic bytes"?**
כל פורמט קובץ מתחיל ב-bytes מיוחדים שמזהים אותו:
- `\x0a\x0d\x0d\x0a` = pcapng (פורמט חדש)
- `\xd4\xc3\xb2\xa1` = pcap (פורמט ישן)

זה כמו להריח מה בבקבוק לפני שאתה שותה — קודם מזהים מה זה.
`f.seek(0)` = מחזירים את ה"מצביע" להתחלת הקובץ אחרי הקריאה.

---

### חלק ח׳ – main() (שורות 125-168)

```python
def main():
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else os.getenv("PCAP_PATH")
    if not pcap_path:
        log.error("No pcap file provided.")
        sys.exit(1)
```

`sys.argv` = רשימת מה שנכתב בטרמינל.
אם הרצת `python main.py sample.pcap`:
- `sys.argv[0]` = `"main.py"`
- `sys.argv[1]` = `"sample.pcap"`

`sys.exit(1)` = יוצא עם קוד שגיאה 1 (0 = הצלחה, כל דבר אחר = שגיאה).

```python
    start_http_server(METRICS_PORT)
    log.info("Prometheus metrics → http://0.0.0.0:%d/metrics", METRICS_PORT)
```

פותח שרת HTTP קטן על פורט 9100.
כשמישהו גולש ל-`http://localhost:9100/metrics` — רואה את המטריקות.

```python
    es_kwargs: dict = {"hosts": [ELASTIC_URL]}
    if ELASTIC_USERNAME and ELASTIC_PASSWORD:
        es_kwargs["basic_auth"] = (ELASTIC_USERNAME, ELASTIC_PASSWORD)
    es = Elasticsearch(**es_kwargs)
```

יוצרים חיבור ל-Elasticsearch.
`**es_kwargs` = מפרקים את ה-dict לפרמטרים (Python trick מועיל).

```python
    with open(pcap_path, "rb") as f:
        reader = open_reader(f)
        for ts, raw in reader:
            doc      = parse_packet(ts, raw)
            protocol = doc["l4_protocol"]

            packets_total.labels(protocol=protocol).inc()
            bytes_total.labels(protocol=protocol).inc(doc["packet_length"])

            write_to_elastic(es, ELASTIC_INDEX, doc)
            processed += 1

            if processed % 1000 == 0:
                log.info("Processed %d packets so far …", processed)
```

**הלולאה המרכזית** — כאן קורה הכל:
1. קוראים כל packet מהקובץ
2. מנתחים אותו
3. מעדכנים את מונה הפרוטוקול ב-Prometheus
4. שולחים ל-Elasticsearch
5. כל 1000 packets — מדפיסים התקדמות

```python
    while True:
        time.sleep(60)
```

אחרי שסיימנו לעבד — **לא יוצאים**!
הישארות חיה מאפשרת ל-Prometheus להמשיך לשאול את ה-/metrics endpoint.
אם היינו יוצאים — הנתונים היו נעלמים לפני ש-Prometheus הספיק לאסוף אותם.

---

## 4. docker-compose.yml

```yaml
version: "3.8"
```
גרסת פורמט ה-docker-compose. 3.8 = גרסה בוגרת ויציבה.

```yaml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.0
```
`image` = איזה קונטיינר להוריד. כמו להגיד "תוריד Windows 11" — Elasticsearch 8.13.0.

```yaml
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
```

| הגדרה | מה היא עושה |
|-------|------------|
| `discovery.type=single-node` | ES בדרך כלל מחפש "חברים" ברשת. זה אומר לו "אתה לבד, בסדר" |
| `xpack.security.enabled=false` | מכבה סיסמאות — קל יותר לפיתוח מקומי |
| `ES_JAVA_OPTS=-Xms512m -Xmx512m` | מגביל זיכרון ל-512MB (בלי זה ES יכול לאכול 4GB+) |

```yaml
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:9200/_cluster/health | grep -qE '\"status\":\"(green|yellow)\"'"]
      interval: 10s
      retries: 12
```

**מה זה healthcheck?**
Docker בודק כל 10 שניות אם Elasticsearch באמת עובד (לא רק שהוא "חי" אלא שהוא מגיב).
Kibana לא יתחיל עד ש-ES יעבור את הbodycheck.

```yaml
  kibana:
    depends_on:
      elasticsearch:
        condition: service_healthy
```

`depends_on` = Kibana מחכה ש-ES יהיה healthy לפני שמתחיל.
בלי זה Kibana היה קורס כי ES עוד לא מוכן.

```yaml
volumes:
  es_data:
    driver: local
```

נתוני Elasticsearch נשמרים **מחוץ לקונטיינר**. בלי זה — כל `docker compose down` ומחק הכל.

---

## 5. Dockerfile

```dockerfile
FROM python:3.11-slim
```
"תתחיל מקונטיינר שכבר יש בו Python 3.11".
`slim` = גרסה קטנה יותר — רק מה שצריך. פחות GB = פחות בעיות אבטחה = deploy מהיר יותר.

```dockerfile
WORKDIR /app
```
כל הפקודות הבאות יתבצעו מתיקיית `/app` בתוך הקונטיינר.

```dockerfile
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
```
**למה להעתיק requirements לפני הקוד?**
Docker בונה שכבות (layers). אם requirements.txt לא השתנה — Docker משתמש ב-cache ולא מתקין מחדש. חוסך זמן build.

```dockerfile
COPY main.py .
EXPOSE 9100
ENTRYPOINT ["python", "main.py"]
```
`EXPOSE` = תיעוד שהקונטיינר משתמש בפורט 9100 (לא פותח אותו בפועל).
`ENTRYPOINT` = הפקודה שרצה כשמפעילים את הקונטיינר.

---

## 6. Helm Chart

**מה זה Helm?**
Kubernetes = מערכת להרצת קונטיינרים בסקייל.
Helm = "מנהל חבילות" של Kubernetes — כמו `pip install` אבל לשירותים שלמים.

**מבנה ה-Chart:**
```
helm/pcap-analyzer/
├── Chart.yaml       ← metadata (שם, גרסה)
├── values.yaml      ← ברירות מחדל שניתן לשנות
└── templates/       ← קבצי Kubernetes אמיתיים עם משתנים
    ├── deployment.yaml
    ├── configmap.yaml
    ├── secret.yaml
    └── service.yaml
```

### values.yaml
```yaml
elasticsearch:
  url: "http://elasticsearch:9200"
  index: "pcap-packets"
metrics:
  port: 9100
```
כל ערך כאן ניתן לדרוס בעת ה-install:
```bash
helm install pcap-analyzer ./helm/pcap-analyzer \
  --set elasticsearch.url=http://my-prod-es:9200
```

### deployment.yaml
```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "9100"
  prometheus.io/path: "/metrics"
```
**Prometheus annotations** = תגיות שאומרות ל-Prometheus "תאסוף מטריקות מה-Pod הזה".
Prometheus סורק את כל ה-Pods ואוסף מכל מי שיש לו את ה-annotation הזה.

### configmap.yaml vs secret.yaml
| ConfigMap | Secret |
|-----------|--------|
| ערכים רגילים (URL, פורט) | ערכים רגישים (סיסמאות) |
| נשמר בטקסט פשוט | נשמר מוצפן ב-Kubernetes |
| `kubectl get configmap` — כולם רואים | `kubectl get secret` — מוגבל |

---

## 7. tests/test_parser.py

```python
def _build_ethernet(payload: bytes, eth_type: int = 0x0800) -> bytes:
    src_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    dst_mac = b"\x11\x22\x33\x44\x55\x66"
    return dst_mac + src_mac + struct.pack("!H", eth_type) + payload
```

בונים "מכשיר" שיוצר packets מזויפים לצורך בדיקה.
`struct.pack("!H", eth_type)` = הופך מספר ל-bytes בפורמט רשת (`!` = big-endian).

```python
class TestParsePacketTCP:
    def test_protocol(self):
        assert self._make()["l4_protocol"] == "tcp"
```

**מה זה assert?**
"תוודא שהתנאי הזה נכון. אם לא — הבדיקה נכשלת."

**למה בדיקות חשובות?**
- בדיקות = **רשת ביטחון**. אם שינית משהו בקוד ושברת פונקציה — הבדיקה תתפוס את זה לפני שהקוד עולה לפרודקשן.
- ב-CI/CD (GitHub Actions וכו׳) הבדיקות רצות אוטומטית בכל push.

---

## 8. שאלות ראיון

### "ספר לי על הפרויקט"
> "בניתי שירות Python שקורא קבצי PCAP — הקלטות רשת — ועושה שני דברים: ראשית, הוא מאנדקס כל packet ב-Elasticsearch כדי שנוכל לחפש ולנתח תעבורת רשת. שנית, הוא חושף מטריקות ב-Prometheus על פרוטוקולים, נפח תעבורה, ושגיאות כתיבה — מה שמאפשר ניטור בזמן אמת ואלרטינג."

---

### "למה בחרת dpkt ולא Scapy?"
> "dpkt קל, מהיר, ובלי dependencies חיצוניים. Scapy עוצמתי יותר אבל כבד — לפרויקט כזה dpkt מספיק ומוריד את גודל ה-Docker image."

---

### "מה זה observability ולמה זה חשוב?"
> "Observability = היכולת להבין מה קורה בתוך המערכת על סמך הפלט שלה. שלושת העמודות הן:
> - **Logs** — מה קרה (אירועים ספציפיים)
> - **Metrics** — כמה פעמים / כמה מהר (מספרים בזמן)
> - **Traces** — איך בקשה עברה דרך המערכת
>
> בלי observability אתה עיוור. כשמשהו נשבר בשעה 3 לפנות בוקר, זה מה שמאפשר לך להבין למה."

---

### "איך הייתה מטפל בכשל של Elasticsearch?"
> "הוספתי retry עם exponential back-off — 3 ניסיונות עם המתנה של 1, 2, 4 שניות. בנוסף, אני מונה כשלים ב-Prometheus כדי שנוכל להגדיר alert: 'אם יש יותר מ-X כשלים בדקה — שלח התראה'."

---

### "איך היית משפר את זה לפרודקשן?"
> 1. **Bulk indexing** — במקום לשלוח כל document בנפרד, לאסוף 500 ולשלוח יחד (מהיר פי 10)
> 2. **Structured logging** — לוגים ב-JSON כדי ש-Kibana יוכל לנתח אותם
> 3. **ILM Policy ב-Elasticsearch** — מחיקה אוטומטית של נתונים ישנים
> 4. **Streaming** — לא לטעון את כל הPCAP לזיכרון בבת אחת (24MB בסדר, אבל 10GB לא)
> 5. **Secret management** — סיסמאות מ-Vault ולא ממשתני סביבה ישירים

---

### "מה זה Helm ולמה השתמשת בו?"
> "Helm הוא package manager ל-Kubernetes. במקום לנהל קבצי YAML בנפרד לכל סביבה, Helm מאפשר לכם להגדיר template אחד עם values שניתן לדרוס לפי סביבה. מה שהיה לוקח 5 `kubectl apply` פקודות הופך ל-`helm install` אחד."

---

### "מה ה-PCAP שניתחת מכיל?"
> "ה-PCAP הוא pcapng — פורמט הקלטה מודרני. מתוך 30,000 הpackets הראשונים:
> - ~36% TCP — כנראה HTTP/HTTPS ואפליקציות
> - ~36% UDP — DNS ו-NTP בעיקר
> - ~1% ICMP — ping/traceroute
> - ~28% אחר — ARP ועוד
>
> הרבות ה-ARP אומרת שזה LAN (רשת מקומית), לא traffic חיצוני."

---

*בהצלחה בראיון! 🎯*
