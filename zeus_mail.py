import sys, imaplib, email, os, json, re, shutil, threading, time, subprocess, queue
from collections import deque
from email.header import decode_header
from datetime import datetime
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer, QMutex
from PyQt5.QtGui import *

# ── Auto-install missing dependencies ────────────────────────────────────────
def _auto_install(pkg, import_name=None):
    try:
        __import__(import_name or pkg)
    except ImportError:
        print(f"Instalando {pkg}...")
        subprocess.run([sys.executable, "-m", "pip", "install", pkg, "--quiet"], check=False)

def _deferred_install():
    _auto_install("pypdf")
    _auto_install("reportlab")
    _auto_install("pillow", "PIL")
    _auto_install("pdfplumber")
    _auto_install("scikit-learn", "sklearn")
threading.Thread(target=_deferred_install, daemon=True).start()

# Import ZEUS Engine
try:
    from zeus_engine import (ZeusDB, BoletoClassifier, PriorityEmailQueue,
                              IMAPIdleWorker, MultiProcessCoordinator)
    _ZEUS_ENGINE = True
except ImportError:
    _ZEUS_ENGINE = False

# Import ZEUS Worker (async process mode)
try:
    from zeus_worker import WorkerClient, EmailBuffer, fast_detect_boleto
    _ZEUS_WORKER = True
except ImportError:
    _ZEUS_WORKER = False

# Import ZEUS Security
try:
    from zeus_security import (ZeusAuth, HardwareKey, SecureConfig,
                               SecureString, AntiTamper, get_auth)
    _ZEUS_SECURITY = True
except ImportError:
    _ZEUS_SECURITY = False
    def get_auth(): return None

# Global DB instance
_DB = ZeusDB() if _ZEUS_ENGINE else None

# ── IMAP server auto-detect ─────────────────────────────────────────────────
IMAP_MAP = {
    "gmail.com": "imap.gmail.com",
    "googlemail.com": "imap.gmail.com",
    "outlook.com": "imap.outlook.com",
    "hotmail.com": "imap.outlook.com",
    "live.com": "imap.outlook.com",
    "msn.com": "imap.outlook.com",
    "yahoo.com": "imap.mail.yahoo.com",
    "yahoo.com.br": "imap.mail.yahoo.com.br",
    "terra.com.br": "imap.terra.com.br",
    "uol.com.br": "imap.uol.com.br",
    "bol.com.br": "imap.bol.com.br",
    "ig.com.br": "imap.ig.com.br",
    "globo.com": "imap.globo.com",
    "r7.com": "imap.r7.com",
    "icloud.com": "imap.mail.me.com",
    "me.com": "imap.mail.me.com",
    "protonmail.com": "imap.protonmail.com",
    "proton.me": "imap.protonmail.com",
    "locaweb.com.br": "imap.locaweb.com.br",
    "kinghost.com.br": "mail.kinghost.com.br",
    "hostgator.com.br": "mail.hostgator.com.br",
    "umbler.com": "imap.umbler.com",
    "zoho.com": "imap.zoho.com",
}

def get_smtp_server(email_addr, cfg):
    """Auto-detect SMTP server for an email address."""
    # Custom override
    if cfg.get("custom_smtp_host"):
        return cfg["custom_smtp_host"], int(cfg.get("custom_smtp_port", 587))
    domain = email_addr.split("@")[-1].lower()
    smtp_map = cfg.get("smtp_servers", {})
    if domain in smtp_map:
        s = smtp_map[domain]
        return s["host"], int(s.get("port", 587))
    # Generic fallback
    return "smtp." + domain, 587

def send_via_smtp(acc_info, from_name, from_email, to_addr, subject, body_text, body_html, attachments, cfg, delete_uid=None, delete_folder=None, raw_original=None):
    """
    Send email via SMTP preserving original content.
    If raw_original is provided, uses it as base (preserves ALL attachments).
    Only patches From/To/Subject headers with new values.
    """
    import smtplib, email as _em

    smtp_host, smtp_port = get_smtp_server(acc_info["email"], cfg)
    login_email = acc_info["email"]
    password    = acc_info["password"]

    # Build message from raw original if available (preserves attachments perfectly)
    if raw_original:
        raw_bytes_in = raw_original if isinstance(raw_original, bytes) else raw_original.encode("utf-8","replace")
        msg = _em.message_from_bytes(raw_bytes_in)
        # Patch only the headers the user changed
        for h in ["From","To","Subject","Cc","Bcc"]:
            if h in msg: del msg[h]
        msg["From"]    = f"{from_name} <{from_email}>" if from_name else from_email
        msg["To"]      = to_addr
        msg["Subject"] = subject
        raw_bytes = msg.as_bytes()
    else:
        # Fallback: build from scratch (no original available)
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.base import MIMEBase
        from email import encoders as enc

        msg = MIMEMultipart("mixed") if attachments else MIMEMultipart("alternative")
        msg["From"]    = f"{from_name} <{from_email}>" if from_name else from_email
        msg["To"]      = to_addr
        msg["Subject"] = subject

        if body_text: msg.attach(MIMEText(body_text, "plain", "utf-8"))
        if body_html: msg.attach(MIMEText(body_html, "html", "utf-8"))

        for att in attachments:
            path = att.get("path",""); name = att.get("name","")
            part_obj = att.get("part")
            if part_obj:
                # Use original part object if available
                msg.attach(part_obj)
            elif path and os.path.exists(path) and name:
                with open(path,"rb") as f:
                    part = MIMEBase("application","octet-stream")
                    part.set_payload(f.read())
                    enc.encode_base64(part)
                    part.add_header("Content-Disposition", f'attachment; filename="{name}"')
                    msg.attach(part)

        raw_bytes = msg.as_bytes()

    # Try multiple SMTP ports/protocols — auto-detect like DeepMail
    SMTP_COMBOS = [
        ("STARTTLS", smtp_port),
        ("STARTTLS", 587),
        ("SSL",      465),
        ("STARTTLS", 25),
        ("STARTTLS", 2587),
        ("PLAIN",    25),
    ]
    sent = False; last_err = None
    for smtp_proto, smtp_try_port in SMTP_COMBOS:
        try:
            if smtp_proto == "SSL":
                import ssl as _ssl2
                ctx2 = _ssl2.create_default_context()
                ctx2.check_hostname = False; ctx2.verify_mode = _ssl2.CERT_NONE
                with smtplib.SMTP_SSL(smtp_host, smtp_try_port, timeout=12, context=ctx2) as srv:
                    srv.ehlo(); srv.login(login_email, password)
                    srv.sendmail(from_email, [to_addr], raw_bytes)
                    sent = True; break
            else:
                with smtplib.SMTP(smtp_host, smtp_try_port, timeout=12) as srv:
                    srv.ehlo()
                    try: srv.starttls()
                    except: pass
                    srv.ehlo(); srv.login(login_email, password)
                    srv.sendmail(from_email, [to_addr], raw_bytes)
                    sent = True; break
        except Exception as _e:
            last_err = _e
            if any(x in str(_e) for x in ["535","534","Authentication","credentials"]):
                raise
            continue
    if not sent: raise Exception(f"SMTP falhou: {last_err}")


    # After sending: delete from source INBOX so it doesn't pile up
    if delete_uid and delete_folder:
        try:
            imap = connect_imap(acc_info)
            imap.select(delete_folder)
            uid_b = delete_uid.encode() if isinstance(delete_uid, str) else delete_uid
            imap.store(uid_b, "+FLAGS", "\\Deleted")
            imap.expunge()
            imap.logout()
        except: pass

    return raw_bytes

def detect_imap(email_addr):
    """Auto-detect IMAP server by testing multiple servers and ports."""
    domain = email_addr.split("@")[-1].lower()
    # Known servers — start here
    if domain in IMAP_MAP:
        return IMAP_MAP[domain], 993
    # Test common prefixes with multiple ports
    for prefix in ["imap.", "mail.", "imap.mail.", "webmail."]:
        server = prefix + domain
        for port in [993, 143, 585]:
            try:
                import ssl as _ssl
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                conn = imaplib.IMAP4_SSL(server, port, ssl_context=ctx)
                conn.logout()
                return server, port
            except: pass
    return "imap." + domain, 993

def parse_accounts_file(filepath):
    accounts = []
    errors = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith("#"): continue
        parts = line.split(",", 1)
        if len(parts) < 2:
            errors.append(f"Linha {i+1}: formato inválido — '{line}'")
            continue
        email_addr = parts[0].strip()
        password = parts[1].strip()
        if "@" not in email_addr:
            errors.append(f"Linha {i+1}: email inválido — '{email_addr}'")
            continue
        server, port = detect_imap(email_addr)
        accounts.append({
            "name": email_addr.split("@")[0],
            "email": email_addr,
            "password": password,
            "imap_server": server,
            "imap_port": str(port),
        })
    return accounts, errors

# ── Style ───────────────────────────────────────────────────────────────────
STYLE = """
* { font-family: 'Helvetica Neue', Arial, sans-serif; }
QMainWindow, QDialog, QWidget { background: #141414; color: #e5e5e5; }
#sidebar { background: #000000; border-right: 1px solid #2a2a2a; }
#sidebar QPushButton { background: transparent; color: #a3a3a3; border: none; text-align: left; padding: 14px 20px; font-size: 13px; border-radius: 0; font-weight: 500; }
#sidebar QPushButton:hover { background: #1a1a1a; color: #ffffff; }
#sidebar QPushButton:checked { background: #e50914; color: #ffffff; border-left: 3px solid #ff0a16; font-weight: 700; }
#topbar { background: #000000; border-bottom: 1px solid #2a2a2a; min-height: 52px; }
#search_box { background: #2a2a2a; border: 1px solid #404040; color: #e5e5e5; border-radius: 4px; padding: 8px 14px; font-size: 13px; min-width: 260px; }
#search_box:focus { border-color: #e50914; }
QPushButton#btn_red { background: #e50914; color: #fff; border: none; border-radius: 4px; padding: 9px 20px; font-size: 13px; font-weight: 700; }
QPushButton#btn_red:hover { background: #f40612; }
QPushButton#btn_ghost { background: rgba(109,109,110,0.7); color: #fff; border: none; border-radius: 4px; padding: 9px 20px; font-size: 13px; font-weight: 600; }
QPushButton#btn_ghost:hover { background: rgba(109,109,110,0.9); }
QPushButton#btn_icon { background: transparent; color: #e5e5e5; border: 1px solid #595959; border-radius: 50%; min-width: 30px; max-width: 30px; min-height: 30px; max-height: 30px; font-size: 13px; }
QPushButton#btn_icon:hover { border-color: #e5e5e5; background: rgba(255,255,255,0.1); }
QPushButton#btn_green { background: #2ecc40; color: #000; border: none; border-radius: 4px; padding: 9px 20px; font-size: 13px; font-weight: 700; }
QPushButton#btn_green:hover { background: #27ae60; }
QTableWidget { background: #141414; gridline-color: #1f1f1f; color: #e5e5e5; border: none; selection-background-color: #2a2a2a; font-size: 13px; }
QTableWidget::item { padding: 10px 8px; border-bottom: 1px solid #1f1f1f; }
QTableWidget::item:selected { background: #2a2a2a; color: #fff; border-left: 2px solid #e50914; }
QHeaderView::section { background: #000; color: #a3a3a3; padding: 10px 8px; border: none; border-bottom: 2px solid #2a2a2a; font-size: 11px; font-weight: 700; letter-spacing: 1px; }
QLineEdit, QTextEdit, QComboBox, QSpinBox { background: #2a2a2a; color: #e5e5e5; border: 1px solid #404040; border-radius: 4px; padding: 8px 12px; font-size: 13px; }
QLineEdit:focus, QTextEdit:focus { border-color: #e50914; }
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView { background: #2a2a2a; color: #e5e5e5; border: 1px solid #404040; }
QTabWidget::pane { border: none; background: #141414; }
QTabBar::tab { background: transparent; color: #a3a3a3; padding: 14px 20px; font-size: 13px; font-weight: 600; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #fff; border-bottom: 2px solid #e50914; }
QGroupBox { border: 1px solid #2a2a2a; border-radius: 6px; margin-top: 14px; padding-top: 14px; color: #a3a3a3; font-size: 11px; font-weight: 700; letter-spacing: 1px; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #a3a3a3; }
QScrollBar:vertical { background: #141414; width: 6px; border: none; }
QScrollBar::handle:vertical { background: #404040; border-radius: 3px; min-height: 30px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QStatusBar { background: #000; color: #595959; font-size: 11px; border-top: 1px solid #2a2a2a; }
QMenu { background: #1a1a1a; color: #e5e5e5; border: 1px solid #2a2a2a; border-radius: 4px; padding: 4px; }
QMenu::item { padding: 9px 16px; border-radius: 3px; }
QMenu::item:selected { background: #e50914; color: #fff; }
QMenu::separator { background: #2a2a2a; height: 1px; margin: 4px 0; }
QListWidget { background: #1a1a1a; border: 1px solid #2a2a2a; color: #e5e5e5; border-radius: 4px; }
QListWidget::item { padding: 10px 12px; border-bottom: 1px solid #2a2a2a; }
QListWidget::item:selected { background: #e50914; color: #fff; }
QCheckBox { color: #e5e5e5; font-size: 13px; spacing: 8px; }
QCheckBox::indicator { width: 18px; height: 18px; border-radius: 3px; border: 2px solid #595959; background: #2a2a2a; }
QCheckBox::indicator:checked { background: #e50914; border-color: #e50914; }
QProgressBar { background: #2a2a2a; border-radius: 2px; border: none; color: transparent; max-height: 3px; }
QProgressBar::chunk { background: #e50914; border-radius: 2px; }
QSplitter::handle { background: #2a2a2a; width: 1px; }
"""

CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".zeus_config.json")
EMAILS_FILE     = os.path.join(os.path.expanduser("~"), ".zeus_emails.json")
SEEN_HASH_FILE  = os.path.join(os.path.expanduser("~"), ".zeus_seen_hashes.json")

def load_seen_hashes():
    try:
        with open(SEEN_HASH_FILE,"r") as f: return set(json.load(f))
    except: return set()

def save_seen_hashes(hashes):
    try:
        with open(SEEN_HASH_FILE,"w") as f: json.dump(list(hashes), f)
    except: pass

def email_hash(em):
    """Stable hash for an email — based on account+subject+date+sender."""
    import hashlib
    key = f"{em.get('account','')}{em.get('subject','')}{em.get('date','')}{em.get('sender','')}"
    return hashlib.md5(key.encode('utf-8','replace')).hexdigest()

def load_emails():
    """Load persisted emails — JSON is primary (never loses data), DB is secondary."""
    # JSON is primary source — always up to date
    if os.path.exists(EMAILS_FILE):
        try:
            with open(EMAILS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            for em in data:
                for att in em.get("attachments", []):
                    att.pop("part", None)
            if data:
                return data
        except: pass
    # DB fallback
    if _ZEUS_ENGINE and _DB:
        try:
            return _DB.load_emails(limit=5000)
        except: pass
    return []

def save_emails(emails):
    """Save emails — always saves ALL to JSON as primary storage."""
    # Always save to JSON first (reliable, never loses data)
    serializable = []
    for em in emails:
        em_copy = {k: v for k, v in em.items()
                   if k not in ("raw","part","_checked")}
        em_copy["attachments"] = [
            {k2: v2 for k2, v2 in att.items() if k2 != "part"}
            for att in em.get("attachments", [])
        ]
        serializable.append(em_copy)
    try:
        with open(EMAILS_FILE, "w", encoding="utf-8") as f:
            json.dump(serializable, f, ensure_ascii=False, indent=2)
    except: pass

    # Also save to DB (secondary — for search/indexing)
    if _ZEUS_ENGINE and _DB:
        try:
            for em in emails:
                h = email_hash(em)
                em_copy = dict(em); em_copy["_hash"] = h
                _DB.insert_email(em_copy)
            for em in emails:
                if em.get("opened"):
                    _DB.mark_opened(em.get("uid",""), em.get("account",""))
        except: pass

def load_config():
    if _ZEUS_SECURITY:
        try:
            from pathlib import Path as _Path
            data = SecureConfig.load(_Path(CONFIG_FILE))
            if data: return data
        except: pass
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                raw = f.read()
                if raw.startswith("ZEUS_ENC_V1:"): pass
                else: return json.loads(raw)
        except: pass
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "accounts": [],
        "download_path": os.path.join(os.path.expanduser("~"), "Downloads", "Zeus"),
        "extensions": [".pdf", ".xml", ".html", ".jpg", ".png", ".zip", ".xls", ".xlsx"],
        "folders": ["INBOX"],
        "only_unread": False,
        "only_attachment": False,
        "search_boleto": True,
        "only_boleto": True,
        "min_value": 500.0,
        "max_days_old": 4,
        "after_capture": "move",  # "move", "delete", "nothing"
        "processed_folder": "Processados",
        "max_emails": 100,
        "cycle_interval": 60,
        "max_threads": 5,
        "monitor_accounts": 0,
        "emails_per_read": 5,
        "alternate_accounts": True,
        "smtp_servers": {
            "terra.com.br":    {"host": "smtp.terra.com.br",    "port": 587},
            "uol.com.br":      {"host": "smtp.uol.com.br",      "port": 587},
            "gmail.com":       {"host": "smtp.gmail.com",       "port": 587},
            "outlook.com":     {"host": "smtp-mail.outlook.com","port": 587},
            "hotmail.com":     {"host": "smtp-mail.outlook.com","port": 587},
            "yahoo.com":       {"host": "smtp.mail.yahoo.com",  "port": 587},
            "yahoo.com.br":    {"host": "smtp.mail.yahoo.com",  "port": 587},
            "bol.com.br":      {"host": "smtp.bol.com.br",      "port": 587},
            "ig.com.br":       {"host": "smtp.ig.com.br",       "port": 587},
            "globo.com":       {"host": "smtp.globo.com",       "port": 587},
        },
        "keywords_include": [
            "duplicata", "duplicatas", "comunicado", "2 via", "2via",
            "segunda via boleto", "contas a pagar", "conta a pagar",
            "aluguel", "alugueis", "boleto", "fatura", "cobrança",
            "pagamento", "vencimento", "nf-e", "nota fiscal",
            "financeiro", "titulo", "titulo a pagar", "aviso de cobrança",
            "boleto digital", "boleto bancario", "recibo", "carnê"
        ],
        "keywords_exclude": [
            "spam", "promoção", "oferta", "desconto", "newsletter",
            "marketing", "publicidade", "unsubscribe"
        ],
    }

def save_config(cfg):
    if _ZEUS_SECURITY:
        try:
            from pathlib import Path as _Path
            SecureConfig.save(cfg, _Path(CONFIG_FILE))
            return
        except: pass
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

def decode_str(s):
    if not s: return ""
    parts = decode_header(s)
    result = []
    for part, enc in parts:
        if isinstance(part, bytes):
            try: result.append(part.decode(enc or "utf-8", errors="replace"))
            except: result.append(part.decode("latin-1", errors="replace"))
        else: result.append(str(part))
    return "".join(result)

# IMAP port/protocol combinations to try in order
IMAP_COMBOS = [
    ("SSL",     993),   # Standard IMAP SSL
    ("SSL",     143),   # IMAP SSL alternate
    ("STARTTLS",143),   # IMAP with STARTTLS
    ("STARTTLS",993),   # STARTTLS on SSL port
    ("SSL",     585),   # Legacy SSL
    ("PLAIN",   143),   # Plain (last resort)
    ("PLAIN",   993),
]

def connect_imap(acc):
    """
    Try multiple port/protocol combinations until one works.
    Caches the working combo in acc dict for future calls.
    """
    server = acc["imap_server"]
    email_addr = acc["email"]
    password = acc["password"]

    # Use cached working combo if available
    if acc.get("_working_port"):
        proto = acc.get("_working_proto","SSL")
        port  = acc["_working_port"]
        return _imap_connect_one(server, email_addr, password, proto, port)

    # Explicit port configured by user — try it first with all protos
    configured_port = int(acc.get("imap_port", 0))
    combos = list(IMAP_COMBOS)
    if configured_port:
        # Prioritize configured port
        prio = [(p, configured_port) for p, _ in combos]
        combos = prio + [c for c in combos if c[1] != configured_port]

    last_err = None
    for proto, port in combos:
        try:
            imap = _imap_connect_one(server, email_addr, password, proto, port)
            # Cache working combo
            acc["_working_proto"] = proto
            acc["_working_port"]  = port
            return imap
        except Exception as e:
            last_err = e
            # Auth failure = stop trying other ports immediately
            err_str = str(e)
            if any(x in err_str for x in ["AUTHENTICATIONFAILED","[AUTH]","Invalid credentials","authentication failed"]):
                raise
            continue

    raise Exception(f"Nenhuma conexão funcionou com {server}: {last_err}")


def _imap_connect_one(server, email_addr, password, proto, port):
    """Attempt one IMAP connection with specific protocol/port."""
    import ssl as _ssl
    timeout = 10

    if proto == "SSL":
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        imap = imaplib.IMAP4_SSL(server, port, ssl_context=ctx)
    elif proto == "STARTTLS":
        imap = imaplib.IMAP4(server, port)
        imap.socket().settimeout(timeout)
        try:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            imap.starttls(ssl_context=ctx)
        except: pass
    else:  # PLAIN
        imap = imaplib.IMAP4(server, port)

    imap.socket().settimeout(timeout)
    imap.login(email_addr, password)
    return imap

def extract_boleto(text):
    for p in [r'\d{5}\.\d{5}\s\d{5}\.\d{6}\s\d{5}\.\d{6}\s\d\s\d{14}', r'\d{47,48}']:
        m = re.search(p, text)
        if m: return m.group()
    return ""

def extract_value(text):
    m = re.search(r'R\$\s*([\d.,]+)', text)
    return "R$ " + m.group(1) if m else ""

def parse_value_float(value_str):
    """Convert 'R$ 1.234,56' to float 1234.56"""
    try:
        v = re.sub(r'[^\d,.]', '', value_str)
        # Brazilian format: 1.234,56
        if ',' in v and '.' in v:
            v = v.replace('.', '').replace(',', '.')
        elif ',' in v:
            v = v.replace(',', '.')
        return float(v)
    except:
        return 0.0

def matches_keywords(subject, body, keywords_include, keywords_exclude):
    """Check if email matches keyword filters."""
    text = (subject + " " + body).lower()
    # If include list not empty, at least one must match
    if keywords_include:
        if not any(kw.lower() in text for kw in keywords_include if kw.strip()):
            return False
    # If exclude list not empty, none must match
    if keywords_exclude:
        if any(kw.lower() in text for kw in keywords_exclude if kw.strip()):
            return False
    return True

def parse_email_date(date_str):
    """Parse email date string to datetime."""
    from email.utils import parsedate_to_datetime
    try:
        return parsedate_to_datetime(date_str).replace(tzinfo=None)
    except:
        try:
            # fallback formats
            for fmt in ["%d/%m/%Y %H:%M:%S", "%d/%m/%Y", "%Y-%m-%d"]:
                try: return datetime.strptime(date_str[:len(fmt)], fmt)
                except: pass
        except: pass
    return datetime.now()

def extract_due(text):
    m = re.search(r'vencimento[:\s]+(\d{2}/\d{2}/\d{4})', text, re.IGNORECASE)
    return m.group(1) if m else ""

# ── Import File Dialog ───────────────────────────────────────────────────────
class ImportFileDialog(QDialog):
    def __init__(self, accounts, errors, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Importar Contas")
        self.setMinimumSize(780, 480)
        self.accounts = accounts
        self.selected = []
        self._build(errors)

    def _build(self, errors):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel(f"⚡ {len(self.accounts)} CONTAS ENCONTRADAS")
        title.setStyleSheet("color: #ffffff; font-size: 20px; font-weight: 900;")
        layout.addWidget(title)

        if errors:
            err_box = QLabel(f"⚠️  {len(errors)} linha(s) ignorada(s)")
            err_box.setStyleSheet("color: #e5a010; font-size: 12px; background: #1a1500; border: 1px solid #e5a010; border-radius: 4px; padding: 6px 12px;")
            layout.addWidget(err_box)

        # IMAP detection preview
        sub = QLabel("SERVIDOR IMAP DETECTADO AUTOMATICAMENTE:")
        sub.setStyleSheet("color: #595959; font-size: 10px; font-weight: 700; letter-spacing: 1px;")
        layout.addWidget(sub)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["✓", "EMAIL", "SERVIDOR IMAP", "STATUS"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.setRowHeight(0, 38)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)

        self.checkboxes = []
        for i, acc in enumerate(self.accounts):
            self.table.insertRow(i)
            self.table.setRowHeight(i, 38)
            chk = QCheckBox(); chk.setChecked(True)
            chk_widget = QWidget()
            chk_layout = QHBoxLayout(chk_widget)
            chk_layout.setContentsMargins(8,0,8,0)
            chk_layout.addWidget(chk)
            self.table.setCellWidget(i, 0, chk_widget)
            self.table.setItem(i, 1, QTableWidgetItem(acc["email"]))
            self.table.setItem(i, 2, QTableWidgetItem(acc["imap_server"]))
            status_item = QTableWidgetItem("Aguardando...")
            status_item.setForeground(QColor("#595959"))
            self.table.setItem(i, 3, status_item)
            self.checkboxes.append(chk)

        layout.addWidget(self.table)

        btns = QHBoxLayout()
        btns.setSpacing(8)
        btn_all = QPushButton("SELECIONAR TUDO"); btn_all.setObjectName("btn_ghost")
        btn_all.setMinimumWidth(140)
        btn_all.clicked.connect(lambda: [c.setChecked(True) for c in self.checkboxes])
        btn_none = QPushButton("DESMARCAR TUDO"); btn_none.setObjectName("btn_ghost")
        btn_none.setMinimumWidth(140)
        btn_none.clicked.connect(lambda: [c.setChecked(False) for c in self.checkboxes])
        self._btn_test = QPushButton("🔌  TESTAR CONEXÕES"); self._btn_test.setObjectName("btn_ghost")
        self._btn_test.setMinimumWidth(150)
        self._btn_test.clicked.connect(self._test_all)
        btn_import = QPushButton("⚡  IMPORTAR E MONITORAR"); btn_import.setObjectName("btn_red")
        btn_import.setMinimumWidth(190)
        btn_import.clicked.connect(self._do_import)
        btn_cancel = QPushButton("CANCELAR"); btn_cancel.setObjectName("btn_ghost")
        btn_cancel.setMinimumWidth(90)
        btn_cancel.clicked.connect(self.reject)
        for b in [btn_all, btn_none, self._btn_test]: btns.addWidget(b)
        btns.addStretch()
        btns.addWidget(btn_cancel)
        btns.addWidget(btn_import)
        layout.addLayout(btns)

    def _test_all(self):
        self._btn_test.setEnabled(False)
        self._btn_test.setText("Testando...")

        n = len(self.accounts)
        if n == 0:
            self._btn_test.setEnabled(True)
            self._btn_test.setText("🔌  TESTAR CONEXÕES")
            return

        lock = threading.Lock()
        results = {}  # {i: (ok, msg)}

        def _test_one(i, acc):
            try:
                imap = connect_imap(acc); imap.logout()
                with lock:
                    results[i] = (True, "✅ OK")
            except Exception as e:
                with lock:
                    results[i] = (False, f"❌ {str(e)[:30]}")

        threads = [threading.Thread(target=_test_one, args=(i, acc), daemon=True)
                   for i, acc in enumerate(self.accounts)]
        for t in threads:
            t.start()

        def _poll():
            with lock:
                snapshot = dict(results)
            for i, (ok, msg) in snapshot.items():
                item = self.table.item(i, 3)
                if item:
                    item.setText(msg)
                    item.setForeground(QColor("#2ecc40" if ok else "#e50914"))
            if any(t.is_alive() for t in threads):
                QTimer.singleShot(200, _poll)
            else:
                self._btn_test.setEnabled(True)
                self._btn_test.setText("🔌  TESTAR CONEXÕES")

        QTimer.singleShot(200, _poll)

    def _do_import(self):
        self.selected = [acc for i, acc in enumerate(self.accounts) if self.checkboxes[i].isChecked()]
        self.accept()

# ── Persistent IMAP Monitor ──────────────────────────────────────────────────
class AccountMonitor(QThread):
    """Keeps a persistent IMAP connection for one account and polls for new emails."""
    new_email = pyqtSignal(dict)
    status_update = pyqtSignal(str, str)  # email, status

    def __init__(self, acc, cfg):
        super().__init__()
        self.acc = acc
        self.cfg = cfg
        self.running = True
        self.imap = None
        self.seen_uids = set()

    def stop(self):
        self.running = False
        if self.imap:
            try: self.imap.logout()
            except: pass

    def run(self):
        interval = int(self.cfg.get("cycle_interval", 60))
        folders = self.cfg.get("folders", ["INBOX"])
        extensions = self.cfg.get("extensions", [])
        only_unread = self.cfg.get("only_unread", False)
        only_att = self.cfg.get("only_attachment", False)
        search_boleto = self.cfg.get("search_boleto", True)
        only_boleto = self.cfg.get("only_boleto", True)
        min_value = float(self.cfg.get("min_value", 0.0))
        max_days_old = int(self.cfg.get("max_days_old", 4))
        after_capture = self.cfg.get("after_capture", "nothing")
        processed_folder = self.cfg.get("processed_folder", "Processados")
        max_emails = int(self.cfg.get("max_emails", 100))
        email_addr = self.acc["email"]

        while self.running:
            try:
                self.status_update.emit(email_addr, "Conectando...")
                self.imap = connect_imap(self.acc)
                self.status_update.emit(email_addr, "✅ Conectado")

                while self.running:
                    for folder in folders:
                        if not self.running: break
                        try:
                            self.imap.select(folder)
                            criteria = "UNSEEN" if only_unread else "ALL"
                            _, msgs = self.imap.search(None, criteria)
                            ids = msgs[0].split()[-max_emails:]
                            new_ids = [i for i in ids if i.decode() not in self.seen_uids]

                            for num in reversed(new_ids):
                                if not self.running: break
                                try:
                                    _, data = self.imap.fetch(num, "(RFC822)")
                                    raw = data[0][1]
                                    msg = email.message_from_bytes(raw)
                                    subject = decode_str(msg.get("Subject", ""))
                                    sender = decode_str(msg.get("From", ""))
                                    to = decode_str(msg.get("To", ""))
                                    date_str = msg.get("Date", "")
                                    body_text = ""
                                    body_html = ""
                                    attachments = []

                                    for part in msg.walk():
                                        ct = part.get_content_type()
                                        cd = str(part.get("Content-Disposition", ""))
                                        if ct == "text/plain" and "attachment" not in cd:
                                            try: body_text += part.get_payload(decode=True).decode("utf-8", errors="replace")
                                            except: pass
                                        elif ct == "text/html" and "attachment" not in cd:
                                            try: body_html += part.get_payload(decode=True).decode("utf-8", errors="replace")
                                            except: pass
                                        fname = decode_str(part.get_filename() or "")
                                        if fname:
                                            ext = os.path.splitext(fname)[1].lower()
                                            if not extensions or ext in extensions:
                                                attachments.append({"name": fname, "part": part, "path": ""})

                                    if only_att and not attachments:
                                        self.seen_uids.add(num.decode())
                                        continue

                                    # ── Age filter: skip emails older than max_days_old ──
                                    try:
                                        em_dt = parse_email_date(date_str)
                                        age_days = (datetime.now() - em_dt).days
                                        if age_days > max_days_old:
                                            self.seen_uids.add(num.decode())
                                            continue
                                    except: pass

                                    boleto_code = extract_boleto(body_text) if search_boleto else ""
                                    # Also search HTML for boleto
                                    if not boleto_code and body_html:
                                        import html as html_mod
                                        clean_html = re.sub(r'<[^>]+>', ' ', body_html)
                                        boleto_code = extract_boleto(html_mod.unescape(clean_html))

                                    value = extract_value(body_text) or extract_value(body_html)
                                    due_date = extract_due(body_text) or extract_due(body_html)

                                    # ── Keyword filter ──
                                    kw_inc = self.cfg.get("keywords_include",[])
                                    kw_exc = self.cfg.get("keywords_exclude",[])
                                    if (kw_inc or kw_exc) and not matches_keywords(subject, body_text, kw_inc, kw_exc):
                                        self.seen_uids.add(num.decode())
                                        continue

                                    # ── Boleto-only filter ──
                                    if only_boleto and not boleto_code:
                                        subj_match = any(kw.lower() in subject.lower() for kw in kw_inc if kw.strip()) if kw_inc else False
                                        if not subj_match:
                                            self.seen_uids.add(num.decode())
                                            continue

                                    # ── Minimum value filter ──
                                    if min_value > 0 and value:
                                        val_float = parse_value_float(value)
                                        if val_float > 0 and val_float < min_value:
                                            self.seen_uids.add(num.decode())
                                            continue

                                    em_data = {
                                        "uid": num.decode(), "folder": folder,
                                        "subject": subject, "sender": sender,
                                        "to": to, "date": date_str,
                                        "state": "NAO LIDO",
                                        "value": value, "due_date": due_date,
                                        "attachments": attachments,
                                        "has_boleto": bool(boleto_code),
                                        "boleto_code": boleto_code,
                                        "body": body_text, "body_html": body_html,
                                        "raw": raw, "account": email_addr,
                                    }
                                    self.seen_uids.add(num.decode())
                                    self.new_email.emit(em_data)

                                    # ── After capture action ──
                                    try:
                                        if after_capture == "delete":
                                            self.imap.store(num, '+FLAGS', '\\Deleted')
                                            self.imap.expunge()
                                        elif after_capture == "move":
                                            # Create folder if not exists
                                            self.imap.create(processed_folder)
                                            self.imap.copy(num, processed_folder)
                                            self.imap.store(num, '+FLAGS', '\\Deleted')
                                            self.imap.expunge()
                                    except: pass

                                    # Auto-download
                                    dl = self.cfg.get("download_path", "")
                                    if dl:
                                        os.makedirs(dl, exist_ok=True)
                                        for att in attachments:
                                            part = att.get("part"); name = att.get("name","")
                                            if part and name:
                                                fpath = os.path.join(dl, name)
                                                try:
                                                    d = part.get_payload(decode=True)
                                                    if d:
                                                        with open(fpath, "wb") as f: f.write(d)
                                                        att["path"] = fpath
                                                except: pass
                                except: pass

                        except: pass

                    self.status_update.emit(email_addr, f"⏳ Aguardando {interval}s...")
                    for _ in range(interval):
                        if not self.running: break
                        time.sleep(1)
                    # Keep-alive ping
                    try: self.imap.noop()
                    except:
                        self.status_update.emit(email_addr, "🔄 Reconectando...")
                        break

            except Exception as e:
                self.status_update.emit(email_addr, f"❌ {str(e)[:40]}")
                if self.running:
                    time.sleep(30)

# ── ZEUS Advanced Boleto Detection Engine ───────────────────────────────────
import hashlib

# Persistent UID cache path
UID_CACHE_FILE = os.path.join(os.path.expanduser("~"), ".zeus_uid_cache.json")

def load_uid_cache():
    """Load UID cache from DB or JSON fallback."""
    if _ZEUS_ENGINE and _DB:
        return {}  # DB handles per-query lookups — no bulk load needed
    try:
        with open(UID_CACHE_FILE, "r") as f:
            return json.load(f)
    except: return {}

def save_uid_cache(cache):
    """Save UID cache — DB handles this automatically."""
    if _ZEUS_ENGINE and _DB:
        return  # DB handles it
    try:
        with open(UID_CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except: pass

# ── Multi-layer boleto detection ─────────────────────────────────────────────
# Layer 1: Numeric barcode patterns (most reliable)
BOLETO_PATTERNS = [
    # Formato padrão linha digitável
    re.compile(r'\d{5}\.\d{5}\s+\d{5}\.\d{6}\s+\d{5}\.\d{6}\s+\d\s+\d{14}'),
    re.compile(r'\d{5}\.\d{5}\d{5}\.\d{6}\d{5}\.\d{6}\d\d{14}'),
    # Código de barras 44-47 dígitos
    re.compile(r'\d{44,48}'),
    # Pix copia e cola
    re.compile(r'00020126\d{10,}'),
    # Padrão banco com pontos
    re.compile(r'\d{4,5}[\.\s]\d{4,5}[\.\s]\d{4,5}[\.\s]\d{4,5}[\.\s]\d{4,14}'),
    # CNAB / remessa
    re.compile(r'(?:nosso.?n[uú]mero|n[uú]mero.?documento)[:\s]+(\d{6,20})', re.IGNORECASE),
]

# Layer 2: Subject keywords (fast IMAP server-side filter)
BOLETO_SUBJECTS = [
    "boleto", "fatura", "duplicata", "cobrança", "cobranc", "vencimento",
    "pagamento", "conta a pagar", "nota fiscal", "nf-e", "nfe", "danfe",
    "titulo", "financeiro", "2 via", "2via", "segunda via", "carnê",
    "aluguel", "condominio", "energia", "agua", "telefone", "internet",
    "mensalidade", "parcela", "prestacao", "aviso", "recibo", "boleto digital",
    "bank slip", "invoice", "payment"
]

# Layer 3: HTML/PDF keyword indicators
BOLETO_BODY_KEYWORDS = [
    "linha digitável", "linha digitavel", "código de barras", "codigo de barras",
    "data de vencimento", "valor do documento", "beneficiário", "beneficiario",
    "cedente", "sacado", "pagável em qualquer banco", "pagavel em qualquer banco",
    "local de pagamento", "nosso número", "nosso numero", "pague até",
    "pague ate", "bank slip", "boleto bancário", "boleto bancario",
    "instrução de cobrança", "instrucao de cobranca", "autenticação mecânica",
    "autenticacao mecanica", "recibo do pagador",
]

# ── PDF Boleto Extractor ─────────────────────────────────────────────────────
def _extract_text_from_pdf_bytes(pdf_bytes):
    """
    Extract raw text from PDF bytes without external libraries.
    Uses multiple strategies:
    1. zlib-decompress FlateDecode streams → find BT/ET text blocks
    2. Raw stream scan for printable ASCII sequences
    3. Regex scan directly on raw bytes for digit patterns
    """
    import zlib, struct

    extracted = []

    # Strategy 1: decompress FlateDecode streams and extract BT/ET text
    try:
        streams = re.findall(rb'stream\r?\n(.*?)\r?\nendstream', pdf_bytes, re.DOTALL)
        for stream in streams:
            try:
                data = zlib.decompress(stream)
            except:
                data = stream  # try raw

            # Extract text between BT...ET blocks (PDF text operators)
            blocks = re.findall(rb'BT\s*(.*?)\s*ET', data, re.DOTALL)
            for block in blocks:
                # Extract string literals: (text) or <hex>
                parts = re.findall(rb'\(([^)]*)\)', block)
                for p in parts:
                    try:
                        txt = p.decode('latin-1', errors='replace')
                        extracted.append(txt)
                    except: pass
                # Hex strings
                hex_parts = re.findall(rb'<([0-9A-Fa-f]+)>', block)
                for h in hex_parts:
                    try:
                        raw_h = bytes.fromhex(h.decode())
                        extracted.append(raw_h.decode('latin-1', errors='replace'))
                    except: pass
    except: pass

    # Strategy 2: scan raw bytes for long digit sequences (barcodes)
    digit_seqs = re.findall(rb'\d{8,}', pdf_bytes)
    for seq in digit_seqs:
        try: extracted.append(seq.decode())
        except: pass

    # Strategy 3: printable ASCII runs ≥ 6 chars
    ascii_runs = re.findall(rb'[ -~]{6,}', pdf_bytes)
    for run in ascii_runs:
        try:
            txt = run.decode('latin-1', errors='replace')
            if any(c.isdigit() for c in txt):
                extracted.append(txt)
        except: pass

    return ' '.join(extracted)


def _extract_text_from_xml_bytes(xml_bytes):
    """Extract text content from XML/NFe bytes."""
    try:
        text = xml_bytes.decode('utf-8', errors='replace')
        # Remove tags
        return re.sub(r'<[^>]+>', ' ', text)
    except:
        return ""


def _search_boleto_in_attachment(att):
    """
    Deep scan attachment bytes for boleto codes.
    Handles: PDF, XML, HTML, TXT, and binary fallback.
    Returns (code, method) or ("", "")
    """
    part = att.get("part")
    name = att.get("name","").lower()
    if not part: return "", ""

    try:
        raw_bytes = part.get_payload(decode=True)
        if not raw_bytes: return "", ""

        # Choose extraction strategy by file type
        if name.endswith(".pdf"):
            text = _extract_text_from_pdf_bytes(raw_bytes)
        elif name.endswith(".xml"):
            text = _extract_text_from_xml_bytes(raw_bytes)
        elif name.endswith((".html",".htm",".txt")):
            try: text = raw_bytes.decode('utf-8', errors='replace')
            except: text = raw_bytes.decode('latin-1', errors='replace')
            if name.endswith((".html",".htm")):
                text = re.sub(r'<[^>]+>', ' ', text)
        else:
            # Binary fallback — extract printable runs and digit sequences
            digit_seqs = re.findall(rb'\d{8,}', raw_bytes)
            text = ' '.join(s.decode() for s in digit_seqs)

        if not text.strip(): return "", ""

        # Run all boleto patterns on extracted text
        for pat in BOLETO_PATTERNS:
            m = pat.search(text)
            if m:
                code = re.sub(r'[\s\.]', '', m.group(0))
                if len(code) >= 44:
                    return code, f"pdf_barcode:{name}"
                elif len(code) >= 20:
                    return code, f"pdf_ref:{name}"

        # Keyword scan on extracted text
        text_lower = text.lower()
        kw_hits = sum(1 for kw in BOLETO_BODY_KEYWORDS if kw in text_lower)
        if kw_hits >= 2:
            val = extract_value(text)
            return f"[pdf_keywords:{kw_hits}] {val}", f"pdf_keywords:{name}"

    except: pass
    return "", ""


_classifier_instance = None
_classifier_lock = threading.Lock()

def _get_classifier():
    global _classifier_instance
    if _classifier_instance is None and _ZEUS_ENGINE and _DB:
        with _classifier_lock:
            if _classifier_instance is None:
                _classifier_instance = BoletoClassifier(_DB)
                # Train in background
                threading.Thread(target=_classifier_instance.train, daemon=True).start()
    return _classifier_instance


def detect_boleto_advanced(subject, body_text, body_html, attachments):
    """
    8-layer boleto detection returning (found: bool, code: str, method: str)
    Layer 0: ML Classifier (if trained)

    Layer 1 — Body text regex (barcode patterns)
    Layer 2 — HTML body regex (barcode patterns)
    Layer 3 — Body keyword scoring
    Layer 4 — Subject keyword matching
    Layer 5 — Attachment name heuristic
    Layer 6 — PDF/XML/HTML attachment deep extraction ← NEW
    Layer 7 — Raw binary digit scan on all attachments ← NEW
    """
    # Layer 0: ML Classifier — fast pre-check
    if _ZEUS_ENGINE and _DB:
        try:
            _clf = _get_classifier()
            if _clf and _clf._trained:
                is_b, conf, method = _clf.predict(subject, body_text)
                if is_b and conf > 0.80:
                    # High confidence ML hit — still extract code
                    pass  # fall through to extract code
                elif not is_b and conf > 0.85:
                    return False, "", f"ml_negative:{conf:.2f}"
        except: pass

    # Layer 1: regex on plain text body
    for pat in BOLETO_PATTERNS:
        m = pat.search(body_text)
        if m:
            code = re.sub(r'[\s\.]', '', m.group(0))
            if len(code) >= 44: return True, code, "body_barcode"
            if len(code) >= 20: return True, code, "body_ref"

    # Layer 2: regex on HTML body (stripped)
    if body_html:
        import html as _html
        clean = _html.unescape(re.sub(r'<[^>]+>', ' ', body_html))
        for pat in BOLETO_PATTERNS:
            m = pat.search(clean)
            if m:
                code = re.sub(r'[\s\.]', '', m.group(0))
                if len(code) >= 44: return True, code, "html_barcode"
                if len(code) >= 20: return True, code, "html_ref"

    # Layer 3: keyword scoring on full body
    full_text = body_text + " " + (re.sub(r'<[^>]+>',' ',body_html) if body_html else "")
    text_lower = full_text.lower()
    kw_hits = sum(1 for kw in BOLETO_BODY_KEYWORDS if kw in text_lower)
    if kw_hits >= 2:
        val = extract_value(full_text); due = extract_due(full_text)
        return True, f"[body_kw:{kw_hits}] {val} venc:{due}", "body_keywords"

    # Layer 4: subject keywords
    subj_lower = subject.lower()
    if sum(1 for kw in BOLETO_SUBJECTS if kw in subj_lower) >= 1:
        val = extract_value(full_text)
        return True, f"[subject] {val}", "subject"

    # Layer 5: attachment name heuristic (fast — no byte read)
    BOLETO_ATT_KW = ["boleto","fatura","nfe","nf-e","danfe","nota","cobranca","cobr",
                     "duplicata","recibo","boleto_bancario","invoice","payment","carne","carnet"]
    SCAN_EXTS = {".pdf", ".xml", ".html", ".htm", ".txt"}

    for att in attachments:
        name = att.get("name","")
        name_lower = name.lower()
        ext = os.path.splitext(name_lower)[1]

        # Named boleto keywords → deep scan immediately
        if any(kw in name_lower for kw in BOLETO_ATT_KW):
            code, method = _search_boleto_in_attachment(att)
            if code: return True, code, f"deep:{method}"
            return True, f"[att_name] {name}", "att_name"

        # Unnamed PDF/XML with mostly digits in name (e.g. "43291.09230.pdf")
        if ext in SCAN_EXTS:
            name_no_ext = os.path.splitext(name_lower)[0]
            digit_ratio = sum(c.isdigit() for c in name_no_ext) / max(len(name_no_ext), 1)
            if digit_ratio > 0.4:  # >40% digits = likely a barcode filename
                code, method = _search_boleto_in_attachment(att)
                if code: return True, code, f"deep_numeric:{method}"

    # Layer 6+7: deep scan ALL PDF/XML attachments regardless of name
    for att in attachments:
        name_lower = att.get("name","").lower()
        ext = os.path.splitext(name_lower)[1]
        if ext in SCAN_EXTS:
            code, method = _search_boleto_in_attachment(att)
            if code: return True, code, f"deep:{method}"

    return False, "", ""

def build_imap_search_query(cfg):
    """Build IMAP SEARCH command to pre-filter on server — zero download."""
    kw_inc = cfg.get("keywords_include", BOLETO_SUBJECTS[:8])
    max_days = int(cfg.get("max_days_old", 4))
    
    # Date since filter
    since_date = (datetime.now() - __import__('timedelta' , fromlist=['timedelta']) if False else
                  datetime.now() - __import__('datetime', fromlist=['timedelta']).timedelta(days=max_days))
    since_str = since_date.strftime("%d-%b-%Y")
    
    # Build OR query for subjects (IMAP supports OR chains)
    # Use first 5 keywords to avoid oversized query
    top_kw = [kw for kw in kw_inc if kw.strip()][:5]
    
    if top_kw:
        # Build: OR (SUBJECT "kw1") (OR (SUBJECT "kw2") ...)
        parts = [f'SUBJECT "{kw}"' for kw in top_kw]
        if len(parts) == 1:
            subj_query = parts[0]
        else:
            subj_query = parts[0]
            for p in parts[1:]:
                subj_query = f"OR ({subj_query}) ({p})"
        return f"SINCE {since_str} ({subj_query})"
    else:
        return f"SINCE {since_str} ALL"


# ── ZEUS Engine v3 — Zero-Block Architecture ─────────────────────────────────
#
# Design:
#   • Each account → 1 native Python thread (FastAccountWorker)
#   • Workers put results in a thread-safe queue (never touch Qt objects)
#   • AccountCoordinator (QThread) drains the queue and emits Qt signals
#   • UI receives signals on main thread — ZERO chance of freeze
#   • Status updates are rate-limited (max 1 per second per account)
#   • Email queue is bounded (maxsize=500) — backpressure prevents OOM
#
import queue

_EMAIL_QUEUE   = queue.Queue(maxsize=500)   # worker → coordinator
_STATUS_QUEUE  = queue.Queue(maxsize=1000)  # worker → coordinator


class FastAccountWorker(threading.Thread):
    """Pure Python thread — NEVER touches Qt. Puts results in queues only."""

    def __init__(self, acc, cfg, uid_cache, cache_lock, run_once=False):
        super().__init__(daemon=True)
        self.acc         = acc
        self.cfg         = cfg
        self.uid_cache   = uid_cache
        self.cache_lock  = cache_lock
        self.running     = True
        self.run_once    = run_once
        self.imap        = None
        self.em_addr     = acc["email"]
        self._last_status_time = 0.0

    def stop(self):
        self.running = False
        if self.imap:
            try: self.imap.logout()
            except: pass

    # ── Status helper — rate-limited ──────────────────────────────────────────
    def _status(self, msg, force=False):
        now = time.time()
        if force or now - self._last_status_time > 1.0:
            self._last_status_time = now
            try: _STATUS_QUEUE.put_nowait((self.em_addr, msg))
            except queue.Full: pass

    # ── UID cache helpers ─────────────────────────────────────────────────────
    def _cache_key(self, folder):
        return f"{self.em_addr}:{folder}"

    def _is_seen(self, folder, uid):
        # Check DB first (persists across sessions)
        if _ZEUS_ENGINE and _DB:
            try:
                if _DB.is_uid_seen(self.em_addr, folder, uid):
                    return True
            except: pass
        # Fallback to in-memory cache
        key = self._cache_key(folder)
        with self.cache_lock:
            return uid in self.uid_cache.get(key, set())

    def _mark_seen(self, folder, uid):
        # Mark in DB
        if _ZEUS_ENGINE and _DB:
            try: _DB.mark_uid_seen(self.em_addr, folder, uid)
            except: pass
        # Also mark in memory cache
        key = self._cache_key(folder)
        with self.cache_lock:
            self.uid_cache.setdefault(key, set()).add(uid)

    # ── IMAP helpers ──────────────────────────────────────────────────────────
    def _connect(self):
        self.imap = connect_imap(self.acc)
        try: self.imap.socket().settimeout(25)
        except: pass

    def _search_server(self, folder):
        """
        Aggressive mode: fetch ALL UNSEEN emails in date range.
        No subject filtering at server level — we want every unread email
        because PDFs can arrive with any subject.
        """
        max_days = int(self.cfg.get("max_days_old", 4))
        from datetime import timedelta
        since = (datetime.now() - timedelta(days=max_days)).strftime("%d-%b-%Y")
        ids = set()
        try:
            # UNSEEN = not read. Fast server-side filter.
            _, msgs = self.imap.search(None, f"UNSEEN SINCE {since}")
            ids = set((msgs[0] or b"").split())
        except: pass
        # Fallback to ALL recent if UNSEEN returns nothing
        if not ids:
            try:
                _, msgs = self.imap.search(None, f"SINCE {since} ALL")
                ids = set((msgs[0] or b"").split())
            except: pass
        return [i for i in ids if not self._is_seen(folder, i.decode())]

    def _fetch_headers_batch(self, ids):
        """Batch header fetch — one IMAP command for up to 100 IDs."""
        results = {}
        if not ids: return results
        try:
            id_str = b','.join(ids[:100])
            _, data = self.imap.fetch(id_str,
                '(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])')
            current_num = None
            buf = b''
            for item in data:
                if isinstance(item, tuple):
                    m = re.match(rb'^(\d+)\s', item[0])
                    if m:
                        if current_num and buf:
                            msg = email.message_from_bytes(buf)
                            results[current_num] = {
                                "subject": decode_str(msg.get("Subject","")),
                                "from":    decode_str(msg.get("From","")),
                                "date":    msg.get("Date",""),
                            }
                        current_num = m.group(1)
                        buf = item[1] if isinstance(item[1], bytes) else b''
                elif isinstance(item, bytes) and current_num:
                    buf += item
            if current_num and buf:
                msg = email.message_from_bytes(buf)
                results[current_num] = {
                    "subject": decode_str(msg.get("Subject","")),
                    "from":    decode_str(msg.get("From","")),
                    "date":    msg.get("Date",""),
                }
        except: pass
        return results

    def _fetch_structure_batch(self, ids):
        """
        For each email ID, check if it has attachments by fetching
        BODYSTRUCTURE — returns {num_bytes: [filename, ...]}
        Falls back to checking Content-Type header for multipart.
        """
        results = {}
        if not ids: return results

        # Try BODYSTRUCTURE first (most reliable)
        try:
            id_str = b','.join(ids[:50])  # smaller batch for reliability
            _, data = self.imap.fetch(id_str, '(BODYSTRUCTURE)')
            for item in data:
                if not isinstance(item, tuple): continue
                try:
                    info_str = item[0].decode('utf-8', errors='replace')
                    # Extract message number
                    m = re.match(r'^(\d+)\s', info_str)
                    if not m: continue
                    num = m.group(1).encode()
                    structure = item[1].decode('utf-8', errors='replace') if isinstance(item[1], bytes) else str(item[1])
                    # Extract filenames from BODYSTRUCTURE
                    names = []
                    for fn in re.finditer(r'"NAME"\s+"([^"]+)"', structure, re.IGNORECASE):
                        names.append(decode_str(fn.group(1)))
                    for fn in re.finditer(r'"FILENAME"\s+"([^"]+)"', structure, re.IGNORECASE):
                        names.append(decode_str(fn.group(1)))
                    # Also check for PDF/XML by type markers
                    has_pdf_type = bool(re.search(r'"APPLICATION"\s+"PDF"', structure, re.IGNORECASE))
                    has_xml_type = bool(re.search(r'"APPLICATION"\s+"XML"', structure, re.IGNORECASE))
                    if has_pdf_type and not any(n.lower().endswith('.pdf') for n in names):
                        names.append('attachment.pdf')
                    if has_xml_type and not any(n.lower().endswith('.xml') for n in names):
                        names.append('attachment.xml')
                    results[num] = names
                except: pass
        except:
            # Fallback: fetch MIME headers to detect multipart/attachment
            try:
                id_str = b','.join(ids[:100])
                _, data = self.imap.fetch(id_str,
                    '(BODY.PEEK[HEADER.FIELDS (CONTENT-TYPE CONTENT-DISPOSITION MIME-VERSION)])')
                current_num = None; buf = b''
                for item in data:
                    if isinstance(item, tuple):
                        m = re.match(rb'^(\d+)\s', item[0])
                        if m:
                            if current_num and buf:
                                results[current_num] = self._extract_att_names_from_headers(buf)
                            current_num = m.group(1)
                            buf = item[1] if isinstance(item[1], bytes) else b''
                    elif isinstance(item, bytes) and current_num:
                        buf += item
                if current_num and buf:
                    results[current_num] = self._extract_att_names_from_headers(buf)
            except: pass
        return results

    def _extract_att_names_from_headers(self, header_bytes):
        """Extract filenames from Content-Disposition/Content-Type headers."""
        names = []
        try:
            text = header_bytes.decode('utf-8', errors='replace')
            for m in re.finditer(r'filename[*]?=["\']?([^"\'\r\n;]+)', text, re.IGNORECASE):
                name = m.group(1).strip().strip('"\'')
                if name: names.append(decode_str(name))
            for m in re.finditer(r'name=["\']?([^"\'\r\n;]+)', text, re.IGNORECASE):
                name = m.group(1).strip().strip('"\'')
                if name: names.append(decode_str(name))
        except: pass
        return names

    def _quick_body_peek(self, num):
        """Read body text without marking as read."""
        try:
            _, data = self.imap.fetch(num, '(BODY.PEEK[TEXT])')
            for item in data:
                if isinstance(item, tuple) and len(item) > 1:
                    raw = item[1]
                    if isinstance(raw, bytes):
                        try:    return raw.decode('utf-8', errors='replace')
                        except: return raw.decode('latin-1', errors='replace')
        except: pass
        return ""

    def _process_full(self, num, folder):
        """Fetch full RFC822 and extract all fields."""
        cfg = self.cfg
        after_capture    = cfg.get("after_capture", "delete")
        processed_folder = cfg.get("processed_folder", "Processados")
        extensions       = cfg.get("extensions", [])
        dl               = cfg.get("download_path", "")

        _, data = self.imap.fetch(num, "(RFC822)")
        raw = data[0][1]
        msg = email.message_from_bytes(raw)

        subject  = decode_str(msg.get("Subject",""))
        sender   = decode_str(msg.get("From",""))
        to_addr  = decode_str(msg.get("To",""))
        date_str = msg.get("Date","")
        body_text = ""; body_html = ""; attachments = []

        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition",""))
            if ct == "text/plain" and "attachment" not in cd:
                try: body_text += part.get_payload(decode=True).decode("utf-8", errors="replace")
                except: pass
            elif ct == "text/html" and "attachment" not in cd:
                try: body_html += part.get_payload(decode=True).decode("utf-8", errors="replace")
                except: pass
            fname = decode_str(part.get_filename() or "")
            if fname:
                ext = os.path.splitext(fname)[1].lower()
                if not extensions or ext in extensions:
                    attachments.append({"name": fname, "part": part, "path": ""})

        # Boleto detection
        found, boleto_code, method = detect_boleto_advanced(
            subject, body_text, body_html, attachments)
        value    = extract_value(body_text) or extract_value(body_html)
        due_date = extract_due(body_text)   or extract_due(body_html)

        uid_str = num.decode() if isinstance(num, bytes) else str(num)

        em_data = {
            "uid": uid_str, "folder": folder, "original_folder": folder,
            "subject": subject, "sender": sender, "to": to_addr,
            "date": date_str, "state": "NAO LIDO",
            "value": value, "due_date": due_date,
            "attachments": attachments,
            "has_boleto": found, "boleto_code": boleto_code,
            "detection_method": method,
            "body": body_text, "body_html": body_html,
            "raw": raw, "account": self.em_addr,
        }

        # After-capture action
        try:
            if after_capture == "delete":
                self.imap.store(num, '+FLAGS', '\\Deleted')
                self.imap.expunge()
            elif after_capture == "move":
                try: self.imap.create(processed_folder)
                except: pass
                self.imap.copy(num, processed_folder)
                self.imap.store(num, '+FLAGS', '\\Deleted')
                self.imap.expunge()
        except: pass

        # Auto-download attachments (in background thread — safe)
        if dl:
            os.makedirs(dl, exist_ok=True)
            for att in attachments:
                p = att.get("part"); n = att.get("name","")
                if p and n:
                    fp = os.path.join(dl, n)
                    try:
                        d = p.get_payload(decode=True)
                        if d:
                            with open(fp, "wb") as f: f.write(d)
                            att["path"] = fp
                    except: pass

        return em_data

    # ── Main loop ─────────────────────────────────────────────────────────────
    def run(self):
        interval    = int(self.cfg.get("cycle_interval", 60))
        folders     = self.cfg.get("folders", ["INBOX"])
        only_boleto = self.cfg.get("only_boleto", True)
        min_value   = float(self.cfg.get("min_value", 0.0))
        per_cycle   = int(self.cfg.get("emails_per_read", 10))
        max_days    = int(self.cfg.get("max_days_old", 4))

        self._pending     = {}
        self._auth_failed = False
        total_captured    = 0

        while self.running:
            if self._auth_failed:
                time.sleep(60); continue

            try:
                # ── Connect ──────────────────────────────────────────────────
                if not self.imap:
                    self._status("🔌 Conectando...", force=True)
                    try:
                        self._connect()
                        self._status("✅ Conectado", force=True)
                    except Exception as e:
                        err = str(e)
                        if any(x in err for x in ["AUTHENTICATIONFAILED","[AUTH]","Invalid credentials","AUTHENTICATE"]):
                            self._auth_failed = True
                            self._status("🔴 Senha incorreta", force=True)
                            return
                        self._status(f"❌ {err[:35]}", force=True)
                        time.sleep(15); continue
                else:
                    try: self.imap.noop()
                    except: self.imap = None; continue

                # ── Fill pending per folder ───────────────────────────────────
                for folder in folders:
                    if not self._pending.get(folder):
                        try:
                            self.imap.select(folder, readonly=True)
                            # Get ALL emails in date range (read + unread)
                            # Using ALL so we don't miss emails marked as read
                            from datetime import timedelta
                            since = (datetime.now() - timedelta(days=max_days)).strftime("%d-%b-%Y")
                            _, msgs = self.imap.search(None, f"SINCE {since}")
                            ids = (msgs[0] or b"").split()
                            total_found = len(ids)
                            # Filter already processed
                            new_ids = [i for i in ids if not self._is_seen(folder, i.decode())]
                            try: new_ids = sorted(new_ids, key=lambda x: int(x))
                            except: pass
                            self._pending[folder] = new_ids
                            skipped = total_found - len(new_ids)
                            self._status(
                                f"🔍 {total_found} emails | {len(new_ids)} novos | {skipped} já processados",
                                force=True)
                        except Exception as e:
                            self._status(f"❌ {folder}: {str(e)[:30]}", force=True)

                # ── Check total pending ───────────────────────────────────────
                total_pending = sum(len(v) for v in self._pending.values())

                if total_pending == 0:
                    save_uid_cache({k: list(v) for k, v in self.uid_cache.items()})
                    if self.run_once:
                        self._status(f"✅ {total_captured} capturados | ciclo concluído", force=True)
                        return
                    self._status(f"✅ {total_captured} capturados | ⏳ {interval}s", force=True)
                    for _ in range(interval):
                        if not self.running: break
                        time.sleep(1)
                    total_captured = 0
                    continue

                # ── Process per_cycle emails ──────────────────────────────────
                for folder in folders:
                    if not self.running: break
                    pending = self._pending.get(folder, [])
                    if not pending: continue

                    batch = pending[:per_cycle]
                    self._pending[folder] = pending[per_cycle:]
                    done = sum(len(v) for v in self._pending.values())

                    self._status(f"📖 {len(batch)} emails | {done} restantes")

                    try:
                        self.imap.select(folder)
                    except:
                        self.imap = None; break

                    for num in batch:
                        if not self.running: break
                        uid_str = num.decode() if isinstance(num, bytes) else str(num)
                        self._mark_seen(folder, uid_str)
                        try:
                            em_data = self._process_full(num, folder)
                            if not em_data: continue

                            # Only filter by value if configured
                            if min_value > 0:
                                v = parse_value_float(em_data.get("value",""))
                                if v > 0 and v < min_value: continue

                            # If boleto-only: require boleto OR any attachment OR subject hint
                            if only_boleto:
                                has_boleto  = em_data.get("has_boleto")
                                has_att     = len(em_data.get("attachments",[])) > 0
                                subj_lower  = em_data.get("subject","").lower()
                                subj_hit    = any(k in subj_lower for k in [
                                    "boleto","fatura","vencimento","venc","cobranca",
                                    "pagamento","nota","nfe","nf-e","duplicata",
                                    "lembrete","aviso","recibo","parcela","mensalidade"
                                ])
                                if not has_boleto and not has_att and not subj_hit:
                                    continue

                            try: _EMAIL_QUEUE.put(em_data, timeout=5)
                            except queue.Full: pass
                            total_captured += 1
                            # Feed to ML classifier for learning
                            if _ZEUS_ENGINE and _DB:
                                try:
                                    clf = _get_classifier()
                                    if clf:
                                        clf.learn(
                                            em_data.get("subject",""),
                                            em_data.get("body",""),
                                            em_data.get("has_boleto", True)
                                        )
                                except: pass

                        except Exception as e:
                            pass  # skip bad emails silently

                    self._status(f"✅ {total_captured} capturados")

                time.sleep(0.1)

            except Exception as e:
                self._status(f"❌ {str(e)[:40]}", force=True)
                self.imap = None
                for _ in range(15):
                    if not self.running: break
                    time.sleep(1)


class AccountCoordinator(QThread):
    """
    Coordinator runs as QThread — drains the shared queues and emits
    Qt signals safely on the Qt thread. Workers NEVER touch Qt.
    """
    new_email     = pyqtSignal(dict)
    status_update = pyqtSignal(str, str)

    def __init__(self, accounts, cfg):
        super().__init__()
        self.accounts     = accounts
        self.cfg          = cfg
        self.running      = True
        self.workers      = []
        self._uid_cache   = {}
        self._cache_lock  = threading.Lock()

    def mark_returned(self, uid, folder, account):
        key = f"{account}:{folder}"
        with self._cache_lock:
            self._uid_cache.setdefault(key, set()).add(uid)
        save_uid_cache({k: list(v) for k, v in self._uid_cache.items()})

    def stop(self):
        self.running = False
        for w in self.workers:
            w.running = False
        save_uid_cache({k: list(v) for k, v in self._uid_cache.items()})

    def _drain_queues(self):
        for _ in range(20):
            try: em = _EMAIL_QUEUE.get_nowait(); self.new_email.emit(em); _EMAIL_QUEUE.task_done()
            except queue.Empty: break
        for _ in range(50):
            try: addr, msg = _STATUS_QUEUE.get_nowait(); self.status_update.emit(addr, msg); _STATUS_QUEUE.task_done()
            except queue.Empty: break

    def run(self):
        with self._cache_lock:
            raw_cache = load_uid_cache()
            self._uid_cache.update({k: set(v) for k, v in raw_cache.items()})

        max_threads     = int(self.cfg.get("max_threads", 5))
        monitor_total   = int(self.cfg.get("monitor_accounts", 0))  # 0 = all

        all_accounts = list(self.accounts)
        if monitor_total > 0:
            all_accounts = all_accounts[:monitor_total]

        if not all_accounts:
            return

        # Se simultâneas >= total de contas: modo permanente (sem rotação)
        if max_threads >= len(all_accounts):
            for acc in all_accounts:
                w = FastAccountWorker(acc, self.cfg, self._uid_cache, self._cache_lock)
                w.start()
                self.workers.append(w)
                time.sleep(0.05)
            while self.running:
                self._drain_queues()
                time.sleep(0.1)
            for w in self.workers:
                w.stop()
            return

        # Modo rotação: N contas simultâneas, cicla por todas
        account_queue = deque(all_accounts)

        while self.running:
            batch_size = min(max_threads, len(account_queue))
            if not batch_size:
                break

            batch = [account_queue.popleft() for _ in range(batch_size)]
            batch_workers = []

            for acc in batch:
                if not self.running:
                    break
                w = FastAccountWorker(acc, self.cfg, self._uid_cache, self._cache_lock, run_once=True)
                w.start()
                self.workers.append(w)
                batch_workers.append((w, acc))
                time.sleep(0.05)

            # Drena filas enquanto o lote roda
            while self.running and any(w.is_alive() for w, _ in batch_workers):
                self._drain_queues()
                time.sleep(0.1)

            # Devolve as contas processadas ao fim da fila para próxima rodada
            for _, acc in batch_workers:
                account_queue.append(acc)

            # Remove workers finalizados da lista
            self.workers = [w for w in self.workers if w.is_alive()]

        for w in self.workers:
            try: w.stop()
            except: pass


# ── Boleto PDF Editor Dialog ─────────────────────────────────────────────────
class BoletoPDFEditor(QDialog):
    """
    Click-to-edit boleto PDF editor.
    Renders PDF as image, user clicks on field to select it,
    then types new value. No auto-detection = no wrong positioning.
    """
    def __init__(self, att, cfg, parent=None):
        super().__init__(parent)
        self.att = att
        self.cfg = cfg
        self.pdf_bytes = None
        self.result_bytes = None
        self.page_w = 595.0
        self.page_h = 842.0
        self.scale  = 1.0
        # List of edits: {x, y, w, h, text, font, size, label}
        self.edits  = []
        self.barcode_rect = None  # (x,y,w,h) in PDF coords
        self.selecting_barcode = False
        self.drag_start = None
        self.drag_rect  = None
        self._load_pdf()
        self.setWindowTitle("⚡ ZEUS — Editor de Boleto")
        self.setMinimumSize(900, 700)
        self._build()

    def _load_pdf(self):
        path = self.att.get("path","")
        if path and os.path.exists(path):
            with open(path,"rb") as f: self.pdf_bytes = f.read()
        else:
            part = self.att.get("part")
            if part: self.pdf_bytes = part.get_payload(decode=True)
        if self.pdf_bytes:
            from boleto_editor import get_pdf_page_size
            self.page_w, self.page_h = get_pdf_page_size(self.pdf_bytes)

    def _build(self):
        main = QHBoxLayout(self)
        main.setContentsMargins(0,0,0,0); main.setSpacing(0)

        # ── Left: PDF canvas ─────────────────────────────────────────────
        left = QWidget(); left.setStyleSheet("background:#1a1a1a;")
        ll = QVBoxLayout(left); ll.setContentsMargins(8,8,8,8); ll.setSpacing(6)

        toolbar = QHBoxLayout()
        btn_render = QPushButton("🔄 Renderizar PDF"); btn_render.setObjectName("btn_ghost")
        btn_render.clicked.connect(self._render_pdf)
        self.lbl_hint = QLabel("Clique em um campo no PDF para selecioná-lo")
        self.lbl_hint.setStyleSheet("color:#595959; font-size:11px;")
        toolbar.addWidget(btn_render); toolbar.addWidget(self.lbl_hint); toolbar.addStretch()
        ll.addLayout(toolbar)

        scroll = QScrollArea(); scroll.setStyleSheet("border:none;")
        self.canvas = QLabel()
        self.canvas.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.canvas.setStyleSheet("background:#2a2a2a;")
        self.canvas.setCursor(Qt.CrossCursor)
        self.canvas.setMouseTracking(True)
        self.canvas.mousePressEvent   = self._canvas_press
        self.canvas.mouseReleaseEvent = self._canvas_release
        self.canvas.mouseMoveEvent    = self._canvas_move
        self.canvas.paintEvent        = self._canvas_paint
        scroll.setWidget(self.canvas)
        ll.addWidget(scroll)

        # ── Right: controls ──────────────────────────────────────────────
        right = QWidget(); right.setFixedWidth(280)
        right.setStyleSheet("background:#0a0a0a; border-left:1px solid #2a2a2a;")
        rl = QVBoxLayout(right); rl.setContentsMargins(14,14,14,14); rl.setSpacing(12)

        title = QLabel("EDITOR DE BOLETO")
        title.setStyleSheet("color:#fff;font-size:14px;font-weight:900;")
        rl.addWidget(title)

        lbl_s = "color:#a3a3a3;font-size:9px;font-weight:700;letter-spacing:1px;"

        # Linha digitável
        rl.addWidget(self._lbl("NOVA LINHA DIGITÁVEL:", lbl_s))
        self.f_linha = QTextEdit(); self.f_linha.setMaximumHeight(60)
        self.f_linha.setFont(QFont("Consolas",9))
        self.f_linha.setPlaceholderText("00000.00000 00000.000000 00000.000000 0 00000000000000")
        self.f_linha.textChanged.connect(self._on_linha_changed)
        rl.addWidget(self.f_linha)

        # Código de barras (auto)
        rl.addWidget(self._lbl("CÓDIGO DE BARRAS (gerado):", lbl_s))
        self.f_codigo = QLineEdit(); self.f_codigo.setReadOnly(True)
        self.f_codigo.setFont(QFont("Consolas",8))
        self.f_codigo.setStyleSheet("background:#0d0d0d;color:#2ecc40;border:1px solid #2a2a2a;font-size:9px;")
        rl.addWidget(self.f_codigo)

        # Preview barcode
        self.barcode_preview = QLabel()
        self.barcode_preview.setFixedHeight(36)
        self.barcode_preview.setStyleSheet("background:white;border:1px solid #2a2a2a;")
        self.barcode_preview.setAlignment(Qt.AlignCenter)
        self.barcode_preview.setText("← Cole a linha digitável")
        rl.addWidget(self.barcode_preview)

        # Barcode position
        btn_sel_barcode = QPushButton("🎯 Selecionar posição do barcode no PDF")
        btn_sel_barcode.setObjectName("btn_ghost")
        btn_sel_barcode.clicked.connect(self._start_select_barcode)
        rl.addWidget(btn_sel_barcode)
        self.lbl_barcode_pos = QLabel("Posição: não definida")
        self.lbl_barcode_pos.setStyleSheet("color:#595959;font-size:10px;")
        rl.addWidget(self.lbl_barcode_pos)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine); sep.setStyleSheet("color:#2a2a2a;")
        rl.addWidget(sep)

        # Text fields to overlay
        rl.addWidget(self._lbl("SUBSTITUIÇÕES DE TEXTO:", lbl_s))
        rl.addWidget(self._lbl("(Clique no PDF para selecionar área)", "color:#404040;font-size:9px;"))

        self.edits_list = QListWidget(); self.edits_list.setMaximumHeight(120)
        self.edits_list.setStyleSheet("font-size:10px;")
        rl.addWidget(self.edits_list)

        edit_btns = QHBoxLayout()
        btn_del_edit = QPushButton("🗑 Remover"); btn_del_edit.setObjectName("btn_ghost")
        btn_del_edit.clicked.connect(self._remove_edit)
        btn_clr_edit = QPushButton("Limpar tudo"); btn_clr_edit.setObjectName("btn_ghost")
        btn_clr_edit.clicked.connect(self._clear_edits)
        edit_btns.addWidget(btn_del_edit); edit_btns.addWidget(btn_clr_edit)
        rl.addLayout(edit_btns)

        rl.addStretch()

        self.lbl_status = QLabel("Renderize o PDF para começar.")
        self.lbl_status.setStyleSheet("color:#e5a010;font-size:10px;")
        self.lbl_status.setWordWrap(True)
        rl.addWidget(self.lbl_status)

        # Action buttons
        btn_preview = QPushButton("👁 PREVIEW"); btn_preview.setObjectName("btn_ghost")
        btn_preview.clicked.connect(self._preview)
        btn_apply = QPushButton("✅ SALVAR PDF"); btn_apply.setObjectName("btn_red")
        btn_apply.clicked.connect(self._apply)
        btn_cancel = QPushButton("CANCELAR"); btn_cancel.setObjectName("btn_ghost")
        btn_cancel.clicked.connect(self.reject)
        for b in [btn_preview, btn_apply, btn_cancel]: rl.addWidget(b)

        main.addWidget(left, 1)
        main.addWidget(right)

        # Render immediately
        QTimer.singleShot(300, self._render_pdf)

    def _lbl(self, text, style=""):
        l = QLabel(text); l.setStyleSheet(style); return l

    def _render_pdf(self):
        """Render PDF page as image using pdf2image or fallback."""
        if not self.pdf_bytes:
            self.lbl_status.setText("PDF não carregado."); return
        self.lbl_status.setText("⏳ Renderizando...")
        QApplication.processEvents()
        try:
            from pdf2image import convert_from_bytes
            images = convert_from_bytes(self.pdf_bytes, dpi=120, first_page=1, last_page=1)
            if images:
                img = images[0]
                img_bytes = io.BytesIO()
                img.save(img_bytes, format="PNG")
                self._set_canvas_image(img_bytes.getvalue(), img.width, img.height)
                return
        except: pass
        # Fallback: show placeholder
        self.lbl_status.setText("pdf2image nao disponivel. Instale: pip install pdf2image")
        self._set_canvas_placeholder()

    def _set_canvas_image(self, png_bytes, img_w, img_h):
        from PyQt5.QtGui import QPixmap
        pm = QPixmap()
        pm.loadFromData(png_bytes)
        self.canvas.setPixmap(pm)
        self.canvas.resize(img_w, img_h)
        self._img_w = img_w; self._img_h = img_h
        self.scale = img_w / self.page_w
        self.lbl_status.setText("✅ PDF renderizado. Clique para selecionar campos.")
        self.lbl_status.setStyleSheet("color:#2ecc40;font-size:10px;")
        self._overlays_pixmap = None

    def _set_canvas_placeholder(self):
        from PyQt5.QtGui import QPixmap, QPainter, QColor, QFont as QF
        w, h = int(self.page_w), int(self.page_h)
        pm = QPixmap(w, h); pm.fill(QColor("white"))
        p = QPainter(pm); p.setFont(QF("Arial",14))
        p.drawText(pm.rect(), Qt.AlignCenter,
            "PDF nao renderizado\nInstale: pip install pdf2image\n\nUse coordenadas manuais")
        p.end()
        self.canvas.setPixmap(pm)
        self.canvas.resize(w, h)
        self._img_w = w; self._img_h = h
        self.scale = 1.0
        self._overlays_pixmap = None

    # ── Mouse events for field selection ──────────────────────────────────
    def _canvas_press(self, ev):
        self.drag_start = ev.pos()
        self.drag_rect  = None

    def _canvas_move(self, ev):
        if self.drag_start:
            self.drag_rect = QRect(self.drag_start, ev.pos()).normalized()
            self.canvas.update()

    def _canvas_release(self, ev):
        if not self.drag_start: return
        end = ev.pos()
        rect = QRect(self.drag_start, end).normalized()
        self.drag_start = None; self.drag_rect = None

        if rect.width() < 5 or rect.height() < 5: return

        # Convert to PDF coordinates
        s = self.scale
        px = rect.x() / s; py = (self._img_h - rect.y() - rect.height()) / s
        pw = rect.width() / s; ph = rect.height() / s

        if self.selecting_barcode:
            self.barcode_rect = (px, py, pw, ph)
            self.selecting_barcode = False
            self.canvas.setCursor(Qt.CrossCursor)
            self.lbl_barcode_pos.setText(f"Pos: x={px:.0f} y={py:.0f} w={pw:.0f} h={ph:.0f}")
            self.lbl_hint.setText("Posição do barcode definida!")
            self.canvas.update()
            return

        # Ask what to put here
        text, ok = QInputDialog.getText(self, "Novo valor",
            f"Digite o texto (x={px:.0f} y={py:.0f} w={pw:.0f} h={ph:.0f}):")
        if ok and text:
            self.edits.append({
                "x": px, "y": py, "w": pw, "h": ph,
                "text": text, "font": "Helvetica", "size": max(7, int(ph * 0.7)),
                "label": f"{text[:20]}... @ ({px:.0f},{py:.0f})"
            })
            self.edits_list.addItem(f"Texto: {text[:20]} @ ({px:.0f},{py:.0f})")
            self.canvas.update()

    def _canvas_paint(self, ev):
        from PyQt5.QtGui import QPainter, QColor, QPen
        pm = self.canvas.pixmap()
        if not pm: return
        p = QPainter(self.canvas)
        p.drawPixmap(0, 0, pm)

        s = self.scale
        h = self._img_h if hasattr(self, '_img_h') else int(self.page_h)

        # Draw existing edits
        p.setPen(QPen(QColor("#e50914"), 2))
        p.setBrush(QColor(229, 9, 20, 40))
        for edit in self.edits:
            rx = int(edit["x"] * s)
            ry = int(h - (edit["y"] + edit["h"]) * s)
            rw = int(edit["w"] * s)
            rh = int(edit["h"] * s)
            p.drawRect(rx, ry, rw, rh)

        # Draw barcode rect
        if self.barcode_rect:
            bx,by,bw,bh = self.barcode_rect
            p.setPen(QPen(QColor("#2ecc40"), 2))
            p.setBrush(QColor(46,204,64,30))
            p.drawRect(int(bx*s), int(h-(by+bh)*s), int(bw*s), int(bh*s))

        # Draw drag rect
        if self.drag_rect:
            p.setPen(QPen(QColor("#e5a010"), 1))
            p.setBrush(QColor(229,160,16,30))
            p.drawRect(self.drag_rect)

        p.end()

    def _start_select_barcode(self):
        self.selecting_barcode = True
        self.canvas.setCursor(Qt.SizeFDiagCursor)
        self.lbl_hint.setText("🎯 Arraste para marcar onde está o código de barras no PDF")
        self.lbl_hint.setStyleSheet("color:#e5a010;font-size:11px;font-weight:700;")

    def _remove_edit(self):
        idx = self.edits_list.currentRow()
        if 0 <= idx < len(self.edits):
            self.edits.pop(idx)
            self.edits_list.takeItem(idx)
            self.canvas.update()

    def _clear_edits(self):
        self.edits.clear(); self.edits_list.clear()
        self.barcode_rect = None
        self.lbl_barcode_pos.setText("Posição: não definida")
        self.canvas.update()

    def _on_linha_changed(self):
        text = self.f_linha.toPlainText().strip()
        try:
            from boleto_editor import linha_para_codigo44, gerar_barras_i2of5
            codigo = linha_para_codigo44(text)
            if codigo and len(codigo) == 44:
                self.f_codigo.setText(codigo)
                # Draw barcode preview
                from PyQt5.QtGui import QPixmap, QPainter, QColor
                pw, ph = 252, 36
                pm = QPixmap(pw, ph); pm.fill(QColor("white"))
                painter = QPainter(pm)
                painter.setBrush(QColor("black"))
                for x, w in gerar_barras_i2of5(codigo, pw, ph-4):
                    painter.fillRect(int(x), 2, max(1,int(w)), ph-4, QColor("black"))
                painter.end()
                self.barcode_preview.setPixmap(pm)
                self.lbl_status.setText("✅ Código gerado!")
                self.lbl_status.setStyleSheet("color:#2ecc40;font-size:10px;")
            else:
                self.f_codigo.setText("")
                self.barcode_preview.setText("← Cole a linha digitável")
        except: pass

    def _generate(self):
        from boleto_editor import criar_overlay, aplicar_overlay, linha_para_codigo44
        if not self.pdf_bytes: return None
        subs = [(e["x"],e["y"],e["w"],e["h"],e["text"],e["font"],e["size"])
                for e in self.edits]
        linha = self.f_linha.toPlainText().strip()
        codigo44 = linha_para_codigo44(linha) if linha else None
        overlay = criar_overlay(self.page_w, self.page_h, subs,
                                codigo44=codigo44,
                                barcode_rect=self.barcode_rect)
        return aplicar_overlay(self.pdf_bytes, overlay)

    def _preview(self):
        self.lbl_status.setText("⏳ Gerando preview...")
        QApplication.processEvents()
        try:
            result = self._generate()
            if result:
                import tempfile
                tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
                tmp.write(result); tmp.close()
                os.startfile(tmp.name)
                self.lbl_status.setText("✅ Preview aberto!")
        except Exception as e:
            self.lbl_status.setText(f"❌ {e}")
            self.lbl_status.setStyleSheet("color:#e50914;font-size:10px;")

    def _apply(self):
        if not self.edits and not (self.f_linha.toPlainText().strip() and self.barcode_rect):
            QMessageBox.warning(self,"Zeus","Nenhuma alteracao definida. Selecione campos no PDF ou defina o barcode.")
            return
        self.lbl_status.setText("⏳ Aplicando...")
        QApplication.processEvents()
        try:
            result = self._generate()
            if result:
                self.result_bytes = result
                path = self.att.get("path","")
                if path:
                    with open(path,"wb") as f: f.write(result)
                self.accept()
        except Exception as e:
            QMessageBox.critical(self,"Zeus",f"Erro:\n{e}")


# ── Email Editor ─────────────────────────────────────────────────────────────# ── Email Editor ─────────────────────────────────────────────────────────────
class EmailEditor(QWidget):
    def __init__(self, data=None, cfg=None, parent=None):
        super().__init__(parent)
        self.data = data or {}
        self.cfg = cfg or {}
        self.att_files = list(self.data.get("attachments", []))
        self._build()
        self._load()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        topbar = QWidget(); topbar.setObjectName("topbar"); topbar.setFixedHeight(52)
        tbl = QHBoxLayout(topbar); tbl.setContentsMargins(16, 0, 16, 0); tbl.setSpacing(6)
        for icon, tip, slot in [("💾", "Salvar", self._save), ("🗑", "Excluir", self._delete),
                                  ("📤", "Devolver para Inbox", self._return_inbox),
                                  ("📅", "Agendar Boleto", self._agendar_boleto),
                                  ("◀", "Anterior", None), ("▶", "Próximo", None)]:
            btn = QPushButton(icon); btn.setObjectName("btn_icon"); btn.setToolTip(tip)
            if slot: btn.clicked.connect(slot)
            tbl.addWidget(btn)
        tbl.addStretch()
        self.lbl_account = QLabel("")
        self.lbl_account.setStyleSheet("color: #595959; font-size: 11px;")
        tbl.addWidget(self.lbl_account)
        layout.addWidget(topbar)

        fields_widget = QWidget()
        fields_widget.setStyleSheet("background: #1a1a1a; border-bottom: 1px solid #2a2a2a;")
        fl = QFormLayout(fields_widget); fl.setContentsMargins(16,12,16,12); fl.setSpacing(8)
        lbl_style = "color: #a3a3a3; font-size: 10px; font-weight: 700; letter-spacing: 1px; min-width: 90px;"
        self.f_subject = QLineEdit(); self.f_from = QLineEdit()
        self.f_to = QLineEdit(); self.f_cc = QLineEdit()
        self.f_bcc = QLineEdit(); self.f_reply = QLineEdit()
        for label, widget in [("ASSUNTO", self.f_subject), ("DE", self.f_from),
                                ("PARA", self.f_to), ("CÓPIA", self.f_cc),
                                ("CÓPIA OCULTA", self.f_bcc), ("RESPOSTA PARA", self.f_reply)]:
            lbl = QLabel(label); lbl.setStyleSheet(lbl_style)
            row_w = QWidget(); rl = QHBoxLayout(row_w); rl.setContentsMargins(0,0,0,0); rl.setSpacing(4)
            copy_btn = QPushButton("⧉"); copy_btn.setObjectName("btn_icon"); copy_btn.setFixedSize(22,22)
            copy_btn.clicked.connect(lambda _, w=widget: QApplication.clipboard().setText(w.text()))
            rl.addWidget(copy_btn); rl.addWidget(widget)
            fl.addRow(lbl, row_w)

        att_lbl = QLabel("ANEXO"); att_lbl.setStyleSheet(lbl_style)
        att_row = QWidget(); arl = QHBoxLayout(att_row); arl.setContentsMargins(0,0,0,0); arl.setSpacing(4)
        btn_add_att = QPushButton("+"); btn_add_att.setObjectName("btn_icon"); btn_add_att.setFixedSize(22,22)
        btn_add_att.clicked.connect(self._add_att)
        self.att_combo = QComboBox(); self.att_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.att_combo.setContextMenuPolicy(Qt.CustomContextMenu)
        self.att_combo.customContextMenuRequested.connect(self._att_menu)
        arl.addWidget(btn_add_att); arl.addWidget(self.att_combo)
        fl.addRow(att_lbl, att_row)
        layout.addWidget(fields_widget)

        splitter = QSplitter(Qt.Horizontal)

        # Body container with toggle bar
        body_container = QWidget()
        body_container.setStyleSheet("background: #141414;")
        bcl = QVBoxLayout(body_container); bcl.setContentsMargins(0,0,0,0); bcl.setSpacing(0)

        # Toggle bar
        toggle_bar = QWidget()
        toggle_bar.setFixedHeight(30)
        toggle_bar.setStyleSheet("background: #0a0a0a; border-bottom: 1px solid #2a2a2a;")
        tgl = QHBoxLayout(toggle_bar); tgl.setContentsMargins(8,0,8,0); tgl.setSpacing(4)

        self.btn_view_html = QPushButton("🌐 Visual")
        self.btn_view_text = QPushButton("📄 Texto")
        self.btn_view_raw  = QPushButton("💻 Código")
        for btn in [self.btn_view_html, self.btn_view_text, self.btn_view_raw]:
            btn.setCheckable(True)
            btn.setStyleSheet("""
                QPushButton { background: transparent; color: #595959; border: none;
                    padding: 2px 10px; font-size: 11px; font-weight: 700; border-radius: 3px; }
                QPushButton:checked { background: #e50914; color: #fff; }
                QPushButton:hover { color: #e5e5e5; }
            """)
            tgl.addWidget(btn)
        tgl.addStretch()
        self.btn_view_html.setChecked(True)
        self.btn_view_html.clicked.connect(lambda: self._set_body_mode("html"))
        self.btn_view_text.clicked.connect(lambda: self._set_body_mode("text"))
        self.btn_view_raw.clicked.connect(lambda: self._set_body_mode("raw"))
        bcl.addWidget(toggle_bar)

        # Stacked body views
        from PyQt5.QtWidgets import QStackedWidget
        self.body_stack = QStackedWidget()

        # HTML view using QTextBrowser (renders HTML, no WebEngine needed)
        self.body_html_view = QTextBrowser()
        self.body_html_view.setOpenExternalLinks(True)
        self.body_html_view.setStyleSheet("background: #ffffff; border: none; color: #000; padding: 8px;")
        self.body_html_view.setZoomFactor(0.75)
        self.body_html_view.document().setDefaultStyleSheet(
            "body{font-size:11px;margin:0;padding:4px;}"
            "img{max-width:100%;height:auto;}"
            "table{max-width:100%;}"
        )

        # Plain text view
        self.body_edit = QTextEdit()
        self.body_edit.setFont(QFont("Consolas", 11))
        self.body_edit.setStyleSheet("background: #141414; border: none; color: #e5e5e5; padding: 16px;")

        # Raw HTML source view
        self.body_raw_view = QTextEdit()
        self.body_raw_view.setFont(QFont("Consolas", 10))
        self.body_raw_view.setStyleSheet("background: #0d0d0d; border: none; color: #50fa7b; padding: 16px;")
        self.body_raw_view.setReadOnly(True)

        self.body_stack.addWidget(self.body_html_view)  # index 0
        self.body_stack.addWidget(self.body_edit)        # index 1
        self.body_stack.addWidget(self.body_raw_view)    # index 2
        bcl.addWidget(self.body_stack)

        info_panel = QWidget(); info_panel.setFixedWidth(220)
        info_panel.setStyleSheet("background: #0a0a0a; border-left: 1px solid #2a2a2a;")
        ipl = QVBoxLayout(info_panel); ipl.setContentsMargins(12,12,12,12); ipl.setSpacing(0)

        def info_row(title, value="—", copyable=False, password=False):
            """Create an info row with title + value + optional copy button."""
            w = QWidget(); w.setStyleSheet("border-bottom: 1px solid #1a1a1a;")
            wl = QVBoxLayout(w); wl.setContentsMargins(0,6,0,6); wl.setSpacing(2)
            t = QLabel(title)
            t.setStyleSheet("color: #404040; font-size: 9px; font-weight: 700; letter-spacing: 1.5px;")
            row = QHBoxLayout(); row.setContentsMargins(0,0,0,0); row.setSpacing(4)
            v = QLabel(value)
            v.setStyleSheet("color: #c0c0c0; font-size: 11px; font-family: Consolas;")
            v.setWordWrap(True)
            row.addWidget(v, 1)
            if copyable:
                btn = QPushButton("⧉"); btn.setObjectName("btn_icon")
                btn.setFixedSize(18, 18); btn.setStyleSheet("font-size: 10px; border-radius: 3px;")
                btn.clicked.connect(lambda _, lbl=v: QApplication.clipboard().setText(lbl.text()))
                row.addWidget(btn)
            wl.addWidget(t); wl.addLayout(row)
            return w, v

        self.info_items = {}

        # Server
        w, self.info_items["server"] = info_row("SERVIDOR IMAP", copyable=True)
        ipl.addWidget(w)
        # Account email
        w, self.info_items["account"] = info_row("EMAIL DA CONTA", copyable=True)
        ipl.addWidget(w)
        # Password — shown with eye toggle
        pw_w = QWidget(); pw_w.setStyleSheet("border-bottom: 1px solid #1a1a1a;")
        pw_wl = QVBoxLayout(pw_w); pw_wl.setContentsMargins(0,6,0,6); pw_wl.setSpacing(2)
        pw_title = QLabel("SENHA")
        pw_title.setStyleSheet("color: #404040; font-size: 9px; font-weight: 700; letter-spacing: 1.5px;")
        pw_row = QHBoxLayout(); pw_row.setContentsMargins(0,0,0,0); pw_row.setSpacing(4)
        self.info_password = QLabel("••••••••")
        self.info_password.setStyleSheet("color: #c0c0c0; font-size: 11px; font-family: Consolas;")
        self._password_visible = False
        self._password_real = ""
        btn_eye = QPushButton("👁"); btn_eye.setObjectName("btn_icon")
        btn_eye.setFixedSize(18,18); btn_eye.setStyleSheet("font-size: 10px; border-radius: 3px;")
        def toggle_pw():
            self._password_visible = not self._password_visible
            self.info_password.setText(self._password_real if self._password_visible else "••••••••")
        btn_eye.clicked.connect(toggle_pw)
        btn_copy_pw = QPushButton("⧉"); btn_copy_pw.setObjectName("btn_icon")
        btn_copy_pw.setFixedSize(18,18); btn_copy_pw.setStyleSheet("font-size: 10px; border-radius: 3px;")
        btn_copy_pw.clicked.connect(lambda: QApplication.clipboard().setText(self._password_real))
        pw_row.addWidget(self.info_password, 1)
        pw_row.addWidget(btn_eye); pw_row.addWidget(btn_copy_pw)
        pw_wl.addWidget(pw_title); pw_wl.addLayout(pw_row)
        ipl.addWidget(pw_w)

        # EML file
        w, self.info_items["eml"] = info_row("ARQUIVO .EML", copyable=True)
        ipl.addWidget(w)
        # Date
        w, self.info_items["date"] = info_row("DATA/HORA")
        ipl.addWidget(w)
        # State
        w, self.info_items["state"] = info_row("ESTADO")
        ipl.addWidget(w)
        # Value
        w, self.info_items["value"] = info_row("VALOR")
        ipl.addWidget(w)
        # Due
        w, self.info_items["due"] = info_row("VENCIMENTO")
        ipl.addWidget(w)
        # Folder/inbox info
        w, self.info_items["folder_info"] = info_row("PASTA")
        ipl.addWidget(w)

        # Boleto frame
        self.boleto_frame = QFrame()
        self.boleto_frame.setStyleSheet("background: #1a0505; border: 1px solid #e50914; border-radius: 4px; margin-top: 8px;")
        bfl = QVBoxLayout(self.boleto_frame); bfl.setContentsMargins(8,8,8,8); bfl.setSpacing(4)
        bt = QLabel("📄 BOLETO DETECTADO")
        bt.setStyleSheet("color: #e50914; font-size: 9px; font-weight: 700; letter-spacing: 1.5px;")
        self.boleto_code_lbl = QLabel()
        self.boleto_code_lbl.setStyleSheet("color: #fff; font-size: 9px; font-family: Consolas;")
        self.boleto_code_lbl.setWordWrap(True)
        btn_copy_boleto = QPushButton("COPIAR CÓDIGO"); btn_copy_boleto.setObjectName("btn_red")
        btn_copy_boleto.clicked.connect(lambda: QApplication.clipboard().setText(self.boleto_code_lbl.text()))
        bfl.addWidget(bt); bfl.addWidget(self.boleto_code_lbl); bfl.addWidget(btn_copy_boleto)
        self.boleto_frame.setVisible(False)
        ipl.addWidget(self.boleto_frame)
        ipl.addStretch()

        splitter.addWidget(body_container); splitter.addWidget(info_panel)
        splitter.setSizes([800, 220])
        layout.addWidget(splitter)

    def _set_body_mode(self, mode):
        """Switch between HTML visual, plain text, and raw HTML source."""
        self.btn_view_html.setChecked(mode == "html")
        self.btn_view_text.setChecked(mode == "text")
        self.btn_view_raw.setChecked(mode == "raw")
        if mode == "html":
            self.body_stack.setCurrentIndex(0)
        elif mode == "text":
            self.body_stack.setCurrentIndex(1)
        else:
            self.body_stack.setCurrentIndex(2)

    def _load(self):
        d = self.data
        self.f_subject.setText(d.get("subject",""))
        self.f_from.setText(d.get("sender",""))
        self.f_to.setText(d.get("to",""))

        body_text = d.get("body","")
        body_html = d.get("body_html","")

        # Plain text
        self.body_edit.setPlainText(body_text)

        # HTML visual — prefer HTML, fallback to text
        if body_html and body_html.strip():
            self.body_html_view.setHtml(body_html)
        elif body_text:
            # Convert plain text to simple HTML preserving line breaks
            html_fallback = "<pre style='font-family:Arial;font-size:13px;white-space:pre-wrap;'>" + body_text.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;") + "</pre>"
            self.body_html_view.setHtml(html_fallback)

        # Raw HTML source
        self.body_raw_view.setPlainText(body_html or body_text)

        # Default: show HTML visual if available, else plain text
        if body_html and body_html.strip():
            self._set_body_mode("html")
        else:
            self._set_body_mode("text")
        acc_email = d.get("account","")
        self.lbl_account.setText(acc_email)

        # Find account info from config to get server + password
        acc_info = {}
        for acc in self.cfg.get("accounts",[]):
            if acc.get("email","") == acc_email:
                acc_info = acc; break

        # Populate right panel
        server = acc_info.get("imap_server","") or (acc_email.split("@")[-1] if "@" in acc_email else "—")
        self.info_items["server"].setText(server)
        self.info_items["account"].setText(acc_email or "—")

        # Password with eye toggle
        pw = acc_info.get("password","")
        self._password_real = pw
        self._password_visible = False
        self.info_password.setText("••••••••" if pw else "—")

        # EML filename
        uid = d.get("uid","")
        folder = d.get("folder","INBOX")
        eml_name = f"{acc_email}.{uid}.eml" if acc_email and uid else "—"
        self.info_items["eml"].setText(eml_name)

        # Date formatted
        date_raw = d.get("date","") or ""
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(date_raw).replace(tzinfo=None)
            date_fmt = f"[ {folder} ][ {dt.strftime('%d/%m/%Y %H:%M:%S')} ]"
        except:
            date_fmt = f"[ {folder} ][ {date_raw[:19]} ]"
        self.info_items["date"].setText(date_fmt)

        state = d.get("state","—")
        self.info_items["state"].setText(f"[ {state} ]")
        self.info_items["value"].setText(d.get("value","—") or "—")
        self.info_items["due"].setText(d.get("due_date","—") or "—")
        self.info_items["folder_info"].setText(folder)

        if d.get("boleto_code"):
            self.boleto_code_lbl.setText(d["boleto_code"])
            self.boleto_frame.setVisible(True)
        else:
            self.boleto_frame.setVisible(False)
        self._refresh_att()

    def _refresh_att(self):
        self.att_combo.clear()
        for att in self.att_files:
            self.att_combo.addItem(att.get("name","") if isinstance(att,dict) else str(att))

    def _add_att(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Adicionar Anexo")
        for f in files: self.att_files.append({"name": os.path.basename(f), "path": f})
        self._refresh_att()

    # Quando frozen (EXE), _MEIPASS é onde o PyInstaller extrai os arquivos bundled
    _MEIPASS   = getattr(sys, '_MEIPASS', None)
    _EXE_DIR   = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) \
                 else os.path.dirname(os.path.abspath(__file__))

    # Paths where PDFEdit.exe can be found (checks in order)
    PDF_EDITOR_PATHS = [
        os.path.join(_MEIPASS,  "Fox", "PDFEdit.exe") if _MEIPASS else "",
        os.path.join(_EXE_DIR,  "Fox", "PDFEdit.exe"),
        os.path.join(_EXE_DIR,  "PDFEdit.exe"),
    ]

    def _find_pdf_editor(self):
        # Check config first
        editor = self.cfg.get("pdf_editor_path","")
        if editor and os.path.exists(editor): return editor
        for p in self.PDF_EDITOR_PATHS:
            if os.path.exists(p): return p
        return None

    def _att_menu(self, pos):
        if self.att_combo.count() == 0: return
        idx = self.att_combo.currentIndex()
        att = self.att_files[idx] if 0 <= idx < len(self.att_files) else None
        is_pdf = att and att.get("name","").lower().endswith(".pdf") if att else False
        menu = QMenu(self)
        menu.addAction("👁  Visualizar", lambda: self._view_att(att))
        if is_pdf:
            menu.addAction("✏️  Editar PDF (PDFEdit)", lambda: self._edit_pdf(idx))
            menu.addAction("📄  Editar Boleto (linha/valor/data)", lambda: self._edit_boleto(idx))
        menu.addAction("✏️  Renomear", lambda: self._rename_att(idx))
        menu.addAction("🔄  Alterar Anexo", lambda: self._edit_or_replace(idx))
        menu.addAction("❌  Remover Anexo", lambda: self._remove_att(idx))
        menu.addSeparator()
        menu.addAction("💾  Salvar Arquivo", lambda: self._save_att(att))
        menu.addAction("📁  Abrir Pasta", lambda: self._open_folder(att))
        menu.addAction("📋  Copiar Nome", lambda: QApplication.clipboard().setText(att.get("name","") if att else ""))
        menu.addAction("🔄  Substituir por Outro Arquivo", lambda: self._replace_att(idx))
        menu.exec_(self.att_combo.mapToGlobal(pos))

    def _edit_or_replace(self, idx):
        """Alterar Anexo — se for PDF abre no PDFEdit, senão abre dialogo de arquivo."""
        if idx < 0 or idx >= len(self.att_files): return
        att = self.att_files[idx]
        if att.get("name","").lower().endswith(".pdf"):
            self._edit_pdf(idx)
        else:
            self._replace_att(idx)

    def _edit_pdf(self, idx):
        """Open PDF in PDFEdit.exe, wait for close, reload the file."""
        if idx < 0 or idx >= len(self.att_files): return
        att = self.att_files[idx]

        # First ensure file is saved to disk
        self._auto_save_att(att)
        path = att.get("path","")

        if not path or not os.path.exists(path):
            QMessageBox.warning(self, "Zeus", "Não foi possível salvar o arquivo temporariamente.")
            return

        # Find PDF editor
        editor = self._find_pdf_editor()
        if not editor:
            # Ask user to locate it
            _start = self._EXE_DIR
            editor, _ = QFileDialog.getOpenFileName(self, "Localizar PDFEdit.exe", _start,
                                                     "Executáveis (*.exe)")
            if not editor: return
            self.cfg["pdf_editor_path"] = editor
            save_config(self.cfg)

        # Get file modification time before opening
        mtime_before = os.path.getmtime(path)

        try:
            import subprocess
            proc = subprocess.Popen([editor, path])
            # Show waiting dialog
            wait_dlg = QDialog(self)
            wait_dlg.setWindowTitle("Zeus — Editando PDF")
            wait_dlg.setFixedSize(360, 140)
            wl = QVBoxLayout(wait_dlg)
            wl.setContentsMargins(24,24,24,24); wl.setSpacing(12)
            lbl = QLabel(f"📝  Editando: {att.get('name','')}")
            lbl.setStyleSheet("color: #ffffff; font-size: 13px; font-weight: 600;")
            sub = QLabel("Edite o PDF e feche o PDFEdit para continuar.")
            sub.setStyleSheet("color: #a3a3a3; font-size: 12px;")
            btn_done = QPushButton("✅  JÁ FECHEI O EDITOR"); btn_done.setObjectName("btn_red")
            btn_done.clicked.connect(wait_dlg.accept)
            btn_cancel = QPushButton("CANCELAR"); btn_cancel.setObjectName("btn_ghost")
            btn_cancel.clicked.connect(wait_dlg.reject)
            btns = QHBoxLayout()
            btns.addWidget(btn_cancel); btns.addWidget(btn_done)
            wl.addWidget(lbl); wl.addWidget(sub); wl.addLayout(btns)
            wait_dlg.exec_()

            # Check if file was modified
            if os.path.exists(path):
                mtime_after = os.path.getmtime(path)
                if mtime_after > mtime_before:
                    att["path"] = path
                    QMessageBox.information(self, "Zeus", "✅ Anexo atualizado com as edições!")
                else:
                    QMessageBox.information(self, "Zeus", "Nenhuma alteração detectada no arquivo.")
        except Exception as e:
            QMessageBox.critical(self, "Zeus", f"Erro ao abrir PDFEdit:\n{e}")

    def _edit_boleto(self, idx):
        """Open boleto PDF editor dialog."""
        if idx < 0 or idx >= len(self.att_files): return
        att = self.att_files[idx]
        # Ensure PDF is saved to disk first
        self._auto_save_att(att)
        dlg = BoletoPDFEditor(att, self.cfg, self)
        if dlg.exec_() and dlg.result_bytes:
            # Update attachment with new bytes
            att["pdf_bytes"] = dlg.result_bytes
            QMessageBox.information(self, "Zeus",
                "✅ Boleto editado!\nO PDF foi atualizado com os novos valores.")

    def _view_att(self, att):
        if not att: return
        path = att.get("path","")
        if path and os.path.exists(path): os.startfile(path)
        else:
            self._auto_save_att(att)
            if att.get("path") and os.path.exists(att["path"]): os.startfile(att["path"])

    def _auto_save_att(self, att):
        if not att or att.get("path"): return
        part = att.get("part")
        if not part: return
        dl = self.cfg.get("download_path", os.path.expanduser("~"))
        os.makedirs(dl, exist_ok=True)
        fpath = os.path.join(dl, att.get("name","arquivo"))
        try:
            data = part.get_payload(decode=True)
            if data:
                with open(fpath,"wb") as f: f.write(data)
                att["path"] = fpath
        except: pass

    def _rename_att(self, idx):
        if idx < 0: return
        old = self.att_files[idx].get("name","")
        new, ok = QInputDialog.getText(self, "Renomear Anexo", "Novo nome:", text=old)
        if ok and new:
            self.att_files[idx]["name"] = new
            self._refresh_att()

    def _replace_att(self, idx):
        if idx < 0: return
        f, _ = QFileDialog.getOpenFileName(self, "Substituir Anexo")
        if f:
            self.att_files[idx] = {"name": os.path.basename(f), "path": f}
            self._refresh_att()

    def _remove_att(self, idx):
        if 0 <= idx < len(self.att_files):
            self.att_files.pop(idx)
            self._refresh_att()

    def _save_att(self, att):
        if not att: return
        self._auto_save_att(att)
        dest, _ = QFileDialog.getSaveFileName(self, "Salvar Anexo", att.get("name","arquivo"))
        if dest:
            src = att.get("path","")
            if src and os.path.exists(src): shutil.copy(src, dest)

    def _open_folder(self, att):
        path = att.get("path","") if att else ""
        folder = os.path.dirname(path) if path and os.path.exists(path) else self.cfg.get("download_path", os.path.expanduser("~"))
        if os.path.exists(folder): os.startfile(folder)

    def _agendar_boleto(self):
        """Schedule boleto from current email directly to Agendados tab."""
        d = self.data
        boleto_code = d.get("boleto_code","")
        value       = d.get("value","")
        due_date    = d.get("due_date","")
        subject     = d.get("subject","")

        # Try to get boleto from attachment if not in body
        if not boleto_code:
            for att in self.att_files:
                name = att.get("name","").lower()
                if name.endswith(".pdf"):
                    boleto_code = f"[PDF: {att.get('name','')}]"
                    break

        # Open schedule dialog pre-filled
        from PyQt5.QtWidgets import QDialog, QFormLayout, QDialogButtonBox
        dlg = QDialog(self); dlg.setWindowTitle("Agendar Boleto"); dlg.setMinimumWidth(440)
        layout = QVBoxLayout(dlg); layout.setContentsMargins(20,20,20,20); layout.setSpacing(12)
        title_lbl = QLabel("📅 AGENDAR BOLETO")
        title_lbl.setStyleSheet("color:#fff;font-size:16px;font-weight:900;")
        layout.addWidget(title_lbl)
        lbl_s = "color:#a3a3a3;font-size:10px;font-weight:700;letter-spacing:1px;"
        form = QFormLayout(); form.setSpacing(10)
        f_desc  = QLineEdit(subject[:50] if subject else "")
        f_code  = QLineEdit(boleto_code)
        f_code.setFont(QFont("Consolas",9))
        f_value = QLineEdit(value)
        f_due   = QLineEdit(due_date)
        f_sched = QLineEdit(datetime.now().strftime("%d/%m/%Y %H:%M"))
        for lbl, w in [("DESCRIÇÃO",f_desc),("CÓDIGO DO BOLETO",f_code),
                        ("VALOR",f_value),("VENCIMENTO",f_due),("AGENDAR PARA",f_sched)]:
            form.addRow(QLabel(lbl), w)
            form.labelForField(w).setStyleSheet(lbl_s)
        layout.addLayout(form)
        btns = QHBoxLayout()
        btn_ok = QPushButton("AGENDAR"); btn_ok.setObjectName("btn_red"); btn_ok.clicked.connect(dlg.accept)
        btn_cancel = QPushButton("CANCELAR"); btn_cancel.setObjectName("btn_ghost"); btn_cancel.clicked.connect(dlg.reject)
        btns.addStretch(); btns.addWidget(btn_cancel); btns.addWidget(btn_ok)
        layout.addLayout(btns)

        if dlg.exec_():
            # Find main window and add to schedules
            main_win = self.window()
            if hasattr(main_win, 'schedules'):
                main_win.schedules.append({
                    "desc": f_desc.text(),
                    "code": f_code.text(),
                    "value": f_value.text(),
                    "due": f_due.text(),
                    "scheduled_for": f_sched.text(),
                    "paid": False
                })
                main_win.cfg["schedules"] = main_win.schedules
                save_config(main_win.cfg)
                main_win._refresh_scheduled()
                QMessageBox.information(self, "Zeus",
                    f"Boleto agendado!\nVer em: aba AGENDADOS")
            else:
                QMessageBox.information(self, "Zeus", "Boleto agendado!")

    def _save(self):
        """Save edits — rebuilds raw email bytes with modified headers."""
        import email as email_mod
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.base import MIMEBase
        from email import encoders as email_encoders

        try:
            raw = self.data.get("raw")
            if raw:
                # Parse existing email and patch headers
                msg = email_mod.message_from_bytes(raw if isinstance(raw, bytes) else raw.encode())
                # Update headers with edited values
                if "From" in msg: del msg["From"]
                if "To" in msg: del msg["To"]
                if "Subject" in msg: del msg["Subject"]
                if "Cc" in msg: del msg["Cc"]
                if "Reply-To" in msg: del msg["Reply-To"]
                msg["From"]     = self.f_from.text()
                msg["To"]       = self.f_to.text()
                msg["Subject"]  = self.f_subject.text()
                if self.f_cc.text():   msg["Cc"]       = self.f_cc.text()
                if self.f_reply.text(): msg["Reply-To"] = self.f_reply.text()
                # Update body text
                for part in msg.walk():
                    ct = part.get_content_type()
                    cd = str(part.get("Content-Disposition",""))
                    if ct == "text/plain" and "attachment" not in cd:
                        try:
                            part.set_payload(self.body_edit.toPlainText().encode("utf-8"), charset="utf-8")
                        except: pass
                        break
                # Save back raw bytes
                new_raw = msg.as_bytes()
                self.data["raw"] = new_raw
            # Update data dict
            self.data["subject"] = self.f_subject.text()
            self.data["sender"]  = self.f_from.text()
            self.data["to"]      = self.f_to.text()
            self.data["body"]    = self.body_edit.toPlainText()
            QMessageBox.information(self, "Zeus", "Alterações salvas! Ao devolver, o email será enviado com os novos dados.")
        except Exception as e:
            QMessageBox.critical(self, "Zeus", f"Erro ao salvar: {e}")
    def _delete(self):
        if QMessageBox.question(self, "Zeus", "Excluir este email?") == QMessageBox.Yes:
            QMessageBox.information(self, "Zeus", "Email excluído!")
    def _return_inbox(self):
        d = self.data
        acc_email = d.get("account","")
        uid = d.get("uid","")
        folder = d.get("folder","")

        if not acc_email:
            QMessageBox.warning(self, "Zeus", "Email sem conta associada."); return

        acc_info = next((a for a in self.cfg.get("accounts",[]) if a.get("email","") == acc_email), None)
        if not acc_info:
            QMessageBox.warning(self, "Zeus", f"Conta {acc_email} nao encontrada."); return

        # Get edited values from fields
        from_field  = self.f_from.text().strip() or acc_email
        to_field    = self.f_to.text().strip()
        subj_field  = self.f_subject.text().strip()
        body_field  = self.body_edit.toPlainText()
        original_folder = d.get("original_folder") or folder or "INBOX"

        # Parse From: "Nome <email>" or just email
        import re as _re
        m = _re.match(r'^(.*?)<(.+?)>$', from_field)
        if m:
            from_name  = m.group(1).strip().strip('"')
            from_email_addr = m.group(2).strip()
        else:
            from_name  = from_field
            from_email_addr = acc_email

        try:
            # Step 1: Get the REAL raw email from server (guaranteed correct)
            raw = d.get("raw")
            if not raw:
                self._status_label = QLabel("Buscando email no servidor...")
                try:
                    imap = connect_imap(acc_info)
                    for try_folder in [folder, "Processados", "INBOX",
                                       original_folder]:
                        try:
                            imap.select(try_folder)
                            uid_b = uid.encode() if isinstance(uid,str) else uid
                            _, data2 = imap.fetch(uid_b, "(RFC822)")
                            if data2 and data2[0] and isinstance(data2[0],tuple):
                                raw = data2[0][1]
                                folder = try_folder
                                break
                        except: pass
                    imap.logout()
                except: pass

            if not raw:
                QMessageBox.warning(self,"Zeus",
                    "Email nao encontrado no servidor.\n"
                    "O email precisa estar na pasta de origem para ser devolvido.")
                return

            # Step 2: Send via SMTP using REAL raw as base
            try:
                sent_raw = send_via_smtp(
                    acc_info, from_name, from_email_addr,
                    to_field, subj_field, body_field, d.get("body_html",""),
                    self.att_files, self.cfg,
                    delete_uid=uid, delete_folder=folder,
                    raw_original=raw
                )
                method = "SMTP"
            except Exception as smtp_err:
                # Fallback: IMAP APPEND
                import email as _em
                msg = _em.message_from_bytes(
                    raw if isinstance(raw,bytes) else raw.encode())
                for h in ["From","To","Subject"]:
                    if h in msg: del msg[h]
                msg["From"]    = f"{from_name} <{from_email_addr}>"
                msg["To"]      = to_field
                msg["Subject"] = subj_field
                sent_raw = msg.as_bytes()
                method = "IMAP APPEND"
                imap2 = connect_imap(acc_info)
                imap2.append(original_folder, None, None, sent_raw)
                # Remove from current folder
                if folder and folder.upper() != original_folder.upper():
                    try:
                        imap2.select(folder)
                        uid_b = uid.encode() if isinstance(uid,str) else uid
                        imap2.store(uid_b, '+FLAGS', '\\Deleted')
                        imap2.expunge()
                    except: pass
                imap2.logout()

            # Mark as seen so monitor won't re-capture
            raw_cache = load_uid_cache()
            key = f"{acc_email}:{original_folder}"
            if key not in raw_cache: raw_cache[key] = []
            if uid and uid not in raw_cache[key]: raw_cache[key].append(uid)
            save_uid_cache(raw_cache)

            QMessageBox.information(self, "Zeus",
                f"Email enviado via {method}!\nDe: {from_name} <{from_email_addr}>\nPara: {to_field}")
        except Exception as e:
            QMessageBox.critical(self, "Zeus", f"Erro: {e}")


# ── Accounts Monitor Panel ────────────────────────────────────────────────────
class MonitorPanel(QWidget):
    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.monitors = {}
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        hdr = QHBoxLayout()
        title = QLabel("CONTAS MONITORADAS")
        title.setStyleSheet("color: #ffffff; font-size: 18px; font-weight: 900;")
        hdr.addWidget(title)
        hdr.addStretch()
        self.lbl_active = QLabel("0 ativas")
        self.lbl_active.setStyleSheet("color: #2ecc40; font-size: 12px; font-weight: 700;")
        hdr.addWidget(self.lbl_active)
        layout.addLayout(hdr)

        self.acc_table = QTableWidget()
        self.acc_table.setColumnCount(5)
        self.acc_table.setHorizontalHeaderLabels(["EMAIL", "SERVIDOR", "STATUS", "EMAILS", ""])
        self.acc_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.acc_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.acc_table.setColumnWidth(4, 36)
        self.acc_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Fixed)
        self.acc_table.verticalHeader().setVisible(False)
        self.acc_table.setShowGrid(False)
        self.acc_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.acc_table)
        self._remove_callback = None  # set by main window

    def set_remove_callback(self, cb):
        self._remove_callback = cb

    def _make_trash_btn(self, email_addr, auth_failed=False):
        btn = QPushButton("🗑")
        btn.setFixedSize(28, 28)
        if auth_failed:
            btn.setStyleSheet("QPushButton { background: #e50914; color: #fff; border: none; border-radius: 4px; font-size: 13px; } QPushButton:hover { background: #ff2020; }")
            btn.setToolTip(f"Senha incorreta — clique para remover {email_addr}")
        else:
            btn.setStyleSheet("QPushButton { background: transparent; color: #595959; border: 1px solid #2a2a2a; border-radius: 4px; font-size: 13px; } QPushButton:hover { background: #e50914; color: #fff; border-color: #e50914; }")
            btn.setToolTip(f"Remover {email_addr}")
        btn.clicked.connect(lambda: self._remove_callback(email_addr) if self._remove_callback else None)
        w = QWidget(); l = QHBoxLayout(w); l.setContentsMargins(2,2,2,2); l.addWidget(btn)
        return w

    def refresh(self, accounts, monitors):
        self.acc_table.setRowCount(0)
        active = 0
        for acc in accounts:
            row = self.acc_table.rowCount()
            self.acc_table.insertRow(row)
            self.acc_table.setRowHeight(row, 36)
            em = acc["email"]
            mon = monitors.get(em)
            auth_failed = False
            status = "⏸ Parado"; color = "#595959"
            if mon and mon.isRunning():
                status = "✅ Ativo"; color = "#2ecc40"; active += 1

            self.acc_table.setItem(row, 0, QTableWidgetItem(em))
            self.acc_table.setItem(row, 1, QTableWidgetItem(acc.get("imap_server","")))
            status_item = QTableWidgetItem(status)
            status_item.setForeground(QColor(color))
            self.acc_table.setItem(row, 2, status_item)
            self.acc_table.setItem(row, 3, QTableWidgetItem("0"))
            self.acc_table.setCellWidget(row, 4, self._make_trash_btn(em, auth_failed))
        self.lbl_active.setText(f"{active} ativa(s)")

    def update_status(self, email_addr, status, accounts):
        for row in range(self.acc_table.rowCount()):
            item = self.acc_table.item(row, 0)
            if item and item.text() == email_addr:
                status_item = self.acc_table.item(row, 2)
                if not status_item: break
                status_item.setText(status)
                auth_fail = any(x in status for x in ["Senha", "🔴", "AUTHEN"])
                if "✅" in status or "Conectado" in status:
                    color = "#2ecc40"
                elif auth_fail or "❌" in status:
                    color = "#e50914"
                    font = QFont("Arial", 9); font.setStrikeOut(auth_fail)
                    status_item.setFont(font)
                    # Make trash button red immediately
                    self.acc_table.setCellWidget(row, 4,
                        self._make_trash_btn(email_addr, auth_failed=True))
                elif "⏳" in status or "s" in status[-3:]:
                    color = "#404040"
                else:
                    color = "#e5a010"
                status_item.setForeground(QColor(color))
                break

# ── Settings Widget ───────────────────────────────────────────────────────────
class SettingsWidget(QWidget):
    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self._build()

    def _lbl(self, text, style=""):
        l = QLabel(text); l.setStyleSheet(style); return l

    def _build(self):
        from PyQt5.QtWidgets import QTabWidget, QDoubleSpinBox
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0,0,0,0); layout.setSpacing(0)

        hdr_bar = QWidget(); hdr_bar.setStyleSheet("background:#0a0a0a;border-bottom:1px solid #2a2a2a;")
        hdr_bar.setFixedHeight(50)
        hbl = QHBoxLayout(hdr_bar); hbl.setContentsMargins(24,0,16,0); hbl.setSpacing(12)
        hdr_lbl = QLabel("CONFIGURAÇÕES")
        hdr_lbl.setStyleSheet("color:#ffffff;font-size:18px;font-weight:900;letter-spacing:-0.5px;")
        hbl.addWidget(hdr_lbl); hbl.addStretch()
        btn_save = QPushButton("SALVAR CONFIGURAÇÕES"); btn_save.setObjectName("btn_red")
        btn_save.setFixedHeight(32); btn_save.clicked.connect(self._save)
        hbl.addWidget(btn_save)
        layout.addWidget(hdr_bar)

        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane { border:none; background:#141414; }
            QTabBar::tab { background:#0d0d0d; color:#595959; padding:10px 20px; border:none;
                border-bottom:2px solid transparent; font-size:10px; font-weight:700;
                letter-spacing:1px; min-width:80px; }
            QTabBar::tab:selected { color:#ffffff; border-bottom:2px solid #e50914; background:#141414; }
            QTabBar::tab:hover { color:#cccccc; background:#111111; }
        """)
        layout.addWidget(tabs)

        lbl_s = "color: #a3a3a3; font-size: 10px; font-weight: 700; letter-spacing: 1px;"

        def _make_tab():
            inner = QWidget(); inner.setStyleSheet("background:#141414;")
            il = QVBoxLayout(inner); il.setContentsMargins(28,20,28,24); il.setSpacing(18)
            sc = QScrollArea(); sc.setWidgetResizable(True); sc.setStyleSheet("border:none;")
            sc.setWidget(inner)
            return sc, il

        # ── CONTAS ────────────────────────────────────────────────────────────
        sc1, l1 = _make_tab()
        acc_group = QGroupBox("CONTAS DE EMAIL")
        agl = QVBoxLayout(acc_group)
        self.acc_list = QListWidget(); self.acc_list.setMaximumHeight(180)
        self._refresh_acc_list()
        acc_btns = QHBoxLayout()
        for label, obj, slot in [("+ ADICIONAR","btn_red",self._add_acc),
                                   ("✏ EDITAR","btn_ghost",self._edit_acc),
                                   ("✕ REMOVER","btn_ghost",self._del_acc)]:
            btn = QPushButton(label); btn.setObjectName(obj); btn.clicked.connect(slot)
            acc_btns.addWidget(btn)
        acc_btns.addStretch()
        agl.addWidget(self.acc_list); agl.addLayout(acc_btns)
        l1.addWidget(acc_group); l1.addStretch()
        tabs.addTab(sc1, "CONTAS")

        # ── MONITORAMENTO ─────────────────────────────────────────────────────
        sc2, l2 = _make_tab()

        opt_group = QGroupBox("OPÇÕES DE CAPTURA")
        ogl = QFormLayout(opt_group); ogl.setSpacing(10)
        self.chk_boleto = QCheckBox("Capturar APENAS emails com boleto")
        self.chk_boleto.setChecked(self.cfg.get("only_boleto", True))
        self.chk_boleto.setStyleSheet("color: #e50914; font-weight: 700;")
        self.chk_unread = QCheckBox("Incluir emails já lidos (até X dias atrás)")
        self.chk_unread.setChecked(not self.cfg.get("only_unread", False))
        self.chk_att = QCheckBox("Somente emails com anexo")
        self.chk_att.setChecked(self.cfg.get("only_attachment", False))
        self.spin_days = QSpinBox(); self.spin_days.setRange(1,30); self.spin_days.setValue(self.cfg.get("max_days_old",4))
        self.spin_min_val = QDoubleSpinBox()
        self.spin_min_val.setRange(0, 999999); self.spin_min_val.setValue(float(self.cfg.get("min_value", 500.0)))
        self.spin_min_val.setPrefix("R$ "); self.spin_min_val.setDecimals(2)
        self.combo_after = QComboBox()
        self.combo_after.addItems(["Não fazer nada", "Mover para 'Processados'", "Apagar do servidor"])
        after_map = {"nothing":0,"move":1,"delete":2}
        self.combo_after.setCurrentIndex(after_map.get(self.cfg.get("after_capture","delete"),2))
        self.combo_after.setStyleSheet("color: #e50914; font-weight: 700;")
        for w in [self.chk_boleto, self.chk_unread, self.chk_att]: ogl.addRow(w)
        ogl.addRow(self._lbl("VALOR MÍNIMO DO BOLETO:", lbl_s), self.spin_min_val)
        ogl.addRow(self._lbl("MÁXIMO DE DIAS ATRÁS:", lbl_s), self.spin_days)
        ogl.addRow(self._lbl("APÓS CAPTURAR O EMAIL:", lbl_s), self.combo_after)
        l2.addWidget(opt_group)

        cycle_group = QGroupBox("CICLO DE LEITURA")
        cgl = QFormLayout(cycle_group); cgl.setSpacing(10)
        self.spin_max = QSpinBox(); self.spin_max.setRange(1,500); self.spin_max.setValue(self.cfg.get("max_emails",100))
        self.spin_interval = QSpinBox(); self.spin_interval.setRange(10,3600); self.spin_interval.setValue(self.cfg.get("cycle_interval",60))
        self.spin_threads = QSpinBox(); self.spin_threads.setRange(1,9999); self.spin_threads.setValue(self.cfg.get("max_threads",5))
        self.spin_threads.setToolTip("Quantas contas conectar ao mesmo tempo (sem limite)")
        self.spin_monitor_accounts = QSpinBox()
        self.spin_monitor_accounts.setRange(0, 99999); self.spin_monitor_accounts.setValue(self.cfg.get("monitor_accounts", 0))
        self.spin_monitor_accounts.setSpecialValueText("Todas")
        self.spin_monitor_accounts.setToolTip("Quantas contas do total monitorar (0 = todas)")
        self.spin_per_read = QSpinBox(); self.spin_per_read.setRange(1,100); self.spin_per_read.setValue(self.cfg.get("emails_per_read",5))
        self.spin_per_read.setToolTip("Quantos emails processar por conta a cada rodada.")
        self.chk_alternate = QCheckBox("Alternar entre contas (recomendado)")
        self.chk_alternate.setChecked(self.cfg.get("alternate_accounts",True))
        self.chk_alternate.setStyleSheet("color: #2ecc40; font-weight: 700;")
        cgl.addRow(self._lbl("MÁX. EMAILS POR PASTA:", lbl_s), self.spin_max)
        cgl.addRow(self._lbl("INTERVALO DE LEITURA (seg):", lbl_s), self.spin_interval)
        cgl.addRow(self._lbl("SIMULTÂNEAS (por rodada):", lbl_s), self.spin_threads)
        cgl.addRow(self._lbl("TOTAL A MONITORAR (0=todas):", lbl_s), self.spin_monitor_accounts)
        cgl.addRow(self._lbl("LER E-MAILS (por rodada/conta):", lbl_s), self.spin_per_read)
        cgl.addRow(self.chk_alternate)
        l2.addWidget(cycle_group)

        folder_group = QGroupBox("PASTAS PARA MONITORAR")
        fgl = QVBoxLayout(folder_group)
        fgl.addWidget(QLabel("Uma pasta por linha:"))
        self.folder_edit = QTextEdit()
        self.folder_edit.setPlainText("\n".join(self.cfg.get("folders",["INBOX"])))
        self.folder_edit.setMaximumHeight(90)
        fgl.addWidget(self.folder_edit)
        l2.addWidget(folder_group)

        path_group = QGroupBox("PASTA DE DOWNLOAD")
        pgl = QHBoxLayout(path_group)
        self.path_edit = QLineEdit(self.cfg.get("download_path",""))
        btn_browse = QPushButton("..."); btn_browse.setObjectName("btn_ghost"); btn_browse.setFixedWidth(48)
        btn_browse.clicked.connect(lambda: self.path_edit.setText(
            QFileDialog.getExistingDirectory(self,"Pasta de Download") or self.path_edit.text()))
        pgl.addWidget(self.path_edit); pgl.addWidget(btn_browse)
        l2.addWidget(path_group); l2.addStretch()
        tabs.addTab(sc2, "MONITORAMENTO")

        # ── FILTROS ───────────────────────────────────────────────────────────
        sc3, l3 = _make_tab()

        ext_group = QGroupBox("EXTENSÕES DE ARQUIVO")
        egl = QVBoxLayout(ext_group)
        egl.addWidget(QLabel("Uma extensão por linha (ex: .pdf):"))
        self.ext_edit = QTextEdit()
        self.ext_edit.setPlainText("\n".join(self.cfg.get("extensions",[])))
        self.ext_edit.setMaximumHeight(90)
        egl.addWidget(self.ext_edit)
        l3.addWidget(ext_group)

        kw_group = QGroupBox("FILTROS POR PALAVRAS-CHAVE NO ASSUNTO")
        kgl = QVBoxLayout(kw_group); kgl.setSpacing(8)
        kgl.addWidget(self._lbl("QUE CONTÉM NO ASSUNTO (uma por linha):", lbl_s))
        self.kw_include_edit = QTextEdit()
        self.kw_include_edit.setPlainText("\n".join(self.cfg.get("keywords_include",[])))
        self.kw_include_edit.setMaximumHeight(120)
        self.kw_include_edit.setStyleSheet("background: #0d1a0d; border: 1px solid #2a4a2a; color: #a6e3a1;")
        kgl.addWidget(self.kw_include_edit)
        kgl.addWidget(self._lbl("QUE NÃO CONTÉM NO ASSUNTO (uma por linha):", lbl_s))
        self.kw_exclude_edit = QTextEdit()
        self.kw_exclude_edit.setPlainText("\n".join(self.cfg.get("keywords_exclude",[])))
        self.kw_exclude_edit.setMaximumHeight(80)
        self.kw_exclude_edit.setStyleSheet("background: #1a0d0d; border: 1px solid #4a2a2a; color: #f38ba8;")
        kgl.addWidget(self.kw_exclude_edit)
        l3.addWidget(kw_group); l3.addStretch()
        tabs.addTab(sc3, "FILTROS")

        # ── AVANÇADO ──────────────────────────────────────────────────────────
        sc4, l4 = _make_tab()

        smtp_group = QGroupBox("SERVIDOR SMTP (para envio com remetente personalizado)")
        smtpl = QFormLayout(smtp_group); smtpl.setSpacing(8)
        lbl_s2 = "color: #a3a3a3; font-size: 10px; font-weight: 700; letter-spacing: 1px;"
        self.smtp_host_edit = QLineEdit(self.cfg.get("custom_smtp_host",""))
        self.smtp_host_edit.setPlaceholderText("Ex: smtp.terra.com.br (deixe vazio para auto-detectar)")
        self.smtp_port_edit = QLineEdit(str(self.cfg.get("custom_smtp_port","587")))
        smtpl.addRow(self._lbl("SERVIDOR SMTP:", lbl_s2), self.smtp_host_edit)
        smtpl.addRow(self._lbl("PORTA SMTP:", lbl_s2), self.smtp_port_edit)
        l4.addWidget(smtp_group)

        pdf_group = QGroupBox("EDITOR DE PDF (PDFEdit.exe)")
        pdfl = QHBoxLayout(pdf_group)
        self.pdf_edit = QLineEdit(self.cfg.get("pdf_editor_path", ""))
        btn_pdf_browse = QPushButton("..."); btn_pdf_browse.setObjectName("btn_ghost"); btn_pdf_browse.setFixedWidth(48)
        _pdf_start = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.expanduser("~")
        btn_pdf_browse.clicked.connect(lambda: self.pdf_edit.setText(
            QFileDialog.getOpenFileName(self, "Localizar PDFEdit.exe", _pdf_start, "Executáveis (*.exe)")[0]
            or self.pdf_edit.text()))
        pdfl.addWidget(self.pdf_edit); pdfl.addWidget(btn_pdf_browse)
        l4.addWidget(pdf_group); l4.addStretch()
        tabs.addTab(sc4, "AVANÇADO")

    def _refresh_acc_list(self):
        self.acc_list.clear()
        for acc in self.cfg.get("accounts",[]):
            self.acc_list.addItem(f"  {acc.get('name','')}  ‹{acc.get('email','')}›  [{acc.get('imap_server','')}]")

    def _add_acc(self):
        dlg = AccountDialog(self)
        if dlg.exec_():
            self.cfg.setdefault("accounts",[]).append(dlg.get_account())
            save_config(self.cfg); self._refresh_acc_list()

    def _edit_acc(self):
        idx = self.acc_list.currentRow()
        if idx < 0: return
        dlg = AccountDialog(self, self.cfg["accounts"][idx])
        if dlg.exec_():
            self.cfg["accounts"][idx] = dlg.get_account()
            save_config(self.cfg); self._refresh_acc_list()

    def _del_acc(self):
        idx = self.acc_list.currentRow()
        if idx < 0: return
        if QMessageBox.question(self,"Zeus","Remover esta conta?") == QMessageBox.Yes:
            self.cfg["accounts"].pop(idx)
            save_config(self.cfg); self._refresh_acc_list()

    def _save(self):
        self.cfg["download_path"] = self.path_edit.text()
        self.cfg["pdf_editor_path"] = self.pdf_edit.text()
        if self.smtp_host_edit.text().strip():
            self.cfg["custom_smtp_host"] = self.smtp_host_edit.text().strip()
            self.cfg["custom_smtp_port"] = int(self.smtp_port_edit.text().strip() or "587")
        self.cfg["only_unread"] = not self.chk_unread.isChecked()
        self.cfg["only_attachment"] = self.chk_att.isChecked()
        self.cfg["only_boleto"] = self.chk_boleto.isChecked()
        try: self.cfg["min_value"] = float(self.spin_min_val.value())
        except: self.cfg["min_value"] = float(self.spin_min_val.value())
        self.cfg["max_days_old"] = self.spin_days.value()
        after_vals = ["nothing","move","delete"]
        self.cfg["after_capture"] = after_vals[self.combo_after.currentIndex()]
        self.cfg["max_emails"] = self.spin_max.value()
        self.cfg["cycle_interval"] = self.spin_interval.value()
        self.cfg["extensions"] = [e.strip() for e in self.ext_edit.toPlainText().split("\n") if e.strip()]
        self.cfg["folders"] = [f.strip() for f in self.folder_edit.toPlainText().split("\n") if f.strip()]
        self.cfg["search_boleto"] = True
        self.cfg["keywords_include"] = [k.strip() for k in self.kw_include_edit.toPlainText().split("\n") if k.strip()]
        self.cfg["keywords_exclude"] = [k.strip() for k in self.kw_exclude_edit.toPlainText().split("\n") if k.strip()]
        self.cfg["max_threads"] = self.spin_threads.value()
        self.cfg["monitor_accounts"] = self.spin_monitor_accounts.value()
        self.cfg["emails_per_read"] = self.spin_per_read.value()
        self.cfg["alternate_accounts"] = self.chk_alternate.isChecked()
        save_config(self.cfg)
        QMessageBox.information(self,"Zeus","✅ Configurações salvas!")

# ── Account Dialog ─────────────────────────────────────────────────────────
class AccountDialog(QDialog):
    def __init__(self, parent=None, account=None):
        super().__init__(parent)
        self.setWindowTitle("Configurar Conta"); self.setMinimumWidth(460)
        acc = account or {}
        layout = QVBoxLayout(self); layout.setContentsMargins(24,24,24,24); layout.setSpacing(16)
        title = QLabel("CONFIGURAR CONTA IMAP")
        title.setStyleSheet("color: #ffffff; font-size: 18px; font-weight: 900;")
        layout.addWidget(title)
        form = QFormLayout(); form.setSpacing(10)
        lbl_style = "color: #a3a3a3; font-size: 10px; font-weight: 700; letter-spacing: 1px;"
        self.f_name = QLineEdit(acc.get("name","")); self.f_name.setPlaceholderText("Nome da conta")
        self.f_email = QLineEdit(acc.get("email","")); self.f_email.setPlaceholderText("email@dominio.com")
        self.f_pass = QLineEdit(acc.get("password","")); self.f_pass.setEchoMode(QLineEdit.Password); self.f_pass.setPlaceholderText("Senha")
        self.f_server = QLineEdit(acc.get("imap_server","imap.gmail.com"))
        self.f_port = QLineEdit(str(acc.get("imap_port","993")))
        btn_detect = QPushButton("AUTO-DETECTAR"); btn_detect.setObjectName("btn_ghost")
        btn_detect.clicked.connect(lambda: self._auto_detect())
        for label, widget in [("NOME",self.f_name),("EMAIL",self.f_email),("SENHA",self.f_pass)]:
            lbl = QLabel(label); lbl.setStyleSheet(lbl_style); form.addRow(lbl, widget)
        srv_row = QWidget(); srl = QHBoxLayout(srv_row); srl.setContentsMargins(0,0,0,0); srl.setSpacing(6)
        srl.addWidget(self.f_server); srl.addWidget(btn_detect)
        form.addRow(QLabel("SERVIDOR IMAP"), srv_row)
        form.addRow(QLabel("PORTA"), self.f_port)
        layout.addLayout(form)
        presets = QHBoxLayout()
        for name, server in [("Gmail","imap.gmail.com"),("Outlook","imap.outlook.com"),("Terra","imap.terra.com.br"),("Yahoo","imap.mail.yahoo.com"),("UOL","imap.uol.com.br")]:
            btn = QPushButton(name); btn.setObjectName("btn_ghost")
            btn.clicked.connect(lambda _, s=server: self.f_server.setText(s))
            presets.addWidget(btn)
        layout.addLayout(presets)
        btns = QHBoxLayout()
        btn_test = QPushButton("TESTAR"); btn_test.setObjectName("btn_ghost"); btn_test.clicked.connect(self._test)
        btn_ok = QPushButton("SALVAR"); btn_ok.setObjectName("btn_red"); btn_ok.clicked.connect(self.accept)
        btn_cancel = QPushButton("CANCELAR"); btn_cancel.setObjectName("btn_ghost"); btn_cancel.clicked.connect(self.reject)
        btns.addWidget(btn_test); btns.addStretch(); btns.addWidget(btn_cancel); btns.addWidget(btn_ok)
        layout.addLayout(btns)

    def _auto_detect(self):
        email_addr = self.f_email.text()
        if "@" not in email_addr: QMessageBox.warning(self,"Zeus","Digite o email primeiro!"); return
        server, port = detect_imap(email_addr)
        self.f_server.setText(server); self.f_port.setText(str(port))

    def _test(self):
        try:
            imap = connect_imap(self.get_account()); imap.logout()
            QMessageBox.information(self,"Zeus","✅ Conexão OK!")
        except Exception as e:
            QMessageBox.critical(self,"Zeus",f"❌ Falha:\n{e}")

    def get_account(self):
        return {"name":self.f_name.text(),"email":self.f_email.text(),
                "password":self.f_pass.text(),"imap_server":self.f_server.text(),
                "imap_port":self.f_port.text()}

# ── Main Window ───────────────────────────────────────────────────────────────
# ── Virtual Email Table Model ────────────────────────────────────────────────
# QAbstractTableModel renders ONLY visible rows — zero lag regardless of count
from PyQt5.QtCore import QAbstractTableModel, QModelIndex, QVariant, Qt as Qt2

COLS = ["✓", "CONTA MONITORADA", "DATA/HORA", "PASTA", "ESTADO", "VALOR", "VENCIMENTO", "ASSUNTO"]
COL_WIDTHS = [46, 220, 130, 80, 110, 90, 90, -1]  # -1 = stretch

class EmailTableModel(QAbstractTableModel):
    def __init__(self, emails=None):
        super().__init__()
        # Use the passed list directly — no copy!
        # This means model._emails IS the same object as ZeusMainWindow.emails
        self._emails = emails if emails is not None else []

    def rowCount(self, parent=QModelIndex()):
        return len(self._emails)

    def columnCount(self, parent=QModelIndex()):
        return len(COLS)

    def headerData(self, section, orientation, role=Qt2.DisplayRole):
        if role == Qt2.DisplayRole and orientation == Qt2.Horizontal:
            return COLS[section]
        if role == Qt2.DisplayRole and orientation == Qt2.Vertical:
            return str(section + 1)
        return QVariant()

    def data(self, index, role=Qt2.DisplayRole):
        if not index.isValid(): return QVariant()
        row, col = index.row(), index.column()
        if row >= len(self._emails): return QVariant()
        em = self._emails[row]

        if role == Qt2.DisplayRole:
            if col == 0: return "LIDO" if em.get("opened") else ""
            if col == 1: return em.get("account","")
            if col == 2:
                date_raw = em.get("date","") or ""
                try:
                    from email.utils import parsedate_to_datetime
                    dt = parsedate_to_datetime(date_raw).replace(tzinfo=None)
                    return dt.strftime("%d/%m/%Y %H:%M")
                except: return date_raw[:16]
            if col == 3: return em.get("folder","")
            if col == 4:
                s = em.get("state","")
                return ("📄 " + s) if em.get("has_boleto") else s
            if col == 5: return em.get("value","") or "—"
            if col == 6: return em.get("due_date","") or "—"
            if col == 7: return em.get("subject","")
            return QVariant()

        if role == Qt2.CheckStateRole and col == 0:
            return Qt2.Checked if em.get("_checked") else Qt2.Unchecked

        if role == Qt2.ForegroundRole:
            from PyQt5.QtGui import QColor
            if em.get("opened"):    return QColor("#cc2222")
            if em.get("is_new"):    return QColor("#ffffff")
            if em.get("has_boleto"): return QColor("#e5e5e5")
            return QColor("#a3a3a3")

        if role == Qt2.FontRole:
            from PyQt5.QtGui import QFont
            f = QFont("Arial", 9)
            if em.get("is_new") or (not em.get("opened") and em.get("state") == "NAO LIDO"):
                f.setBold(True)
            return f

        if role == Qt2.BackgroundRole:
            from PyQt5.QtGui import QColor
            if em.get("is_new"):    return QColor("#1e0000")
            if em.get("opened"):    return QColor("#0e0000")
            if em.get("has_boleto"): return QColor("#140505")
            return QVariant()

        return QVariant()

    def setData(self, index, value, role=Qt2.EditRole):
        if role == Qt2.CheckStateRole and index.column() == 0:
            row = index.row()
            if 0 <= row < len(self._emails):
                self._emails[row]["_checked"] = (value == Qt2.Checked)
                self.dataChanged.emit(index, index, [role])
                return True
        return False

    def flags(self, index):
        base = Qt2.ItemIsEnabled | Qt2.ItemIsSelectable
        if index.column() == 0:
            base |= Qt2.ItemIsUserCheckable
        return base

    def prepend_email(self, em):
        """Insert at top (row 0) — O(1) UI update."""
        self.beginInsertRows(QModelIndex(), 0, 0)
        self._emails.insert(0, em)
        self.endInsertRows()

    def append_email(self, em):
        """Append at bottom — O(1) UI update."""
        n = len(self._emails)
        self.beginInsertRows(QModelIndex(), n, n)
        self._emails.append(em)
        self.endInsertRows()

    def append_batch(self, ems):
        """Append multiple emails in ONE model update."""
        if not ems: return
        start = len(self._emails)
        end   = start + len(ems) - 1
        self.beginInsertRows(QModelIndex(), start, end)
        self._emails.extend(ems)
        self.endInsertRows()

    def remove_rows(self, rows_desc):
        """Remove multiple rows (descending order) efficiently."""
        for row in rows_desc:
            if 0 <= row < len(self._emails):
                self.beginRemoveRows(QModelIndex(), row, row)
                self._emails.pop(row)
                self.endRemoveRows()

    def refresh_row(self, row):
        if 0 <= row < len(self._emails):
            self.dataChanged.emit(
                self.index(row, 0),
                self.index(row, len(COLS)-1))

    def get_checked_rows(self):
        return [i for i, em in enumerate(self._emails) if em.get("_checked")]


# ─────────────────────────────────────────────────────────────────────────────
# EXTRATOR DE EMAILS — Aba integrada ao Zeus
# ─────────────────────────────────────────────────────────────────────────────

_EXT_PALAVRAS = frozenset({
    "noreply","no-reply","no_reply","naoresponder","nao-responder","nao_responder",
    "naoresponda","nao-responda","nao_responda","do_not_reply","do-not-reply",
    "donotreply","not-reply","mailer-daemon","postmaster","abuse","admin",
    "administrator","webmaster","robot","bot","nobody","spam","notifications",
    "notification","alert","alerta","automacao","automatico","bounce","return",
    "delivery","mailer","unsubscribe","amazon","mercadolivre","mercadopago",
    "linkedin","newsletter","marketing","promocoes","ofertas","confirmacao",
    "verificacao","validation","validate","welcome","cadastro","registro",
    "register","signup","news","suporte","support","contato","contact","info",
    "faleconosco","atendimento","central","relacionamento","ouvidoria","sac",
    "help","noticias","comunicado","social","facebook","instagram","twitter",
    "microsoft","apple","banco","bradesco","itau","caixa","santander","serasa",
    "vivo","claro","tim","oi",
})
_EXT_EMAIL_RE = re.compile(r'[\w.%+\-]{2,64}@[\w.\-]+\.\w{2,}', re.IGNORECASE)


def _ext_is_servico(local):
    local = local.lower()
    if len(local) <= 2: return True
    if sum(c.isdigit() for c in local) > len(local) * 0.6: return True
    if len(set(local)) <= 2: return True
    for w in _EXT_PALAVRAS:
        if w in local: return True
    return False


def _ext_parse_addrs(header_val):
    from email.utils import getaddresses as _ga
    result = []
    for _, addr in _ga([header_val]):
        if addr and "@" in addr:
            result.append(addr.lower().strip())
    if not result:
        result = [m.lower() for m in _EXT_EMAIL_RE.findall(header_val)]
    return result


class ExtractorThread(QThread):
    email_found  = pyqtSignal(str, str)
    log_msg      = pyqtSignal(str, str)
    conta_done   = pyqtSignal(str, int)
    conta_error  = pyqtSignal(str, str)
    finished_all = pyqtSignal(int)
    progress_upd = pyqtSignal(str, int)

    _CAIXAS = ["INBOX", "Sent", "SENT", "Enviados", "enviados", "Sent Messages"]
    _BATCH  = 200

    def __init__(self, accounts, anos, dominios, campos, emails_global, lock, output_dir, workers=1):
        super().__init__()
        self.accounts      = accounts
        self.anos          = anos
        self.dominios      = dominios
        self.campos        = campos
        self.emails_global = emails_global
        self.lock          = lock
        self.output_dir    = output_dir
        self.workers       = max(1, workers)
        self._stop         = False
        self._q            = queue.Queue()

    def stop(self): self._stop = True

    def _dispatch(self, msg):
        k = msg[0]
        if   k == "email": self.email_found.emit(msg[1], msg[2])
        elif k == "log":   self.log_msg.emit(msg[1], msg[2])
        elif k == "done":  self.conta_done.emit(msg[1], msg[2])
        elif k == "error": self.conta_error.emit(msg[1], msg[2])
        elif k == "prog":  self.progress_upd.emit(msg[1], msg[2])

    def run(self):
        import concurrent.futures as cf
        with cf.ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = {ex.submit(self._worker, acc): acc
                    for acc in self.accounts if not self._stop}
            active = set(futs)
            while active and not self._stop:
                try:
                    while True: self._dispatch(self._q.get_nowait())
                except queue.Empty: pass
                done_futs = {f for f in active if f.done()}
                for f in done_futs:
                    try: f.result()
                    except Exception as e: self.log_msg.emit(f"Erro: {e}", "err")
                active -= done_futs
                if active: self.msleep(50)
        try:
            while True: self._dispatch(self._q.get_nowait())
        except queue.Empty: pass
        self.finished_all.emit(len(self.emails_global))

    def _worker(self, acc):
        conta  = acc.get("email","")
        senha  = acc.get("password","")
        srv    = acc.get("imap_server","")
        prt    = int(acc.get("imap_port", 993))
        q      = self._q
        dom_res = [re.compile(r'@' + re.escape(d.strip().lower()) + r'$', re.I)
                   for d in self.dominios if d.strip()]
        hf  = " ".join(f.upper() for f in self.campos)
        cmd = f"(BODY.PEEK[HEADER.FIELDS ({hf})])"
        n_novos = n_proc = 0
        try:
            mail = (imaplib.IMAP4_SSL(srv, prt) if prt == 993 else imaplib.IMAP4(srv, prt))
            if prt != 993:
                try: mail.starttls()
                except: pass
            mail.login(conta, senha)
            q.put(("log", f"[{conta}] Login OK", "ok"))
        except Exception as e:
            q.put(("error", conta, str(e)))
            q.put(("log", f"[{conta}] FALHOU: {e}", "err"))
            return
        try:
            for caixa in self._CAIXAS:
                if self._stop: break
                try:
                    ok, _ = mail.select(caixa, readonly=True)
                    if ok != "OK": continue
                except: continue
                try:
                    if self.anos:
                        ids = []
                        for ano in self.anos:
                            _, d1 = mail.search(None, f"SINCE 01-Jan-{ano} BEFORE 01-Jan-{ano+1}")
                            if d1 and d1[0]: ids.extend(d1[0].split())
                    else:
                        _, id_data = mail.search(None, "ALL")
                        ids = id_data[0].split() if id_data and id_data[0] else []
                except Exception as e:
                    q.put(("log", f"[{conta}] search {caixa}: {e}", "warn")); continue
                if not ids: continue
                q.put(("log", f"[{conta}] {caixa}: {len(ids)} msgs", "info"))
                for i in range(0, len(ids), self._BATCH):
                    if self._stop: break
                    batch   = ids[i:i+self._BATCH]
                    ids_str = ",".join(x.decode() if isinstance(x, bytes) else str(x) for x in batch)
                    try: _, msgs = mail.fetch(ids_str, cmd)
                    except: continue
                    for item in msgs:
                        if not isinstance(item, tuple) or len(item) < 2: continue
                        raw = item[1]
                        try:
                            msg = (email.message_from_bytes(raw) if isinstance(raw, bytes)
                                   else email.message_from_string(str(raw)))
                        except: continue
                        addrs = []
                        if "FROM" in self.campos: addrs += _ext_parse_addrs(msg.get("From",""))
                        if "TO"   in self.campos: addrs += _ext_parse_addrs(msg.get("To",""))
                        if "CC"   in self.campos: addrs += _ext_parse_addrs(msg.get("Cc",""))
                        if "BCC"  in self.campos: addrs += _ext_parse_addrs(msg.get("Bcc",""))
                        for addr in addrs:
                            if not addr or addr == conta.lower(): continue
                            if _ext_is_servico(addr.split("@")[0]): continue
                            if dom_res and not any(r.search(addr) for r in dom_res): continue
                            with self.lock:
                                if addr not in self.emails_global:
                                    self.emails_global.add(addr)
                                    n_novos += 1
                                    q.put(("email", addr, conta))
                        n_proc += 1
                    q.put(("prog", conta, n_proc))
        finally:
            try: mail.logout()
            except: pass
        q.put(("done", conta, n_novos))
        q.put(("log", f"[{conta}] Concluido: {n_novos} novos", "ok"))


class ExtractorWidget(QWidget):
    _GS = ("QGroupBox{color:#e50914;font-weight:700;font-size:10px;"
           "border:1px solid #2a2a2a;border-radius:4px;padding-top:18px;margin-top:4px;}"
           "QGroupBox::title{subcontrol-origin:margin;left:8px;}")
    _GS2 = ("QGroupBox{color:#595959;font-weight:700;font-size:9px;"
            "border:1px solid #2a2a2a;border-radius:4px;padding-top:16px;margin-top:4px;}"
            "QGroupBox::title{subcontrol-origin:margin;left:8px;}")

    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.cfg           = cfg
        self.emails_global = set()
        self.lock          = threading.Lock()
        self._thread       = None
        self._acc_novos    = {}
        self._prog_items   = {}
        self._output_dir   = os.path.join(os.path.expanduser("~"), "Zeus_Extraidos")
        os.makedirs(self._output_dir, exist_ok=True)
        self._build()
        QTimer.singleShot(50, self._refresh_accounts)

    def _lbl(self, text, color="#595959", size=9, bold=False):
        l = QLabel(text)
        w = "700" if bold else "400"
        l.setStyleSheet(f"color:{color};font-size:{size}px;font-weight:{w};")
        return l

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16,12,16,12); root.setSpacing(8)

        # ── TOP: contas + opções ──────────────────────────────────────────────
        top = QHBoxLayout(); top.setSpacing(10)

        grp_acc = QGroupBox("CONTAS ZEUS"); grp_acc.setStyleSheet(self._GS)
        al = QVBoxLayout(grp_acc); al.setSpacing(6)
        ah = QHBoxLayout()
        self.lbl_n_contas = self._lbl("0 contas")
        btn_rel = QPushButton("Recarregar"); btn_rel.setObjectName("btn_ghost")
        btn_rel.clicked.connect(self._refresh_accounts)
        ah.addWidget(self.lbl_n_contas); ah.addStretch(); ah.addWidget(btn_rel)
        al.addLayout(ah)
        self.lst_acc = QListWidget()
        self.lst_acc.setMaximumHeight(110)
        self.lst_acc.setStyleSheet(
            "QListWidget{background:#0d0d0d;border:1px solid #2a2a2a;"
            "color:#a3a3a3;font-family:Consolas;font-size:10px;}")
        al.addWidget(self.lst_acc)
        top.addWidget(grp_acc, stretch=3)

        grp_opt = QGroupBox("OPCOES DE EXTRACAO"); grp_opt.setStyleSheet(self._GS)
        ol = QVBoxLayout(grp_opt); ol.setSpacing(6)

        ol.addWidget(self._lbl("CAMPOS A EXTRAIR:", bold=True))
        chk_row = QHBoxLayout()
        self.chk_from = QCheckBox("FROM"); self.chk_from.setChecked(True)
        self.chk_to   = QCheckBox("TO");   self.chk_to.setChecked(True)
        self.chk_cc   = QCheckBox("CC");   self.chk_cc.setChecked(True)
        self.chk_bcc  = QCheckBox("BCC");  self.chk_bcc.setChecked(False)
        chk_s = "color:#e0e0e0;font-size:10px;"
        for c in [self.chk_from,self.chk_to,self.chk_cc,self.chk_bcc]:
            c.setStyleSheet(chk_s); chk_row.addWidget(c)
        chk_row.addStretch(); ol.addLayout(chk_row)

        fr_row = QHBoxLayout(); fr_row.setSpacing(12)
        w_ano = QWidget(); wal = QVBoxLayout(w_ano); wal.setContentsMargins(0,0,0,0); wal.setSpacing(2)
        wal.addWidget(self._lbl("ANOS (ex: 2025,2026):"))
        self.edit_anos = QLineEdit(); self.edit_anos.setPlaceholderText("vazio = todos")
        self.edit_anos.setStyleSheet("background:#0d0d0d;color:#e0e0e0;border:1px solid #2a2a2a;padding:4px;font-size:10px;")
        wal.addWidget(self.edit_anos); fr_row.addWidget(w_ano)
        w_dom = QWidget(); wdl = QVBoxLayout(w_dom); wdl.setContentsMargins(0,0,0,0); wdl.setSpacing(2)
        wdl.addWidget(self._lbl("DOMINIOS (vazio = todos):"))
        self.edit_dom = QLineEdit(); self.edit_dom.setPlaceholderText("ex: terra.com.br,gmail.com")
        self.edit_dom.setStyleSheet("background:#0d0d0d;color:#e0e0e0;border:1px solid #2a2a2a;padding:4px;font-size:10px;")
        wdl.addWidget(self.edit_dom); fr_row.addWidget(w_dom)
        ol.addLayout(fr_row)

        wk_row = QHBoxLayout()
        wk_row.addWidget(self._lbl("Contas simultaneas:"))
        self.spin_workers = QSpinBox(); self.spin_workers.setRange(1,10); self.spin_workers.setValue(1)
        self.spin_workers.setStyleSheet("background:#0d0d0d;color:#e0e0e0;border:1px solid #2a2a2a;padding:2px 4px;font-size:10px;")
        wk_row.addWidget(self.spin_workers); wk_row.addStretch()
        ol.addLayout(wk_row)
        top.addWidget(grp_opt, stretch=2)
        root.addLayout(top)

        # ── CONTROLS ─────────────────────────────────────────────────────────
        ctrl = QHBoxLayout()
        self.btn_start = QPushButton("INICIAR EXTRACAO"); self.btn_start.setObjectName("btn_red")
        self.btn_start.clicked.connect(self._start)
        self.btn_stop_ext = QPushButton("PARAR"); self.btn_stop_ext.setObjectName("btn_ghost")
        self.btn_stop_ext.setEnabled(False); self.btn_stop_ext.clicked.connect(self._stop_ext)
        btn_folder = QPushButton("ABRIR PASTA"); btn_folder.setObjectName("btn_ghost")
        btn_folder.clicked.connect(self._open_folder)
        self.lbl_total = QLabel("0 emails unicos")
        self.lbl_total.setStyleSheet("color:#e50914;font-weight:700;font-size:13px;")
        ctrl.addWidget(self.btn_start); ctrl.addWidget(self.btn_stop_ext)
        ctrl.addWidget(btn_folder); ctrl.addStretch(); ctrl.addWidget(self.lbl_total)
        root.addLayout(ctrl)

        self.prog_bar = QProgressBar(); self.prog_bar.setMaximumHeight(5)
        self.prog_bar.setVisible(False)
        self.prog_bar.setStyleSheet(
            "QProgressBar{background:#1a1a1a;border:none;border-radius:2px;}"
            "QProgressBar::chunk{background:#e50914;border-radius:2px;}")
        root.addWidget(self.prog_bar)

        # ── BOTTOM ────────────────────────────────────────────────────────────
        bot = QHBoxLayout(); bot.setSpacing(8)

        grp_prog = QGroupBox("PROGRESSO POR CONTA"); grp_prog.setStyleSheet(self._GS2)
        prl = QVBoxLayout(grp_prog)
        self.lst_prog = QListWidget()
        self.lst_prog.setStyleSheet(
            "QListWidget{background:#0a0a0a;border:none;"
            "color:#595959;font-family:Consolas;font-size:10px;}")
        prl.addWidget(self.lst_prog)
        bot.addWidget(grp_prog, stretch=1)

        right = QVBoxLayout(); right.setSpacing(6)

        grp_res = QGroupBox("EMAILS EXTRAIDOS"); grp_res.setStyleSheet(self._GS)
        rl = QVBoxLayout(grp_res)
        rh = QHBoxLayout()
        btn_clr  = QPushButton("LIMPAR");     btn_clr.setObjectName("btn_ghost");  btn_clr.clicked.connect(self._clear_results)
        btn_save = QPushButton("SALVAR TXT"); btn_save.setObjectName("btn_ghost"); btn_save.clicked.connect(self._save_all)
        rh.addStretch(); rh.addWidget(btn_clr); rh.addWidget(btn_save)
        rl.addLayout(rh)
        self.txt_res = QTextEdit(); self.txt_res.setReadOnly(True)
        self.txt_res.setStyleSheet(
            "QTextEdit{background:#0a0a0a;color:#e0e0e0;"
            "font-family:Consolas;font-size:10px;border:none;}")
        rl.addWidget(self.txt_res)
        right.addWidget(grp_res, stretch=3)

        grp_log = QGroupBox("LOG"); grp_log.setStyleSheet(self._GS2)
        ll = QVBoxLayout(grp_log)
        self.txt_log = QTextEdit(); self.txt_log.setReadOnly(True); self.txt_log.setMaximumHeight(110)
        self.txt_log.setStyleSheet(
            "QTextEdit{background:#050505;color:#595959;"
            "font-family:Consolas;font-size:9px;border:none;}")
        btn_log_clr = QPushButton("LIMPAR LOG"); btn_log_clr.setObjectName("btn_ghost")
        btn_log_clr.clicked.connect(self.txt_log.clear)
        ll.addWidget(self.txt_log); ll.addWidget(btn_log_clr)
        right.addWidget(grp_log, stretch=1)

        bot.addLayout(right, stretch=3)
        root.addLayout(bot)

    def _refresh_accounts(self):
        self.lst_acc.clear()
        accs = self.cfg.get("accounts",[])
        for acc in accs:
            em  = acc.get("email","")
            srv = acc.get("imap_server","")
            self.lst_acc.addItem(f"  {em}  [{srv}]")
        n   = len(accs)
        col = "#2ecc40" if n else "#595959"
        self.lbl_n_contas.setText(f"{n} conta(s)")
        self.lbl_n_contas.setStyleSheet(f"color:{col};font-size:10px;")

    def _get_campos(self):
        c = []
        if self.chk_from.isChecked(): c.append("FROM")
        if self.chk_to.isChecked():   c.append("TO")
        if self.chk_cc.isChecked():   c.append("CC")
        if self.chk_bcc.isChecked():  c.append("BCC")
        return c or ["FROM"]

    def _get_anos(self):
        raw = self.edit_anos.text().strip()
        if not raw: return []
        return [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]

    def _get_doms(self):
        raw = self.edit_dom.text().strip()
        if not raw: return []
        return [d.strip().lower() for d in re.split(r'[,\s]+', raw) if d.strip()]

    def _log_ext(self, text, level="info"):
        colors = {"ok":"#2ecc40","err":"#e50914","warn":"#e5a010","info":"#595959"}
        col = colors.get(level,"#595959")
        ts  = datetime.now().strftime("%H:%M:%S")
        self.txt_log.append(f'<span style="color:{col}">[{ts}] {text}</span>')
        sb = self.txt_log.verticalScrollBar(); sb.setValue(sb.maximum())

    def _start(self):
        accs = self.cfg.get("accounts",[])
        if not accs:
            QMessageBox.warning(self,"Zeus","Nenhuma conta configurada!\nVa em Configuracoes > CONTAS.")
            return
        self.emails_global.clear(); self._acc_novos.clear()
        self._prog_items.clear();   self.txt_res.clear()
        self.lbl_total.setText("0 emails unicos")
        self.lst_prog.clear()
        for acc in accs:
            em   = acc.get("email","")
            item = QListWidgetItem(f"  ... {em}")
            item.setForeground(QColor("#595959"))
            self.lst_prog.addItem(item)
            self._prog_items[em] = item
        self.btn_start.setEnabled(False); self.btn_stop_ext.setEnabled(True)
        self.prog_bar.setVisible(True);   self.prog_bar.setRange(0,0)
        anos    = self._get_anos()
        doms    = self._get_doms()
        campos  = self._get_campos()
        workers = self.spin_workers.value()
        self._log_ext(f"Iniciando: {len(accs)} contas | campos:{campos} | "
                      f"dominios:{doms or ['TODOS']} | anos:{anos or ['todos']}","info")
        self._thread = ExtractorThread(
            accs, anos, doms, campos,
            self.emails_global, self.lock, self._output_dir, workers)
        self._thread.email_found.connect(self._on_email)
        self._thread.log_msg.connect(self._log_ext)
        self._thread.conta_done.connect(self._on_conta_done)
        self._thread.conta_error.connect(self._on_conta_error)
        self._thread.finished_all.connect(self._on_finished)
        self._thread.progress_upd.connect(self._on_progress)
        self._thread.start()

    def _stop_ext(self):
        if self._thread: self._thread.stop()
        self.btn_start.setEnabled(True); self.btn_stop_ext.setEnabled(False)
        self.prog_bar.setVisible(False);  self.prog_bar.setRange(0,1)
        self._log_ext("Extracao interrompida pelo usuario","warn")

    def _on_email(self, addr, conta):
        self.txt_res.append(addr)
        sb = self.txt_res.verticalScrollBar(); sb.setValue(sb.maximum())
        self._acc_novos[conta] = self._acc_novos.get(conta,0)+1
        self.lbl_total.setText(f"{len(self.emails_global)} emails unicos")
        fname = os.path.join(self._output_dir, f"{conta}.txt")
        try:
            with open(fname,"a",encoding="utf-8") as f: f.write(addr+"\n")
        except Exception: pass

    def _on_conta_done(self, conta, n_novos):
        item = self._prog_items.get(conta)
        if item:
            item.setText(f"  OK  {conta}  [{n_novos} novos]")
            item.setForeground(QColor("#2ecc40"))

    def _on_conta_error(self, conta, err):
        item = self._prog_items.get(conta)
        if item:
            item.setText(f"  ERR {conta}  {err[:50]}")
            item.setForeground(QColor("#e50914"))

    def _on_progress(self, conta, n_proc):
        item = self._prog_items.get(conta)
        if item:
            novos = self._acc_novos.get(conta,0)
            item.setText(f"  ... {conta}  proc:{n_proc}  novos:{novos}")
            item.setForeground(QColor("#e5a010"))

    def _on_finished(self, total):
        self.prog_bar.setVisible(False); self.prog_bar.setRange(0,1)
        self.btn_start.setEnabled(True); self.btn_stop_ext.setEnabled(False)
        self.lbl_total.setText(f"{total} emails unicos")
        self._log_ext(f"CONCLUIDO — {total} emails unicos extraidos","ok")
        QMessageBox.information(self,"Extracao Concluida",
            f"{total} emails unicos extraidos!\n\n"
            f"Arquivos salvos em:\n{self._output_dir}\n\n"
            "Um TXT por conta (nome = email de login).")

    def _clear_results(self): self.txt_res.clear()

    def _save_all(self):
        if not self.emails_global:
            QMessageBox.warning(self,"Zeus","Nada para salvar."); return
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path, _ = QFileDialog.getSaveFileName(self,"Salvar todos os emails",
            os.path.join(self._output_dir, f"todos_{ts}.txt"),
            "Arquivos de Texto (*.txt)")
        if path:
            with open(path,"w",encoding="utf-8") as f:
                f.write("\n".join(sorted(self.emails_global)))
            QMessageBox.information(self,"Salvo",f"Salvo: {path}")

    def _open_folder(self):
        try: os.startfile(self._output_dir)
        except Exception: pass


class ZeusMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("⚡ ZEUS — Email Monitor")
        self.setMinimumSize(1280, 750)
        self.resize(1440, 860)
        self.cfg = load_config()
        self.monitors = {}
        self._coordinator = None
        # Must initialize before _build() — EmailTableModel needs self.emails
        self.emails = []
        self.sent_emails = []
        self._seen_hashes = set()
        self._build()
        # Load persisted data async after UI ready
        self.sent_emails = self._load_sent_emails()
        self._seen_hashes = load_seen_hashes()
        self._load_batch_index = 0
        QTimer.singleShot(200, self._load_emails_batch)
        QTimer.singleShot(400, self._load_sent_table)
        n_acc = len(self.cfg.get("accounts", []))
        self._status(f"Carregando emails salvos... {n_acc} conta(s) configurada(s).")

    def _build(self):
        central = QWidget(); self.setCentralWidget(central)
        main_layout = QHBoxLayout(central); main_layout.setContentsMargins(0,0,0,0); main_layout.setSpacing(0)

        # Sidebar
        sidebar = QWidget(); sidebar.setObjectName("sidebar"); sidebar.setFixedWidth(210)
        sl = QVBoxLayout(sidebar); sl.setContentsMargins(0,0,0,0); sl.setSpacing(0)
        logo = QLabel("⚡ ZEUS")
        logo.setStyleSheet("color: #e50914; font-size: 28px; font-weight: 900; letter-spacing: -1px; padding: 24px 20px 4px;")
        sub = QLabel("EMAIL MONITOR")
        sub.setStyleSheet("color: #404040; font-size: 9px; font-weight: 700; letter-spacing: 3px; padding: 0 20px 20px;")
        sl.addWidget(logo); sl.addWidget(sub)
        sep = QFrame(); sep.setFrameShape(QFrame.HLine); sep.setStyleSheet("background: #2a2a2a; max-height: 1px; margin: 0 16px;")
        sl.addWidget(sep)
        self.sidebar_btns = []
        for icon, label, idx in [("📥","CAIXA DE ENTRADA",0),("📡","MONITORAMENTO",1),("✏️","EDITOR",2),("📤","ENVIADOS",3),("📅","AGENDADOS",4),("⚙️","CONFIGURAÇÕES",5),("⬇","EXTRATOR",6)]:
            btn = QPushButton(f"  {icon}  {label}"); btn.setCheckable(True)
            btn.clicked.connect(lambda _, i=idx: self._switch_tab(i))
            sl.addWidget(btn); self.sidebar_btns.append(btn)
        sl.addStretch()
        self.acc_count_lbl = QLabel("  0 contas")
        self.acc_count_lbl.setStyleSheet("color: #404040; font-size: 10px; padding: 12px 20px;")
        sl.addWidget(self.acc_count_lbl)
        main_layout.addWidget(sidebar)

        # Content
        content = QWidget(); cl = QVBoxLayout(content); cl.setContentsMargins(0,0,0,0); cl.setSpacing(0)

        # Topbar
        topbar = QWidget(); topbar.setObjectName("topbar"); topbar.setFixedHeight(52)
        tbl = QHBoxLayout(topbar); tbl.setContentsMargins(20,0,20,0); tbl.setSpacing(10)
        self.page_title = QLabel("CAIXA DE ENTRADA")
        self.page_title.setStyleSheet("color: #fff; font-size: 18px; font-weight: 900;")
        tbl.addWidget(self.page_title); tbl.addStretch()
        self.search_box = QLineEdit(); self.search_box.setObjectName("search_box")
        self.search_box.setPlaceholderText("🔍  Buscar emails..."); self.search_box.textChanged.connect(self._filter)
        tbl.addWidget(self.search_box)
        # Import button - highlighted
        btn_import_file = QPushButton("📂  IMPORTAR"); btn_import_file.setObjectName("btn_green")
        btn_import_file.clicked.connect(self._import_file)
        btn_monitor = QPushButton("▶  INICIAR"); btn_monitor.setObjectName("btn_red"); btn_monitor.clicked.connect(self._start_monitoring)
        btn_refresh = QPushButton("🔄"); btn_refresh.setObjectName("btn_ghost")
        btn_refresh.setToolTip("Forçar nova leitura agora")
        btn_refresh.setFixedWidth(38)
        btn_refresh.clicked.connect(self._refresh_monitor)
        btn_clear_cache = QPushButton("🧹"); btn_clear_cache.setObjectName("btn_ghost")
        btn_clear_cache.setToolTip("Limpar cache e reprocessar todos os emails")
        btn_clear_cache.setFixedWidth(38)
        btn_clear_cache.clicked.connect(self._clear_cache_and_rescan)
        btn_stop = QPushButton("⏹  PARAR"); btn_stop.setObjectName("btn_ghost"); btn_stop.clicked.connect(self._stop_monitoring)
        for b in [btn_import_file, btn_monitor, btn_refresh, btn_clear_cache, btn_stop]: tbl.addWidget(b)
        cl.addWidget(topbar)

        # Stack
        self.stack = QTabWidget(); self.stack.tabBar().setVisible(False)
        self.stack.setStyleSheet("QTabWidget::pane { border: none; }")

        # Page 0: Inbox
        self.inbox_page = self._build_inbox_page()
        self.stack.addTab(self.inbox_page, "inbox")

        # Page 1: Monitor Panel
        self.monitor_panel = MonitorPanel(self.cfg)
        self.monitor_panel.set_remove_callback(self._remove_account_from_monitor)
        self.stack.addTab(self.monitor_panel, "monitor")

        # Page 2: Editor
        self.editor = EmailEditor(cfg=self.cfg)
        self.stack.addTab(self.editor, "editor")

        # Page 3: Agendados
        self.scheduled_page = self._build_scheduled_page()
        # Page 3: Sent
        self.sent_page = self._build_sent_page()
        self.stack.addTab(self.sent_page, "sent")

        self.stack.addTab(self.scheduled_page, "scheduled")

        # Page 5: Settings
        self.settings_page = SettingsWidget(self.cfg)
        self.stack.addTab(self.settings_page, "settings")

        # Page 6: Extractor
        self.extractor_page = ExtractorWidget(self.cfg)
        self.stack.addTab(self.extractor_page, "extractor")

        cl.addWidget(self.stack)
        main_layout.addWidget(content)

        # Status bar
        self.status_bar = QStatusBar(); self.setStatusBar(self.status_bar)
        self.progress = QProgressBar(); self.progress.setMaximumWidth(120); self.progress.setVisible(False)
        self.count_lbl = QLabel("0 emails"); self.count_lbl.setStyleSheet("color: #595959; font-size: 11px; padding-right: 8px;")
        self.status_bar.addPermanentWidget(self.progress); self.status_bar.addPermanentWidget(self.count_lbl)

        self._switch_tab(0)

    def _build_inbox_page(self):
        page = QWidget(); pl = QVBoxLayout(page)
        pl.setContentsMargins(0,0,0,0); pl.setSpacing(0)

        # Action bar
        action_bar = QWidget()
        action_bar.setStyleSheet("background:#0a0a0a;border-bottom:1px solid #2a2a2a;")
        action_bar.setFixedHeight(34)
        abl = QHBoxLayout(action_bar); abl.setContentsMargins(8,0,8,0); abl.setSpacing(6)

        self.chk_select_all = QCheckBox(); self.chk_select_all.setToolTip("Selecionar tudo")
        self.chk_select_all.stateChanged.connect(self._toggle_select_all)
        abl.addWidget(self.chk_select_all)

        btn_delete_sel = QPushButton("🗑")
        btn_delete_sel.setObjectName("btn_icon"); btn_delete_sel.setFixedSize(26,26)
        btn_delete_sel.setStyleSheet("QPushButton{background:transparent;color:#e50914;border:1px solid #e50914;border-radius:4px;font-size:14px;}QPushButton:hover{background:#e50914;color:#fff;}")
        btn_delete_sel.clicked.connect(self._delete_selected)
        abl.addWidget(btn_delete_sel)

        sep = QFrame(); sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet("color:#2a2a2a;"); sep.setFixedWidth(1)
        abl.addWidget(sep)

        self.lbl_total   = QLabel("Total: 0")
        self.lbl_unread  = QLabel("Nao lidos: 0")
        self.lbl_boletos = QLabel("Boletos: 0")
        self.lbl_new     = QLabel("Novos: 0")
        self.lbl_selected= QLabel("")
        for lbl, color in [(self.lbl_total,"#595959"),(self.lbl_unread,"#e5e5e5"),
                            (self.lbl_boletos,"#e50914"),(self.lbl_new,"#2ecc40"),
                            (self.lbl_selected,"#e5a010")]:
            lbl.setStyleSheet(f"color:{color};font-size:11px;font-weight:700;")
            abl.addWidget(lbl)
        abl.addStretch()
        pl.addWidget(action_bar)

        # Virtual table view — only renders visible rows
        from PyQt5.QtWidgets import QTableView, QHeaderView as QHV
        self._email_model = EmailTableModel(self.emails)
        self.table_view = QTableView()
        self.table_view.setModel(self._email_model)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table_view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.verticalHeader().setDefaultSectionSize(26)
        self.table_view.setShowGrid(True)
        self.table_view.setWordWrap(False)
        self.table_view.setSortingEnabled(False)
        # Column widths
        hh = self.table_view.horizontalHeader()
        for i, w in enumerate(COL_WIDTHS):
            if w == -1: hh.setSectionResizeMode(i, QHV.Stretch)
            else:
                hh.setSectionResizeMode(i, QHV.Fixed)
                self.table_view.setColumnWidth(i, w)
        self.table_view.setStyleSheet("""
            QTableView { gridline-color:#222; background:#141414; border:none; }
            QTableView::item { padding:0 8px; border-right:1px solid #222; color:#a3a3a3; }
            QTableView::item:selected { background:#2a0000; color:#ff4444; border-left:3px solid #e50914; }
            QHeaderView::section { background:#000; color:#a3a3a3; padding:8px; border:none;
                border-bottom:2px solid #2a2a2a; font-size:11px; font-weight:700; letter-spacing:1px; }
        """)
        self.table_view.doubleClicked.connect(self._open_email)
        self.table_view.clicked.connect(self._on_row_click)
        self.table_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table_view.customContextMenuRequested.connect(self._table_menu)
        # Keep self.table as alias for backwards compat
        self.table = self.table_view
        pl.addWidget(self.table_view)
        return page

    def _build_sent_page(self):
        page = QWidget(); pl = QVBoxLayout(page)
        pl.setContentsMargins(0,0,0,0); pl.setSpacing(0)

        action_bar = QWidget()
        action_bar.setStyleSheet("background:#0a0a0a;border-bottom:1px solid #2a2a2a;")
        action_bar.setFixedHeight(34)
        abl = QHBoxLayout(action_bar); abl.setContentsMargins(8,0,8,0); abl.setSpacing(6)
        self.chk_select_all_sent = QCheckBox()
        self.chk_select_all_sent.stateChanged.connect(self._toggle_select_all_sent)
        abl.addWidget(self.chk_select_all_sent)
        btn_del = QPushButton("🗑"); btn_del.setFixedSize(26,26)
        btn_del.setStyleSheet("QPushButton{background:transparent;color:#e50914;border:1px solid #e50914;border-radius:4px;font-size:14px;}QPushButton:hover{background:#e50914;color:#fff;}")
        btn_del.clicked.connect(self._delete_selected_sent)
        abl.addWidget(btn_del)
        self.lbl_sent_count = QLabel("0 enviados")
        self.lbl_sent_count.setStyleSheet("color:#595959;font-size:11px;font-weight:700;margin-left:8px;")
        abl.addWidget(self.lbl_sent_count); abl.addStretch()
        pl.addWidget(action_bar)

        self.sent_table = QTableWidget()
        self.sent_table.setColumnCount(7)
        self.sent_table.setHorizontalHeaderLabels(["✓","DE","PARA","DATA/HORA","ASSUNTO","VALOR","PASTA ORIGEM"])
        hh = self.sent_table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.Fixed)
        self.sent_table.setColumnWidth(0,28); self.sent_table.setColumnWidth(1,180)
        self.sent_table.setColumnWidth(2,180); self.sent_table.setColumnWidth(3,130)
        self.sent_table.setColumnWidth(5,90); self.sent_table.setColumnWidth(6,90)
        hh.setSectionResizeMode(4, QHeaderView.Stretch)
        self.sent_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.sent_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.sent_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.sent_table.verticalHeader().setVisible(False)
        self.sent_table.setShowGrid(True); self.sent_table.setWordWrap(False)
        self.sent_table.setStyleSheet("""
            QTableWidget{gridline-color:#222;background:#141414;}
            QTableWidget::item{padding:0 8px;border-right:1px solid #222;}
            QTableWidget::item:selected{background:#002a0a;color:#2ecc40;border-left:3px solid #2ecc40;}
        """)
        pl.addWidget(self.sent_table)
        return page

    def _add_sent_row(self, em):
        row = self.sent_table.rowCount()
        self.sent_table.insertRow(row)
        self.sent_table.setRowHeight(row, 22)
        chk = QTableWidgetItem(); chk.setCheckState(Qt.Unchecked)
        self.sent_table.setItem(row, 0, chk)
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(em.get("date","")).replace(tzinfo=None)
            date_str = dt.strftime("%d/%m/%Y %H:%M")
        except: date_str = str(em.get("date",""))[:16]
        for col, val in enumerate([em.get("sender",""), em.get("to",""), date_str,
                                    em.get("subject",""), em.get("value","") or "—",
                                    em.get("original_folder","INBOX")]):
            item = QTableWidgetItem(str(val))
            item.setForeground(QColor("#a6e3a1")); item.setFont(QFont("Arial",9))
            self.sent_table.setItem(row, col+1, item)
        self.lbl_sent_count.setText(f"{self.sent_table.rowCount()} enviado(s)")

    def _load_sent_table(self):
        if not hasattr(self, 'sent_table'): return
        self.sent_table.setUpdatesEnabled(False)
        for em in self.sent_emails: self._add_sent_row(em)
        self.sent_table.setUpdatesEnabled(True)
        self.lbl_sent_count.setText(f"{len(self.sent_emails)} enviado(s)")

    def _toggle_select_all_sent(self, state):
        cs = Qt.Checked if state == Qt.Checked else Qt.Unchecked
        for row in range(self.sent_table.rowCount()):
            item = self.sent_table.item(row, 0)
            if item: item.setCheckState(cs)

    def _delete_selected_sent(self):
        rows = set()
        for row in range(self.sent_table.rowCount()):
            item = self.sent_table.item(row, 0)
            if item and item.checkState() == Qt.Checked: rows.add(row)
        for idx in self.sent_table.selectedIndexes(): rows.add(idx.row())
        rows = sorted(rows, reverse=True)
        if not rows: QMessageBox.information(self,"Zeus","Nenhum item selecionado."); return
        if QMessageBox.question(self,"Zeus",f"Apagar {len(rows)} item(ns)?") != QMessageBox.Yes: return
        for row in rows:
            if 0 <= row < len(self.sent_emails): self.sent_emails.pop(row)
            self.sent_table.removeRow(row)
        self.lbl_sent_count.setText(f"{self.sent_table.rowCount()} enviado(s)")
        self._save_sent_emails()

    def _save_sent_emails(self):
        import threading as _t
        _t.Thread(target=self._do_save_sent, daemon=True).start()

    def _do_save_sent(self):
        try:
            sent_file = os.path.join(os.path.expanduser("~"), ".zeus_sent.json")
            data = [{k:v for k,v in e.items() if k not in ("raw","part")} for e in self.sent_emails]
            with open(sent_file,"w",encoding="utf-8") as f: json.dump(data,f,ensure_ascii=False,indent=2)
        except: pass

    def _load_sent_emails(self):
        try:
            sent_file = os.path.join(os.path.expanduser("~"), ".zeus_sent.json")
            if os.path.exists(sent_file):
                with open(sent_file,"r",encoding="utf-8") as f: return json.load(f)
        except: pass
        return []

    def _build_scheduled_page(self):
        page = QWidget(); pl = QVBoxLayout(page); pl.setContentsMargins(24,24,24,24); pl.setSpacing(16)

        hdr = QHBoxLayout()
        title = QLabel("BOLETOS AGENDADOS"); title.setStyleSheet("color: #fff; font-size: 18px; font-weight: 900;")
        hdr.addWidget(title); hdr.addStretch()
        btn_add = QPushButton("+ AGENDAR BOLETO"); btn_add.setObjectName("btn_red")
        btn_add.clicked.connect(self._add_scheduled)
        hdr.addWidget(btn_add)
        pl.addLayout(hdr)

        self.scheduled_table = QTableWidget()
        self.scheduled_table.setColumnCount(7)
        self.scheduled_table.setHorizontalHeaderLabels(["DESCRIÇÃO","CÓDIGO DO BOLETO","VALOR","VENCIMENTO","AGENDADO PARA","STATUS","AÇÕES"])
        self.scheduled_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.scheduled_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Fixed)
        self.scheduled_table.setColumnWidth(6, 175)
        self.scheduled_table.verticalHeader().setVisible(False)
        self.scheduled_table.setShowGrid(False)
        self.scheduled_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        pl.addWidget(self.scheduled_table)

        # Load saved schedules
        self.schedules = self.cfg.get("schedules", [])
        self._refresh_scheduled()

        return page

    def _refresh_scheduled(self):
        self.scheduled_table.setRowCount(0)
        now = datetime.now()
        for i, s in enumerate(self.schedules):
            row = self.scheduled_table.rowCount()
            self.scheduled_table.insertRow(row)
            self.scheduled_table.setRowHeight(row, 38)
            # Determine status
            try:
                sched_dt = datetime.strptime(s.get("scheduled_for",""), "%d/%m/%Y %H:%M")
                if s.get("paid"): status = "✅ Pago"
                elif sched_dt < now: status = "⚠️ Vencido"
                else: status = "⏳ Aguardando"
            except: status = "—"

            color_map = {"✅ Pago": "#2ecc40", "⚠️ Vencido": "#e50914", "⏳ Aguardando": "#e5a010"}
            vals = [s.get("desc",""), s.get("code",""), s.get("value",""),
                    s.get("due",""), s.get("scheduled_for",""), status]
            for col, val in enumerate(vals):
                item = QTableWidgetItem(str(val))
                item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
                if col == 5:
                    item.setForeground(QColor(color_map.get(val, "#a3a3a3")))
                self.scheduled_table.setItem(row, col, item)

            # Action buttons
            btn_w = QWidget(); btn_l = QHBoxLayout(btn_w); btn_l.setContentsMargins(3,2,3,2); btn_l.setSpacing(3)
            _ics = ("QPushButton{background:transparent;color:#a3a3a3;border:1px solid #333;"
                    "border-radius:3px;font-size:9px;font-weight:700;padding:0 4px;}"
                    "QPushButton:hover{background:#2a2a2a;color:#fff;border-color:#555;}")
            btn_copy = QPushButton("COPIAR"); btn_copy.setFixedSize(62,24); btn_copy.setStyleSheet(_ics)
            btn_copy.setToolTip("Copiar código")
            btn_copy.clicked.connect(lambda _, c=s.get("code",""): QApplication.clipboard().setText(c))
            btn_paid = QPushButton("PAGO"); btn_paid.setFixedSize(48,24); btn_paid.setStyleSheet(_ics)
            btn_paid.setToolTip("Marcar como pago")
            btn_paid.clicked.connect(lambda _, idx=i: self._mark_paid(idx))
            btn_del = QPushButton("DEL"); btn_del.setFixedSize(42,24)
            btn_del.setStyleSheet("QPushButton{background:transparent;color:#e50914;border:1px solid #e50914;"
                                   "border-radius:3px;font-size:9px;font-weight:700;padding:0 6px;}"
                                   "QPushButton:hover{background:#e50914;color:#fff;}")
            btn_del.setToolTip("Excluir")
            btn_del.clicked.connect(lambda _, idx=i: self._del_scheduled(idx))
            btn_l.addWidget(btn_copy); btn_l.addWidget(btn_paid); btn_l.addWidget(btn_del)
            self.scheduled_table.setCellWidget(row, 6, btn_w)

    def _add_scheduled(self, boleto_code="", value="", due=""):
        dlg = QDialog(self); dlg.setWindowTitle("Agendar Boleto"); dlg.setMinimumWidth(440)
        layout = QVBoxLayout(dlg); layout.setContentsMargins(24,24,24,24); layout.setSpacing(14)
        title = QLabel("📅 AGENDAR BOLETO"); title.setStyleSheet("color: #fff; font-size: 16px; font-weight: 900;")
        layout.addWidget(title)
        form = QFormLayout(); form.setSpacing(10)
        lbl_s = "color: #a3a3a3; font-size: 10px; font-weight: 700; letter-spacing: 1px;"
        f_desc = QLineEdit(); f_desc.setPlaceholderText("Ex: Conta de luz junho")
        f_code = QLineEdit(boleto_code); f_code.setPlaceholderText("Código de barras do boleto")
        f_value = QLineEdit(value); f_value.setPlaceholderText("R$ 0,00")
        f_due = QLineEdit(due); f_due.setPlaceholderText("DD/MM/AAAA")
        f_sched = QLineEdit(datetime.now().strftime("%d/%m/%Y %H:%M")); f_sched.setPlaceholderText("DD/MM/AAAA HH:MM")
        for lbl, w in [("DESCRIÇÃO",f_desc),("CÓDIGO DO BOLETO",f_code),("VALOR",f_value),
                        ("VENCIMENTO",f_due),("AGENDAR PARA",f_sched)]:
            l = QLabel(lbl); l.setStyleSheet(lbl_s); form.addRow(l, w)
        layout.addLayout(form)
        btns = QHBoxLayout()
        btn_ok = QPushButton("AGENDAR"); btn_ok.setObjectName("btn_red"); btn_ok.clicked.connect(dlg.accept)
        btn_cancel = QPushButton("CANCELAR"); btn_cancel.setObjectName("btn_ghost"); btn_cancel.clicked.connect(dlg.reject)
        btns.addStretch(); btns.addWidget(btn_cancel); btns.addWidget(btn_ok)
        layout.addLayout(btns)
        if dlg.exec_():
            self.schedules.append({
                "desc": f_desc.text(), "code": f_code.text(),
                "value": f_value.text(), "due": f_due.text(),
                "scheduled_for": f_sched.text(), "paid": False
            })
            self.cfg["schedules"] = self.schedules
            save_config(self.cfg)
            self._refresh_scheduled()

    def _mark_paid(self, idx):
        if 0 <= idx < len(self.schedules):
            self.schedules[idx]["paid"] = True
            self.cfg["schedules"] = self.schedules
            save_config(self.cfg)
            self._refresh_scheduled()

    def _del_scheduled(self, idx):
        if QMessageBox.question(self,"Zeus","Excluir este agendamento?") == QMessageBox.Yes:
            if 0 <= idx < len(self.schedules):
                self.schedules.pop(idx)
                self.cfg["schedules"] = self.schedules
                save_config(self.cfg)
                self._refresh_scheduled()

    def _switch_tab(self, idx):
        self.stack.setCurrentIndex(idx)
        titles = ["CAIXA DE ENTRADA","MONITORAMENTO","EDITOR","ENVIADOS","AGENDADOS","CONFIGURAÇÕES","EXTRATOR"]
        self.page_title.setText(titles[idx] if idx < len(titles) else "")
        for i, btn in enumerate(self.sidebar_btns): btn.setChecked(i == idx)
        if idx == 5:
            self.settings_page.cfg = self.cfg
            self.settings_page._refresh_acc_list()
        elif idx == 6:
            self.extractor_page.cfg = self.cfg
            self.extractor_page._refresh_accounts()

    def _import_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Abrir Arquivo de Contas", "",
                                               "Arquivos de Texto (*.txt *.csv);;Todos os Arquivos (*)")
        if not path: return
        try:
            accounts, errors = parse_accounts_file(path)
            if not accounts:
                QMessageBox.warning(self,"Zeus",f"Nenhuma conta válida encontrada.\n\nErros:\n" + "\n".join(errors[:10]))
                return
            dlg = ImportFileDialog(accounts, errors, self)
            if dlg.exec_() and dlg.selected:
                # Merge with existing
                existing_emails = {a["email"] for a in self.cfg.get("accounts",[])}
                added = 0
                for acc in dlg.selected:
                    if acc["email"] not in existing_emails:
                        self.cfg.setdefault("accounts",[]).append(acc)
                        added += 1
                save_config(self.cfg)
                self._update_acc_count()
                self.settings_page._refresh_acc_list()
                reply = QMessageBox.question(self,"Zeus",
                    f"✅ {added} conta(s) importada(s)!\n\nDeseja iniciar o monitoramento agora?")
                if reply == QMessageBox.Yes:
                    self._start_monitoring()
        except Exception as e:
            QMessageBox.critical(self,"Zeus",f"Erro ao ler arquivo:\n{e}")

    def _update_acc_count(self):
        n = len(self.cfg.get("accounts",[]))
        self.acc_count_lbl.setText(f"  {n} conta(s)")

    def _start_monitoring(self):
        accounts = self.cfg.get("accounts",[])
        if not accounts:
            QMessageBox.warning(self,"Zeus","Importe um arquivo ou adicione contas nas Configurações!")
            return

        self._stop_monitoring()

        use_idle = _ZEUS_ENGINE and self.cfg.get("use_imap_idle", True)

        # Choose engine mode
        use_worker_process = _ZEUS_WORKER and self.cfg.get("use_worker_process", False)

        if use_worker_process:
            # ── Async subprocess mode (zero UI freeze) ──
            try:
                self._worker_client = WorkerClient(
                    email_cb  = lambda em: QTimer.singleShot(0, lambda e=em: self._on_new_email(e)),
                    status_cb = lambda addr, s: QTimer.singleShot(0, lambda a=addr, m=s: self._on_status_update(a, m))
                )
                self._worker_client.start(accounts, self.cfg)
                self.monitors = {"_worker": None}
            except Exception as e:
                self._status(f"Worker process failed: {e} — falling back to threads")
                use_worker_process = False

        if not use_worker_process:
            # ── Thread mode with optional IDLE push ──
            self._coordinator = AccountCoordinator(accounts, self.cfg)
            self._coordinator.new_email.connect(self._on_new_email)
            self._coordinator.status_update.connect(self._on_status_update)
            self._coordinator.start()
            self.monitors = {"_coordinator": self._coordinator}

        # IMAP IDLE workers for instant push notifications
        if use_idle and _ZEUS_ENGINE:
            self._idle_workers = getattr(self, '_idle_workers', [])
            for w in self._idle_workers:
                try: w.stop()
                except: pass
            self._idle_workers = []
            for acc in accounts[:20]:
                try:
                    w = IMAPIdleWorker(acc,
                        on_new_mail_cb=self._on_idle_push,
                        status_cb=lambda a,s: None)
                    w.start()
                    self._idle_workers.append(w)
                except: pass

        self.monitor_panel.refresh(accounts, self.monitors)
        self._switch_tab(1)
        mode = "IDLE+THREAD" if (use_idle and _ZEUS_ENGINE) else "THREAD"
        db_mode = "SQLite" if _ZEUS_ENGINE else "JSON"
        self._status(f"⚡ {mode} | {len(accounts)} conta(s) | DB:{db_mode} | ML:{'ON' if _ZEUS_ENGINE else 'OFF'}")
        self._update_acc_count()

    def _on_idle_push(self, email_addr):
        """IMAP IDLE push — force immediate rescan of this account."""
        if hasattr(self, '_coordinator') and self._coordinator:
            for w in getattr(self._coordinator, 'workers', []):
                if getattr(w, 'em_addr','') == email_addr:
                    w._pending = {}
                    break


    def _on_status_update(self, email_addr, status):
        accounts = self.cfg.get("accounts",[])
        self.monitor_panel.update_status(email_addr, status, accounts)

    def _stop_monitoring(self):
        if hasattr(self, '_worker_client') and self._worker_client:
            try: self._worker_client.stop()
            except: pass
            self._worker_client = None
        if hasattr(self, '_coordinator') and self._coordinator:
            try: self._coordinator.stop()
            except: pass
            self._coordinator = None
        for key, mon in list(self.monitors.items()):
            try: mon.stop()
            except: pass
        self.monitors.clear()
        accounts = self.cfg.get("accounts",[])
        self.monitor_panel.refresh(accounts, self.monitors)
        self._status("⏹ Monitoramento parado.")

    def _load_sent_table(self):
        self.sent_table.setUpdatesEnabled(False)
        for em in self.sent_emails:
            self._add_sent_row(em)
        self.sent_table.setUpdatesEnabled(True)
        self.lbl_sent_count.setText(f"{len(self.sent_emails)} enviado(s)")

    def _load_emails_batch(self):
        """Load saved emails in batches of 30 to keep UI responsive."""
        BATCH = 30
        if not hasattr(self, '_all_saved_emails'):
            raw = load_emails()
            # Ordena por data do email mais recente primeiro ao carregar
            def _date_key(em):
                try:
                    return parse_email_date(em.get("date", ""))
                except:
                    return datetime.min
            self._all_saved_emails = sorted(raw, key=_date_key, reverse=True)
            self._load_batch_index = 0
            # Limpa em-place para manter a mesma referência usada pelo model
            del self.emails[:]
            self._email_model._emails = self.emails
            # Disable sorting during bulk load for massive speedup
            self.table.setSortingEnabled(False)

        batch = self._all_saved_emails[self._load_batch_index:self._load_batch_index + BATCH]
        if not batch:
            del self._all_saved_emails
            self.table.setSortingEnabled(False)
            self.count_lbl.setText(f"{len(self.emails)} emails")
            self._update_stats()
            self._status(f"Pronto. {len(self.emails)} emails carregados.")
            return

        # Use batch insert — single model update for entire batch
        for em in batch:
            em["is_new"] = False
            self._seen_hashes.add(email_hash(em))
        # append_batch estende model._emails que é a mesma referência de self.emails
        self._email_model.append_batch(batch)

        self._load_batch_index += BATCH
        loaded = min(self._load_batch_index, len(self._all_saved_emails))
        total  = len(self._all_saved_emails)
        self.count_lbl.setText(f"Carregando {loaded}/{total}...")
        # Longer delay between batches when list is large
        delay = 5 if total < 200 else 15
        QTimer.singleShot(delay, self._load_emails_batch)

    def _on_new_email(self, em):
        em["is_new"] = True
        em["opened"] = False
        # Dedup by content hash (survives cache clears)
        h = email_hash(em)
        if h in self._seen_hashes:
            return
        # Also dedup by uid+account in current session
        key = em.get("uid","") + em.get("account","")
        if any((e.get("uid","") + e.get("account","")) == key for e in self.emails):
            return
        # Mark as permanently seen
        self._seen_hashes.add(h)
        import threading as _t
        _t.Thread(target=save_seen_hashes, args=(self._seen_hashes.copy(),), daemon=True).start()
        # Add to model and emails list — model._emails IS self.emails
        self._email_model.prepend_email(em)
        # emails list is same object as model._emails so already updated
        self._update_stats()
        self.count_lbl.setText(f"{len(self.emails)} emails")
        # Save in background
        import threading as _t
        if not hasattr(self, '_save_pending') or not self._save_pending:
            self._save_pending = True
            QTimer.singleShot(2000, self._save_emails_bg)

    def _save_emails_bg(self):
        self._save_pending = False
        import threading as _t
        _t.Thread(target=save_emails, args=(self.emails[:],), daemon=True).start()

    def _flush_email_buffer(self):
        """Add buffered emails to table — max 20 per tick to stay responsive."""
        self._flush_scheduled = False
        if not hasattr(self, '_email_buffer') or not self._email_buffer:
            return

        # Process max 20 rows per tick — schedule next flush if more remain
        CHUNK = 20
        batch = self._email_buffer[:CHUNK]
        self._email_buffer = self._email_buffer[CHUNK:]

        # New emails go to top one by one (small batch, no freeze)
        for em in batch:
            self._email_model.prepend_email(em)
        self.count_lbl.setText(f"{len(self.emails)} emails")
        self._update_stats()

        # If more remain — schedule next chunk with tiny delay (keeps UI alive)
        if self._email_buffer:
            self._flush_scheduled = True
            QTimer.singleShot(30, self._flush_email_buffer)
        else:
            # All done — save in background
            import threading as _t
            _t.Thread(target=save_emails, args=(self.emails[:],), daemon=True).start()
        sender = em.get("sender","")[:35]
        subject = em.get("subject","")[:35]
        boleto_info = f" 📄 R${em.get('value','')}" if em.get("has_boleto") else ""
        self._status(f"📧 {sender} — {subject}{boleto_info}")
        accounts = self.cfg.get("accounts",[])
        self.monitor_panel.refresh(accounts, self.monitors)
        self._update_stats()

    def _add_row(self, em, append=False):
        """Add to model — O(1), no UI freeze ever."""
        if append or not em.get("is_new", False):
            self._email_model.append_email(em)
        else:
            self._email_model.prepend_email(em)
        em["is_new"] = False
        em["opened"] = em.get("opened", False)
        self._update_stats()

    def _update_stats(self):
        total = len(self.emails)
        # Fast count using list comprehension
        unread = boletos = new_count = 0
        for e in self.emails:
            if e.get("state") == "NAO LIDO": unread += 1
            if e.get("has_boleto"): boletos += 1
            if e.get("is_new"): new_count += 1
        self.lbl_total.setText(f"Total: {total}")
        self.lbl_unread.setText(f"Não lidos: {unread}")
        self.lbl_boletos.setText(f"Boletos: {boletos}")
        self.lbl_new.setText(f"Novos: {new_count}")

    def _on_row_click(self, index):
        row = index.row()
        emails = self._email_model._emails
        if 0 <= row < len(emails):
            em = emails[row]
            if not em.get("opened"):
                em["opened"] = True
                self._email_model.refresh_row(row)
                import threading as _t
                _t.Thread(target=save_emails, args=(self.emails[:],), daemon=True).start()

    def _filter(self, text):
        text = text.lower()
        for row in range(len(self.emails)):
            em = self.emails[row]
            if not text:
                self.table_view.setRowHidden(row, False)
                continue
            haystack = (em.get("account","") + em.get("subject","") +
                        em.get("sender","") + em.get("value","") +
                        em.get("state","")).lower()
            self.table_view.setRowHidden(row, text not in haystack)

    def _open_email(self, index=None):
        row = index.row() if index else self.table_view.currentIndex().row()
        # Always get email from model — guaranteed to match what's displayed
        emails = self._email_model._emails
        if 0 <= row < len(emails):
            em = emails[row]
            self.editor = EmailEditor(em, self.cfg)
            self.stack.removeTab(2); self.stack.insertTab(2, self.editor, "editor")
            self._switch_tab(2)

    def _table_menu(self, pos):
        row = self.table_view.currentIndex().row()
        if row < 0: return
        # Use model index — guaranteed to match displayed row
        emails = self._email_model._emails
        if row >= len(emails): return
        menu = QMenu(self)
        menu.addAction("✏️  Abrir no Editor", self._open_email)
        menu.addAction("💾  Salvar Anexos", lambda: self._save_attachments(row))
        menu.addAction("🔍  Ver Código do Boleto", lambda: self._show_boleto(row))
        menu.addAction("↩️  Devolver para Inbox", lambda: self._return_email_to_inbox(row))
        menu.addAction("📅  Agendar Boleto", lambda: self._schedule_from_email(row))
        menu.addSeparator()
        menu.addAction("🗑  Excluir este", lambda: self._delete_row(row))
        menu.addAction("🗑  Apagar selecionados", self._delete_selected)
        menu.exec_(self.table.viewport().mapToGlobal(pos))

    def _return_email_to_inbox(self, row):
        if row >= len(self.emails): return
        em = self.emails[row]
        acc_email = em.get("account","")
        folder = em.get("folder","")
        uid = em.get("uid","")
        original_folder = em.get("original_folder") or folder or "INBOX"

        if not acc_email:
            QMessageBox.warning(self,"Zeus","Email sem conta associada."); return

        acc_info = next((a for a in self.cfg.get("accounts",[]) if a.get("email","") == acc_email), None)
        if not acc_info:
            QMessageBox.warning(self,"Zeus",f"Conta {acc_email} nao encontrada."); return

        to_addr  = em.get("to","")
        subject  = em.get("subject","")
        body     = em.get("body","")
        body_html= em.get("body_html","")
        sender   = em.get("sender","")

        # Parse sender name and email
        import re as _re
        m = _re.match(r'^(.*?)<(.+?)>$', sender)
        if m:
            from_name = m.group(1).strip().strip('"')
            from_addr = m.group(2).strip()
        else:
            from_name = sender
            from_addr = acc_email

        try:
            method = ""
            # Always fetch raw from server first — guarantees correct email
            raw = em.get("raw")
            if not raw:
                try:
                    imap = connect_imap(acc_info)
                    for try_folder in [folder, original_folder,
                                       "Processados", "INBOX"]:
                        try:
                            imap.select(try_folder)
                            uid_b = uid.encode() if isinstance(uid,str) else uid
                            _, data = imap.fetch(uid_b, "(RFC822)")
                            if data and data[0] and isinstance(data[0],tuple):
                                raw = data[0][1]
                                folder = try_folder; break
                        except: pass
                    imap.logout()
                except: pass

            if not raw:
                QMessageBox.warning(self,"Zeus",
                    f"Email nao encontrado no servidor.\nUID: {uid}\nPasta: {folder}")
                return

            # Send via SMTP using real raw
            try:
                send_via_smtp(acc_info, from_name, from_addr,
                              to_addr, subject, body, body_html,
                              em.get("attachments",[]), self.cfg,
                              delete_uid=uid, delete_folder=folder,
                              raw_original=raw)
                method = "SMTP"
            except Exception as smtp_err:
                # Fallback: IMAP APPEND
                import email as _em
                msg = _em.message_from_bytes(
                    raw if isinstance(raw,bytes) else raw.encode())
                for h in ["From","To","Subject"]:
                    if h in msg: del msg[h]
                msg["From"]    = f"{from_name} <{from_addr}>"
                msg["To"]      = to_addr
                msg["Subject"] = subject
                raw_bytes = msg.as_bytes()

                if folder and folder.upper() != original_folder.upper():
                    try:
                        imap.select(folder)
                        uid_b = uid.encode() if isinstance(uid,str) else uid
                        imap.store(uid_b, '+FLAGS', '\\Deleted')
                        imap.expunge()
                    except: pass
                imap.append(original_folder, None, None, raw_bytes)
                imap.logout()
                method = "IMAP"

            # Update local state
            em["folder"] = original_folder
            em["state"] = "NAO LIDO"
            save_emails(self.emails)

            if 0 <= row < len(self.emails):
                self._email_model.refresh_row(row)

            # Mark as seen so monitor won't re-capture
            if hasattr(self, '_coordinator') and self._coordinator:
                self._coordinator.mark_returned(uid, original_folder, acc_email)
            raw_cache = load_uid_cache()
            key = f"{acc_email}:{original_folder}"
            if key not in raw_cache: raw_cache[key] = []
            if uid and uid not in raw_cache[key]: raw_cache[key].append(uid)
            save_uid_cache(raw_cache)

            # Record in Enviados tab
            sent_record = dict(em)
            sent_record["sender"] = f"{from_name} <{from_addr}>"
            sent_record["sent_via"] = method
            if not hasattr(self, "sent_emails"): self.sent_emails = []
            self.sent_emails.append(sent_record)
            self._add_sent_row(sent_record)
            self._save_sent_emails()

            QMessageBox.information(self,"Zeus",f"Email enviado via {method}!\nDe: {from_name} <{from_addr}>\nVer em: aba ENVIADOS")

        except Exception as e:
            QMessageBox.critical(self,"Zeus",f"Erro ao devolver: {e}")




    def _remove_account_from_monitor(self, email_addr):
        """Remove account from config and stop its worker."""
        if QMessageBox.question(self, "Zeus",
                f"Remover a conta {email_addr}?\n\nEla será removida das configurações.") != QMessageBox.Yes:
            return
        # Stop worker if running
        if hasattr(self, '_coordinator') and self._coordinator:
            for w in getattr(self._coordinator, 'workers', []):
                if getattr(w, 'em_addr', '') == email_addr:
                    w.running = False
        # Remove from config
        self.cfg['accounts'] = [a for a in self.cfg.get('accounts', []) if a.get('email') != email_addr]
        save_config(self.cfg)
        self._update_acc_count()
        # Refresh monitor panel
        accounts = self.cfg.get('accounts', [])
        self.monitor_panel.refresh(accounts, self.monitors)
        self._status(f"Conta {email_addr} removida.")

    def _refresh_monitor(self):
        """Force immediate re-read — clears pending queues so workers rescan now."""
        if hasattr(self, '_coordinator') and self._coordinator:
            for w in getattr(self._coordinator, 'workers', []):
                try:
                    # Clear pending so they refill on next loop iteration
                    w._pending = {}
                except: pass
            self._status("🔄 Forçando nova leitura...")
        else:
            self._status("⚠️ Monitor não ativo. Clique em INICIAR.")

    def _clear_cache_and_rescan(self):
        """Clear IMAP UID cache to force rescan — but keep content hashes to prevent duplicates."""
        if QMessageBox.question(self, "Zeus",
            "Limpar cache IMAP e forcar nova varredura?\n\n"
            "O Zeus vai reler os emails do servidor.\n"
            "Emails ja capturados NAO aparecerao duplicados.") != QMessageBox.Yes:
            return
        # Clear IMAP UID cache only (NOT content hashes)
        try:
            if os.path.exists(UID_CACHE_FILE):
                os.remove(UID_CACHE_FILE)
        except: pass
        # Clear coordinator UID cache (single lock acquisition — sem deadlock)
        if hasattr(self, '_coordinator') and self._coordinator:
            try:
                with self._coordinator._cache_lock:
                    self._coordinator._uid_cache.clear()
                # Limpa _pending de cada worker (sem adquirir lock de novo)
                for w in getattr(self._coordinator, 'workers', []):
                    try: w._pending = {}
                    except: pass
            except Exception:
                pass
        self._status("🔄 Cache IMAP limpo — rescaneando (sem duplicatas)...")

    def _toggle_select_all(self, state):
        checked = (state == Qt.Checked)
        for em in self.emails: em["_checked"] = checked
        self._email_model.dataChanged.emit(
            self._email_model.index(0,0),
            self._email_model.index(len(self.emails)-1, 0))
        self._update_selected_count()

    def _on_selection_changed(self):
        self._update_selected_count()

    def _update_selected_count(self):
        selected = self._get_checked_rows()
        if selected:
            self.lbl_selected.setText(f"| {len(selected)} selecionado(s)")
        else:
            self.lbl_selected.setText("")

    def _get_checked_rows(self):
        checked = set(self._email_model.get_checked_rows())
        for idx in self.table_view.selectedIndexes():
            checked.add(idx.row())
        return sorted(checked, reverse=True)

    def _delete_selected(self):
        """Delete all checked/selected rows and permanently mark UIDs as seen."""
        rows = self._get_checked_rows()
        if not rows:
            QMessageBox.information(self, "Zeus", "Nenhuma mensagem selecionada.\nMarque as caixas ou clique nas linhas primeiro.")
            return
        if QMessageBox.question(self, "Zeus",
                f"Apagar {len(rows)} mensagem(ns) selecionada(s)?") != QMessageBox.Yes:
            return
        # Mark UIDs as permanently seen so monitor never re-captures
        uid_cache = load_uid_cache()
        for row in rows:
            if 0 <= row < len(self.emails):
                em = self.emails[row]
                uid    = em.get("uid","")
                folder = em.get("original_folder") or em.get("folder","INBOX")
                account= em.get("account","")
                if uid and account:
                    key = f"{account}:{folder}"
                    if key not in uid_cache: uid_cache[key] = []
                    if uid not in uid_cache[key]:
                        uid_cache[key].append(uid)
                    # Also mark in running coordinator
                    if hasattr(self,'_coordinator') and self._coordinator:
                        self._coordinator.mark_returned(uid, folder, account)
        save_uid_cache(uid_cache)

        self._email_model.remove_rows(rows)
        for row in rows:
            if 0 <= row < len(self.emails):
                self.emails.pop(row)
        self.chk_select_all.setChecked(False)
        self._update_stats()
        self.count_lbl.setText(f"{len(self.emails)} emails")
        import threading as _t
        _t.Thread(target=save_emails, args=(self.emails[:],), daemon=True).start()
        self._status(f"🗑 {len(rows)} mensagem(ns) apagada(s).")

    def _schedule_from_email(self, row):
        if row >= len(self.emails): return
        em = self.emails[row]
        self._add_scheduled(
            boleto_code=em.get("boleto_code",""),
            value=em.get("value",""),
            due=em.get("due_date","")
        )
        self._switch_tab(4)

    def _save_attachments(self, row):
        if row >= len(self.emails): return
        em = self.emails[row]
        atts = em.get("attachments",[])
        if not atts: QMessageBox.information(self,"Zeus","Nenhum anexo."); return
        folder = QFileDialog.getExistingDirectory(self,"Salvar Anexos em...")
        if folder:
            saved = 0
            for att in atts:
                path = att.get("path",""); name = att.get("name","arquivo")
                if path and os.path.exists(path):
                    shutil.copy(path, os.path.join(folder,name)); saved += 1
            QMessageBox.information(self,"Zeus",f"✅ {saved} anexo(s) salvos!")

    def _show_boleto(self, row):
        if row >= len(self.emails): return
        code = self.emails[row].get("boleto_code","")
        if code:
            msg = QMessageBox(self); msg.setWindowTitle("Zeus — Boleto")
            msg.setText(f"<b style='color:#e50914'>CÓDIGO DO BOLETO</b><br><br><code>{code}</code>")
            copy_btn = msg.addButton("COPIAR", QMessageBox.ActionRole)
            msg.addButton("FECHAR", QMessageBox.RejectRole)
            msg.exec_()
            if msg.clickedButton() == copy_btn: QApplication.clipboard().setText(code)
        else:
            QMessageBox.information(self,"Zeus","Nenhum boleto encontrado.")

    def _delete_row(self, row):
        if QMessageBox.question(self,"Zeus","Excluir este email?") == QMessageBox.Yes:
            emails = self._email_model._emails
            if 0 <= row < len(emails):
                em = emails[row]
                uid = em.get("uid",""); folder = em.get("original_folder") or em.get("folder","INBOX"); account = em.get("account","")
                if uid and account:
                    uid_cache = load_uid_cache()
                    key = f"{account}:{folder}"
                    if key not in uid_cache: uid_cache[key] = []
                    if uid not in uid_cache[key]: uid_cache[key].append(uid)
                    save_uid_cache(uid_cache)
                    if hasattr(self,'_coordinator') and self._coordinator:
                        self._coordinator.mark_returned(uid, folder, account)
                self.emails.pop(row)
            self._email_model.remove_rows([row])
            save_emails(self.emails)
            self._update_stats()

    def _status(self, msg): self.status_bar.showMessage(f"  {msg}")

    def closeEvent(self, event):
        self._stop_monitoring()
        # Save synchronously on close — never lose data
        try:
            save_emails(self.emails[:])
        except: pass
        event.accept()

# ── Entry Point ──────────────────────────────────────────────────────────────
# ── Login Screen ─────────────────────────────────────────────────────────────
# Uses zeus_security.py for PBKDF2 + hardware-bound encryption
AUTH_FILE = os.path.join(os.path.expanduser("~"), ".zeus_auth.json")

def _load_auth():
    try:
        with open(AUTH_FILE,"r") as f: return json.load(f)
    except: return {}

def _save_auth(data):
    try:
        with open(AUTH_FILE,"w") as f: json.dump(data, f)
    except: pass


class ZeusLoginWindow(QWidget):
    login_success = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.auth = _load_auth()
        self.is_first = not self.auth.get("pwd")
        self.attempts = 0
        self.setWindowTitle("ZEUS — Email Monitor")
        self.setFixedSize(460, 540)
        self.setStyleSheet("""
            QWidget { background:#0a0a0a; color:#e5e5e5; font-family:Arial; }
            QLineEdit {
                background:#1a1a1a; border:1px solid #2a2a2a;
                border-radius:6px; padding:12px 16px;
                font-size:15px; color:#e5e5e5;
            }
            QLineEdit:focus { border:1px solid #e50914; }
            QPushButton#btn_login {
                background:#e50914; color:#fff; border:none;
                border-radius:6px; padding:14px; font-size:14px;
                font-weight:700; letter-spacing:1px;
            }
            QPushButton#btn_login:hover { background:#ff1a24; }
            QPushButton#btn_link {
                background:transparent; color:#404040;
                border:none; font-size:11px;
                text-decoration:underline;
            }
            QPushButton#btn_link:hover { color:#e5e5e5; }
        """)
        self._build()

    def _build(self):
        vl = QVBoxLayout(self)
        vl.setContentsMargins(50,40,50,30)
        vl.setSpacing(0)

        # Logo
        ico = QLabel("⚡"); ico.setAlignment(Qt.AlignCenter)
        ico.setStyleSheet("font-size:56px; margin-bottom:4px;")
        vl.addWidget(ico)

        title = QLabel("ZEUS"); title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color:#e50914;font-size:32px;font-weight:900;letter-spacing:8px;")
        vl.addWidget(title)

        sub = QLabel("EMAIL MONITOR"); sub.setAlignment(Qt.AlignCenter)
        sub.setStyleSheet("color:#2a2a2a;font-size:10px;letter-spacing:4px;margin-bottom:32px;")
        vl.addWidget(sub)

        lbl = QLabel("CRIE SUA SENHA" if self.is_first else "DIGITE SUA SENHA")
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet("color:#404040;font-size:10px;font-weight:700;letter-spacing:2px;margin-bottom:16px;")
        vl.addWidget(lbl)

        self.f_pwd = QLineEdit(); self.f_pwd.setEchoMode(QLineEdit.Password)
        self.f_pwd.setPlaceholderText("Senha"); self.f_pwd.setFixedHeight(48)
        self.f_pwd.returnPressed.connect(self._submit)
        vl.addWidget(self.f_pwd)

        vl.addSpacing(10)

        self.f_confirm = QLineEdit(); self.f_confirm.setEchoMode(QLineEdit.Password)
        self.f_confirm.setPlaceholderText("Confirmar senha"); self.f_confirm.setFixedHeight(48)
        self.f_confirm.returnPressed.connect(self._submit)
        self.f_confirm.setVisible(self.is_first)
        vl.addWidget(self.f_confirm)

        vl.addSpacing(6)

        # Show password toggle
        hl = QHBoxLayout()
        self.chk_show = QCheckBox("Mostrar senha")
        self.chk_show.setStyleSheet("color:#404040;font-size:11px;")
        self.chk_show.stateChanged.connect(self._toggle)
        hl.addWidget(self.chk_show); hl.addStretch()
        vl.addLayout(hl)

        vl.addSpacing(20)

        self.btn = QPushButton("CRIAR E ENTRAR" if self.is_first else "ENTRAR")
        self.btn.setObjectName("btn_login"); self.btn.setFixedHeight(50)
        self.btn.clicked.connect(self._submit)
        vl.addWidget(self.btn)

        vl.addSpacing(12)

        self.lbl_status = QLabel(""); self.lbl_status.setAlignment(Qt.AlignCenter)
        self.lbl_status.setStyleSheet("font-size:12px;"); self.lbl_status.setWordWrap(True)
        vl.addWidget(self.lbl_status)

        vl.addStretch()

        if not self.is_first:
            btn_forgot = QPushButton("Esqueci a senha")
            btn_forgot.setObjectName("btn_link")
            btn_forgot.clicked.connect(self._forgot)
            vl.addWidget(btn_forgot)

        foot = QLabel("ZEUS Email Monitor"); foot.setAlignment(Qt.AlignCenter)
        foot.setStyleSheet("color:#1a1a1a;font-size:10px;")
        vl.addWidget(foot)

        QTimer.singleShot(100, self.f_pwd.setFocus)

    def _toggle(self, state):
        mode = QLineEdit.Normal if state else QLineEdit.Password
        self.f_pwd.setEchoMode(mode); self.f_confirm.setEchoMode(mode)

    def _shake(self):
        pos = self.pos()
        for i, dx in enumerate([12,-12,9,-9,6,-6,3,-3,0]):
            QTimer.singleShot(i*25, lambda x=dx: self.move(pos.x()+x, pos.y()))

    def _submit(self):
        pwd = self.f_pwd.text().strip()
        if not pwd:
            self._shake(); self.lbl_status.setText("Digite a senha."); return

        auth = get_auth() if _ZEUS_SECURITY else None

        if self.is_first:
            if len(pwd) < 4:
                self._shake(); self.lbl_status.setText("Minimo 4 caracteres."); return
            if pwd != self.f_confirm.text():
                self._shake(); self.lbl_status.setText("Senhas nao coincidem.")
                self.f_confirm.clear(); self.f_confirm.setFocus(); return
            self.btn.setEnabled(False); self.btn.setText("Criando...")
            self.lbl_status.setStyleSheet("color:#404040;font-size:12px;")
            self.lbl_status.setText("Criando senha segura...")
            pwd_copy = pwd
            self.f_pwd.setText(""); self.f_confirm.setText("")
            done = [False]

            def _create():
                try:
                    if auth:
                        auth.set_password(pwd_copy)
                    else:
                        import hashlib as _h
                        _save_auth({"pwd": _h.sha256(pwd_copy.encode()).hexdigest()})
                except Exception:
                    pass
                done[0] = True

            threading.Thread(target=_create, daemon=True).start()

            def _poll_create():
                if not done[0]:
                    QTimer.singleShot(100, _poll_create)
                    return
                self.lbl_status.setStyleSheet("color:#2ecc40;font-size:12px;")
                self.lbl_status.setText("Senha criada com seguranca!")
                QTimer.singleShot(500, self._grant)

            QTimer.singleShot(100, _poll_create)

        else:
            if auth:
                self.btn.setEnabled(False); self.btn.setText("Verificando...")
                self.lbl_status.setStyleSheet("color:#404040;font-size:12px;")
                self.lbl_status.setText("Verificando...")
                pwd_copy = pwd
                self.f_pwd.setText("")
                result = [None]

                def _verify():
                    try:
                        result[0] = auth.verify(pwd_copy)
                    except Exception:
                        result[0] = False

                threading.Thread(target=_verify, daemon=True).start()

                def _poll_verify():
                    if result[0] is None:
                        QTimer.singleShot(100, _poll_verify)
                        return
                    self._on_verify_result(result[0], auth)

                QTimer.singleShot(100, _poll_verify)
            else:
                import hashlib as _h, hmac as _hmac
                ok = _hmac.compare_digest(
                    self.auth.get("pwd",""),
                    _h.sha256(pwd.encode()).hexdigest()
                )
                self.f_pwd.setText("")
                self._on_verify_result(ok, None)

    def _on_verify_result(self, ok, auth):
        self.btn.setEnabled(True); self.btn.setText("ENTRAR")
        if ok:
            self.lbl_status.setStyleSheet("color:#2ecc40;font-size:12px;")
            self.lbl_status.setText("Acesso liberado!")
            self.btn.setEnabled(False)
            if auth:
                auth.start_session(timeout_minutes=60, lock_callback=self._on_session_timeout)
            QTimer.singleShot(400, self._grant)
        else:
            self.attempts += 1
            left = max(0, 5 - self.attempts)
            self.lbl_status.setStyleSheet("color:#e50914;font-size:12px;")
            self.lbl_status.setText(
                f"Senha incorreta. {left} tentativa(s)." if left else "Bloqueado 30s.")
            self.f_pwd.setFocus(); self._shake()
            if self.attempts >= 5:
                self.btn.setEnabled(False)
                QTimer.singleShot(30000, lambda: [
                    self.btn.setEnabled(True), setattr(self,'attempts',0),
                    self.lbl_status.setText("")])

    def _on_session_timeout(self):
        """Called when session times out due to inactivity."""
        # Must run on UI thread
        QTimer.singleShot(0, self._lock_screen)

    def _lock_screen(self):
        """Re-show login screen after session timeout."""
        from PyQt5.QtWidgets import QApplication
        for w in QApplication.topLevelWidgets():
            w.hide()
        login = ZeusLoginWindow()
        def unlock():
            for w in QApplication.topLevelWidgets():
                if w is not login: w.show()
        login.login_success.connect(unlock)
        login.show()

    def _forgot(self):
        r = QMessageBox.question(self, "Redefinir senha",
            "Apagar senha e reconfigurar?\nSuas contas e emails serao mantidos.",
            QMessageBox.Yes | QMessageBox.No)
        if r == QMessageBox.Yes:
            try: os.remove(AUTH_FILE)
            except: pass
            QMessageBox.information(self, "ZEUS", "Senha removida. Reinicie o ZEUS.")
            QApplication.quit()

    def _grant(self):
        self.login_success.emit()
        self.close()



def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    app.setApplicationName("ZEUS Email Monitor")

    # Anti-tamper check (disabled in EXE mode to avoid false positives)
    # if _ZEUS_SECURITY:
    #     passed, reason = AntiTamper.run_checks(allow_debug=False, allow_vm=True)
    #     if not passed and reason == "debugger_detected":
    #         sys.exit(0)

    login = ZeusLoginWindow()
    def _on_login():
        w = ZeusMainWindow()
        # Register activity on any key/mouse
        if _ZEUS_SECURITY:
            auth = get_auth()
            if auth:
                w.installEventFilter(w)
        w.show()
        app._main_window = w
    login.login_success.connect(_on_login)
    login.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
