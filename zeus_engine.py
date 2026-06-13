"""
ZEUS Engine — Core processing components running outside the GUI thread.

Components:
  1. ZeusDB          — SQLite database replacing JSON files
  2. BoletoClassifier — ML model (Naive Bayes) for boleto detection
  3. PriorityEmailQueue — heapq-based priority queue
  4. IMAPIdleWorker   — IMAP IDLE push notifications
  5. ProcessWorker    — multiprocessing worker (per account)
"""
import os, sqlite3, json, hashlib, time, re, queue, threading
import multiprocessing as mp
from datetime import datetime
from pathlib import Path

DB_PATH = Path.home() / ".zeus_db.sqlite"

# ─── 1. SQLite Database ───────────────────────────────────────────────────────
class ZeusDB:
    """
    Thread-safe SQLite wrapper.
    Replaces zeus_emails.json, zeus_uid_cache.json, zeus_seen_hashes.json.
    WAL mode = concurrent reads + writes without locking.
    """
    def __init__(self, path=DB_PATH):
        self.path = str(path)
        self._local = threading.local()
        self._init_schema()

    def _conn(self):
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            c = sqlite3.connect(self.path, check_same_thread=False)
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA cache_size=10000")
            c.row_factory = sqlite3.Row
            self._local.conn = c
        return self._local.conn

    def _init_schema(self):
        c = self._conn()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS emails (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                uid         TEXT NOT NULL,
                account     TEXT NOT NULL,
                folder      TEXT,
                subject     TEXT,
                sender      TEXT,
                to_addr     TEXT,
                date_str    TEXT,
                state       TEXT DEFAULT 'NAO LIDO',
                value       TEXT,
                due_date    TEXT,
                boleto_code TEXT,
                has_boleto  INTEGER DEFAULT 0,
                body        TEXT,
                body_html   TEXT,
                opened      INTEGER DEFAULT 0,
                content_hash TEXT,
                captured_at TEXT,
                UNIQUE(uid, account)
            );
            CREATE INDEX IF NOT EXISTS idx_emails_account ON emails(account);
            CREATE INDEX IF NOT EXISTS idx_emails_date    ON emails(date_str DESC);
            CREATE INDEX IF NOT EXISTS idx_emails_boleto  ON emails(has_boleto);
            CREATE INDEX IF NOT EXISTS idx_emails_hash    ON emails(content_hash);

            CREATE TABLE IF NOT EXISTS seen_uids (
                account TEXT NOT NULL,
                folder  TEXT NOT NULL,
                uid     TEXT NOT NULL,
                PRIMARY KEY (account, folder, uid)
            );
            CREATE INDEX IF NOT EXISTS idx_seen ON seen_uids(account, folder);

            CREATE TABLE IF NOT EXISTS sent_emails (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                account TEXT,
                subject TEXT,
                to_addr TEXT,
                sent_at TEXT,
                method  TEXT,
                data    TEXT
            );

            CREATE TABLE IF NOT EXISTS scheduled (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                desc         TEXT,
                code         TEXT,
                value        TEXT,
                due          TEXT,
                scheduled_for TEXT,
                paid         INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS ml_training (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                text    TEXT NOT NULL,
                label   INTEGER NOT NULL,
                added_at TEXT
            );
        """)
        c.commit()

    # ── Email CRUD ────────────────────────────────────────────────────────────
    def insert_email(self, em: dict) -> bool:
        """Insert email. Returns False if duplicate."""
        try:
            c = self._conn()
            c.execute("""
                INSERT OR IGNORE INTO emails
                (uid, account, folder, subject, sender, to_addr, date_str,
                 state, value, due_date, boleto_code, has_boleto,
                 body, body_html, opened, content_hash, captured_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                em.get("uid",""), em.get("account",""), em.get("folder",""),
                em.get("subject",""), em.get("sender",""), em.get("to",""),
                em.get("date",""), em.get("state","NAO LIDO"),
                em.get("value",""), em.get("due_date",""),
                em.get("boleto_code",""), 1 if em.get("has_boleto") else 0,
                em.get("body","")[:50000],  # cap at 50KB
                em.get("body_html","")[:50000],
                1 if em.get("opened") else 0,
                em.get("_hash",""),
                datetime.now().isoformat()
            ))
            c.commit()
            return c.execute("SELECT changes()").fetchone()[0] > 0
        except Exception as e:
            return False

    def load_emails(self, limit=2000, offset=0) -> list:
        """Load emails ordered by captured_at DESC (newest first)."""
        c = self._conn()
        rows = c.execute("""
            SELECT * FROM emails
            ORDER BY captured_at DESC
            LIMIT ? OFFSET ?
        """, (limit, offset)).fetchall()
        return [dict(r) for r in rows]

    def mark_opened(self, uid, account):
        c = self._conn()
        c.execute("UPDATE emails SET opened=1 WHERE uid=? AND account=?", (uid, account))
        c.commit()

    def delete_emails(self, ids: list):
        c = self._conn()
        c.executemany("DELETE FROM emails WHERE id=?", [(i,) for i in ids])
        c.commit()

    def search_emails(self, query: str) -> list:
        c = self._conn()
        q = f"%{query}%"
        rows = c.execute("""
            SELECT * FROM emails
            WHERE subject LIKE ? OR sender LIKE ? OR account LIKE ? OR value LIKE ?
            ORDER BY captured_at DESC LIMIT 500
        """, (q, q, q, q)).fetchall()
        return [dict(r) for r in rows]

    # ── UID Cache ─────────────────────────────────────────────────────────────
    def is_uid_seen(self, account, folder, uid) -> bool:
        c = self._conn()
        r = c.execute(
            "SELECT 1 FROM seen_uids WHERE account=? AND folder=? AND uid=?",
            (account, folder, uid)).fetchone()
        return r is not None

    def mark_uid_seen(self, account, folder, uid):
        c = self._conn()
        c.execute(
            "INSERT OR IGNORE INTO seen_uids(account,folder,uid) VALUES(?,?,?)",
            (account, folder, uid))
        c.commit()

    def mark_uids_seen_batch(self, entries: list):
        """entries = [(account, folder, uid), ...]"""
        c = self._conn()
        c.executemany(
            "INSERT OR IGNORE INTO seen_uids(account,folder,uid) VALUES(?,?,?)",
            entries)
        c.commit()

    def get_seen_uids(self, account, folder) -> set:
        c = self._conn()
        rows = c.execute(
            "SELECT uid FROM seen_uids WHERE account=? AND folder=?",
            (account, folder)).fetchall()
        return {r[0] for r in rows}

    def is_hash_seen(self, h: str) -> bool:
        c = self._conn()
        r = c.execute("SELECT 1 FROM emails WHERE content_hash=?", (h,)).fetchone()
        return r is not None

    # ── ML Training data ──────────────────────────────────────────────────────
    def add_training_sample(self, text: str, is_boleto: bool):
        c = self._conn()
        c.execute("INSERT INTO ml_training(text,label,added_at) VALUES(?,?,?)",
                  (text[:5000], 1 if is_boleto else 0, datetime.now().isoformat()))
        c.commit()

    def get_training_data(self):
        c = self._conn()
        rows = c.execute("SELECT text, label FROM ml_training").fetchall()
        return [(r[0], r[1]) for r in rows]

    # ── Scheduled ─────────────────────────────────────────────────────────────
    def get_scheduled(self) -> list:
        c = self._conn()
        return [dict(r) for r in c.execute("SELECT * FROM scheduled ORDER BY scheduled_for").fetchall()]

    def add_scheduled(self, s: dict):
        c = self._conn()
        c.execute("""INSERT INTO scheduled(desc,code,value,due,scheduled_for,paid)
                     VALUES(?,?,?,?,?,?)""",
                  (s.get("desc",""), s.get("code",""), s.get("value",""),
                   s.get("due",""), s.get("scheduled_for",""), 0))
        c.commit()

    def mark_paid(self, sid: int):
        c = self._conn()
        c.execute("UPDATE scheduled SET paid=1 WHERE id=?", (sid,))
        c.commit()


# ─── 2. Boleto ML Classifier ──────────────────────────────────────────────────
class BoletoClassifier:
    """
    Naive Bayes + TF-IDF classifier.
    Learns from captured emails to detect boletos with high precision.
    Falls back to regex if not enough training data.
    Model is retrained automatically as more emails accumulate.
    """
    MODEL_PATH = Path.home() / ".zeus_ml_model.pkl"
    MIN_SAMPLES = 10  # minimum samples before ML kicks in

    def __init__(self, db: ZeusDB):
        self.db = db
        self._clf = None
        self._vec = None
        self._trained = False
        self._lock = threading.Lock()
        # Try to load existing model
        self._load_model()

    def _load_model(self):
        try:
            import pickle
            if self.MODEL_PATH.exists():
                with open(self.MODEL_PATH, 'rb') as f:
                    self._vec, self._clf = pickle.load(f)
                    self._trained = True
        except: pass

    def train(self, force=False):
        """Train or retrain the model from DB samples."""
        with self._lock:
            try:
                samples = self.db.get_training_data()
                if len(samples) < self.MIN_SAMPLES and not force:
                    return False
                from sklearn.naive_bayes import MultinomialNB
                from sklearn.feature_extraction.text import TfidfVectorizer
                texts  = [s[0] for s in samples]
                labels = [s[1] for s in samples]
                vec = TfidfVectorizer(max_features=5000, ngram_range=(1,2),
                                      analyzer='char_wb', min_df=1)
                X = vec.fit_transform(texts)
                clf = MultinomialNB(alpha=0.1)
                clf.fit(X, labels)
                self._vec = vec
                self._clf = clf
                self._trained = True
                # Save model
                import pickle
                with open(self.MODEL_PATH, 'wb') as f:
                    pickle.dump((vec, clf), f)
                return True
            except Exception as e:
                return False

    def predict(self, subject: str, body: str) -> tuple:
        """
        Returns (is_boleto: bool, confidence: float, method: str)
        """
        text = f"{subject} {body[:2000]}"

        # ML prediction if trained
        if self._trained and self._vec and self._clf:
            try:
                X = self._vec.transform([text])
                prob = self._clf.predict_proba(X)[0]
                label = self._clf.predict(X)[0]
                conf  = prob[label]
                if conf > 0.6:
                    return (bool(label), float(conf), f"ml:{conf:.2f}")
            except: pass

        # Fallback: regex scoring
        score = 0
        text_lower = text.lower()
        KEYWORDS = ["boleto","fatura","vencimento","pagamento","cobrança",
                    "duplicata","nota fiscal","nfe","linha digitável",
                    "código de barras","valor do documento","nosso número",
                    "local de pagamento","cedente","sacado","recibo"]
        score += sum(2 for kw in KEYWORDS if kw in text_lower)
        # Barcode pattern
        import re
        if re.search(r'\d{44,48}', text): score += 10
        if re.search(r'\d{5}\.\d{5}\s\d{5}\.\d{6}', text): score += 10
        return (score >= 4, min(score/20.0, 1.0), f"regex:{score}")

    def learn(self, subject: str, body: str, is_boleto: bool):
        """Add sample and retrain periodically."""
        text = f"{subject} {body[:2000]}"
        self.db.add_training_sample(text, is_boleto)
        # Retrain every 50 new samples
        count = len(self.db.get_training_data())
        if count % 50 == 0:
            threading.Thread(target=self.train, daemon=True).start()


# ─── 3. Priority Email Queue ──────────────────────────────────────────────────
import heapq

class PriorityEmailQueue:
    """
    Priority queue for email processing.
    PDF boletos → highest priority (0)
    Subject boleto keywords → high priority (1)
    Unread with attachments → medium (2)
    Regular unread → low (3)
    Read/old → lowest (4)
    """
    def __init__(self):
        self._heap = []
        self._lock = threading.Lock()
        self._counter = 0  # tiebreaker

    def _priority(self, num_bytes, subject, att_names, is_unread):
        subj = subject.lower()
        att_lower = [n.lower() for n in att_names]
        has_pdf = any(n.endswith(('.pdf','.xml')) for n in att_lower)
        has_boleto_name = any(
            kw in n for n in att_lower
            for kw in ['boleto','fatura','nfe','duplicata','nota']
        )
        subj_boleto = any(kw in subj for kw in
            ['boleto','fatura','vencimento','cobrança','pagamento','duplicata'])

        if has_pdf and has_boleto_name: return 0
        if has_pdf:                     return 1
        if subj_boleto:                 return 2
        if is_unread:                   return 3
        return 4

    def put(self, num_bytes, subject="", att_names=None, is_unread=True):
        with self._lock:
            p = self._priority(num_bytes, subject, att_names or [], is_unread)
            heapq.heappush(self._heap, (p, self._counter, num_bytes))
            self._counter += 1

    def get_batch(self, n=10):
        """Get up to n highest-priority items."""
        with self._lock:
            batch = []
            for _ in range(min(n, len(self._heap))):
                _, _, num = heapq.heappop(self._heap)
                batch.append(num)
            return batch

    def __len__(self):
        return len(self._heap)


# ─── 4. IMAP IDLE Worker ─────────────────────────────────────────────────────
class IMAPIdleWorker(threading.Thread):
    """
    Uses IMAP IDLE command for push notifications.
    Server pushes EXISTS/RECENT when new email arrives.
    Much more efficient than polling every N seconds.
    Falls back to polling if server doesn't support IDLE.
    """
    def __init__(self, acc, on_new_mail_cb, status_cb):
        super().__init__(daemon=True)
        self.acc = acc
        self.on_new_mail = on_new_mail_cb
        self.status_cb   = status_cb
        self.running     = True
        self.imap        = None
        self.supports_idle = False

    def stop(self):
        self.running = False
        if self.imap:
            try: self.imap.send(b"DONE\r\n")
            except: pass
            try: self.imap.logout()
            except: pass

    def _connect(self):
        from zeus_mail import connect_imap
        self.imap = connect_imap(self.acc)
        # Check IDLE support
        cap = self.imap.capability()[1][0].decode()
        self.supports_idle = 'IDLE' in cap

    def run(self):
        em_addr = self.acc["email"]
        while self.running:
            try:
                if not self.imap:
                    self.status_cb(em_addr, "🔌 Conectando IDLE...")
                    self._connect()
                    self.status_cb(em_addr,
                        f"✅ {'IDLE' if self.supports_idle else 'POLL'}")

                self.imap.select("INBOX")

                if self.supports_idle:
                    # Send IDLE command
                    self.imap.send(b"a001 IDLE\r\n")
                    # Wait for server push (up to 28 min — server timeout)
                    self.imap.sock.settimeout(1700)
                    while self.running:
                        try:
                            line = self.imap.readline()
                            if not line: break
                            line_s = line.decode('utf-8', errors='replace').strip()
                            # New mail: "* N EXISTS" or "* N RECENT"
                            if 'EXISTS' in line_s or 'RECENT' in line_s:
                                self.on_new_mail(em_addr)
                                break
                            if line_s.startswith('+'):
                                pass  # IDLE continuation, keep waiting
                        except:
                            break
                    # Exit IDLE
                    try: self.imap.send(b"DONE\r\n")
                    except: pass
                else:
                    # Fallback polling every 30s
                    time.sleep(30)
                    self.on_new_mail(em_addr)

            except Exception as e:
                self.status_cb(em_addr, f"❌ {str(e)[:35]}")
                self.imap = None
                time.sleep(15)


# ─── 5. Multiprocess Worker ───────────────────────────────────────────────────
def _process_account_worker(acc_dict, cfg_dict, result_queue, cmd_queue):
    """
    Runs in a SEPARATE PROCESS — bypasses Python GIL completely.
    Each account gets its own CPU core.
    Communicates via multiprocessing.Queue (pickle-safe).
    """
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from zeus_mail import (connect_imap, decode_str, extract_value,
                           extract_due, BOLETO_PATTERNS, BOLETO_BODY_KEYWORDS,
                           _imap_connect_one)
    import email as email_mod
    import re, time, imaplib
    from datetime import datetime, timedelta

    em_addr  = acc_dict["email"]
    per_cycle = int(cfg_dict.get("emails_per_read", 10))
    max_days  = int(cfg_dict.get("max_days_old", 4))
    folders   = cfg_dict.get("folders", ["INBOX"])
    pending   = {}
    imap      = None

    def status(msg): result_queue.put(("status", em_addr, msg))
    def emit(em):    result_queue.put(("email",  em_addr, em))

    while True:
        # Check for stop command
        try:
            cmd = cmd_queue.get_nowait()
            if cmd == "STOP": break
        except: pass

        try:
            if not imap:
                status("🔌 Conectando...")
                imap = connect_imap(acc_dict)
                status("✅ Conectado")

            try: imap.noop()
            except: imap = None; continue

            # Fill pending
            since = (datetime.now() - timedelta(days=max_days)).strftime("%d-%b-%Y")
            for folder in folders:
                if not pending.get(folder):
                    imap.select(folder, readonly=True)
                    _, msgs = imap.search(None, f"SINCE {since}")
                    ids = (msgs[0] or b"").split()
                    pending[folder] = list(reversed(ids))[:2000]
                    if ids: status(f"🔍 {len(ids)} emails em {folder}")

            total_pending = sum(len(v) for v in pending.values())
            if total_pending == 0:
                status(f"✅ Completo | ⏳")
                time.sleep(int(cfg_dict.get("cycle_interval", 60)))
                continue

            for folder in folders:
                batch = pending.get(folder, [])[:per_cycle]
                pending[folder] = pending.get(folder, [])[per_cycle:]
                if not batch: continue

                imap.select(folder)
                status(f"📖 {len(batch)} | {total_pending-len(batch)} restantes")

                for num in batch:
                    try:
                        _, data = imap.fetch(num, "(RFC822)")
                        raw = data[0][1]
                        msg = email_mod.message_from_bytes(raw)
                        subject  = decode_str(msg.get("Subject",""))
                        sender   = decode_str(msg.get("From",""))
                        to_addr  = decode_str(msg.get("To",""))
                        date_str = msg.get("Date","")
                        body_text = ""; body_html = ""; attachments = []

                        for part in msg.walk():
                            ct = part.get_content_type()
                            cd = str(part.get("Content-Disposition",""))
                            if ct == "text/plain" and "attachment" not in cd:
                                try: body_text += part.get_payload(decode=True).decode("utf-8",errors="replace")
                                except: pass
                            elif ct == "text/html" and "attachment" not in cd:
                                try: body_html += part.get_payload(decode=True).decode("utf-8",errors="replace")
                                except: pass
                            fname = decode_str(part.get_filename() or "")
                            if fname:
                                attachments.append({"name": fname, "path": ""})

                        # Detect boleto
                        full = body_text + " " + re.sub(r'<[^>]+',' ', body_html)
                        has_barcode = any(p.search(full) for p in BOLETO_PATTERNS)
                        kw_hits = sum(1 for k in BOLETO_BODY_KEYWORDS if k in full.lower())
                        has_boleto = has_barcode or kw_hits >= 2
                        boleto_code = ""
                        for p in BOLETO_PATTERNS:
                            m = p.search(full)
                            if m: boleto_code = re.sub(r'[\s\.]','',m.group(0)); break

                        value    = extract_value(body_text) or extract_value(body_html)
                        due_date = extract_due(body_text)   or extract_due(body_html)
                        has_pdf  = any(a["name"].lower().endswith((".pdf",".xml")) for a in attachments)

                        if not has_boleto and not has_pdf:
                            subj_lower = subject.lower()
                            has_boleto = any(k in subj_lower for k in
                                ["boleto","fatura","vencimento","lembrete","cobrança","pagamento"])

                        if not has_boleto and not has_pdf: continue

                        emit({
                            "uid": num.decode(), "folder": folder,
                            "original_folder": folder,
                            "subject": subject, "sender": sender,
                            "to": to_addr, "date": date_str,
                            "state": "NAO LIDO", "value": value,
                            "due_date": due_date, "attachments": attachments,
                            "has_boleto": has_boleto, "boleto_code": boleto_code,
                            "body": body_text[:10000], "body_html": "",
                            "account": em_addr, "has_pdf": has_pdf,
                        })
                    except: pass

            time.sleep(0.1)

        except Exception as e:
            status(f"❌ {str(e)[:40]}")
            imap = None
            time.sleep(15)


class MultiProcessCoordinator:
    """
    Spawns one OS process per account.
    Drains results via Queue and forwards to UI via callbacks.
    """
    def __init__(self, accounts, cfg, email_cb, status_cb):
        self.accounts   = accounts
        self.cfg        = cfg
        self.email_cb   = email_cb
        self.status_cb  = status_cb
        self._procs     = []
        self._result_q  = mp.Queue(maxsize=1000)
        self._cmd_queues= []
        self._drain_thread = None
        self.running    = False

    def start(self):
        self.running = True
        max_proc = int(self.cfg.get("max_threads", 20))
        for acc in self.accounts[:max_proc]:
            cmd_q = mp.Queue()
            p = mp.Process(
                target=_process_account_worker,
                args=(dict(acc), dict(self.cfg), self._result_q, cmd_q),
                daemon=True
            )
            p.start()
            self._procs.append(p)
            self._cmd_queues.append(cmd_q)
            time.sleep(0.05)
        self._drain_thread = threading.Thread(target=self._drain, daemon=True)
        self._drain_thread.start()

    def _drain(self):
        while self.running:
            try:
                item = self._result_q.get(timeout=0.1)
                kind = item[0]
                if kind == "email":
                    _, addr, em = item
                    self.email_cb(em)
                elif kind == "status":
                    _, addr, msg = item
                    self.status_cb(addr, msg)
            except: pass

    def stop(self):
        self.running = False
        for q in self._cmd_queues:
            try: q.put_nowait("STOP")
            except: pass
        for p in self._procs:
            p.terminate()
            p.join(timeout=3)
        self._procs.clear()
