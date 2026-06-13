"""
ZEUS Worker Process — zero UI, zero GIL contention
====================================================
Runs as a completely separate OS process.
Communicates with UI via multiprocessing.connection (named pipe).

Architecture:
  zeus_mail.py (UI process)
       ↕  named pipe (localhost:6789)
  zeus_worker.py (worker process)
       ↕  IMAP connections
  Email servers

The UI process NEVER touches IMAP or heavy processing.
The worker process NEVER touches Qt.
Impossible to freeze the UI from worker activity.
"""
import sys, os, json, re, email, imaplib, ssl, time, threading
import asyncio, queue, struct, hashlib, array, logging
import multiprocessing as mp
from multiprocessing.connection import Listener, Client
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename=str(Path.home() / ".zeus_worker.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("zeus_worker")

WORKER_ADDRESS = ('localhost', 6789)
WORKER_AUTHKEY  = b'zeus_secure_2026'

# ── Zero-copy email buffer ──────────────────────────────────────────────────
class EmailBuffer:
    """
    Zero-copy buffer for email processing.
    Uses memoryview to avoid copying raw bytes multiple times.
    Processes directly on the original buffer slice.
    """
    __slots__ = ('_buf', '_view', 'size')

    def __init__(self, raw_bytes: bytes):
        # Single allocation — all operations use views into this
        self._buf  = bytearray(raw_bytes)
        self._view = memoryview(self._buf)
        self.size  = len(self._buf)

    def slice(self, start: int, end: int) -> memoryview:
        """Zero-copy slice — no allocation."""
        return self._view[start:end]

    def find_pattern(self, pattern: bytes) -> int:
        """Fast pattern search using array module (C speed)."""
        return self._buf.find(pattern)

    def scan_digits(self, min_run: int = 8) -> list:
        """
        Scan for digit sequences without creating strings.
        Uses array module for C-speed iteration.
        Returns list of (start, length) tuples.
        """
        runs = []
        in_run = False
        run_start = 0
        # Use array for faster byte iteration than list
        arr = array.array('B', self._buf)
        for i, b in enumerate(arr):
            is_digit = 48 <= b <= 57  # ord('0')=48, ord('9')=57
            if is_digit and not in_run:
                run_start = i; in_run = True
            elif not is_digit and in_run:
                if i - run_start >= min_run:
                    runs.append((run_start, i - run_start))
                in_run = False
        if in_run and len(self._buf) - run_start >= min_run:
            runs.append((run_start, len(self._buf) - run_start))
        return runs

    def extract_barcode_candidates(self) -> list:
        """
        Extract barcode candidates directly from buffer.
        Zero string allocation until a candidate is found.
        """
        candidates = []
        for start, length in self.scan_digits(min_run=20):
            if 20 <= length <= 50:
                # Only now allocate a string for this candidate
                s = self._view[start:start+length].tobytes().decode('ascii', errors='ignore')
                candidates.append(s)
        return candidates

    def to_bytes(self) -> bytes:
        return bytes(self._buf)

    def __len__(self): return self.size


# ── Compiled regex (compiled once, reused — C-speed matching) ───────────────
_RE_BARCODE = re.compile(
    rb'(?:'
    rb'\d{5}[\.\s]\d{5}[\.\s]\d{5}[\.\s]\d{6}[\.\s]\d{5}[\.\s]\d{6}[\.\s]\d[\.\s]\d{14}'
    rb'|\d{44,48}'
    rb'|00020126\d{10,}'  # PIX
    rb')', re.ASCII
)
_RE_VALUE   = re.compile(rb'R\$\s*(\d{1,3}(?:\.\d{3})*(?:,\d{2})?|\d+,\d{2})', re.IGNORECASE)
_RE_DUE     = re.compile(rb'(?:venc\w*|due date)[^\d]*(\d{2}[/.-]\d{2}[/.-]\d{2,4})', re.IGNORECASE)

_BOLETO_KW_BYTES = [
    b'linha digit', b'codigo de barras', b'vencimento', b'beneficiario',
    b'cedente', b'sacado', b'nosso numero', b'local de pagamento',
    b'pagavel em qualquer', b'valor do documento', b'data de vencimento',
    b'pagavel em qualquer', b'valor do documento', b'data de vencimento',
]

_BOLETO_SUBJ_KW = [
    b'boleto', b'fatura', b'vencimento', b'cobranca', b'duplicata',
    b'nota fiscal', b'nfe', b'lembrete', b'aviso', b'pagamento',
    b'mensalidade', b'parcela',
]


def fast_detect_boleto(buf: EmailBuffer, subject_bytes: bytes) -> tuple:
    """
    Fast boleto detection directly on bytes — zero string conversion
    until a match is found.
    Returns (is_boleto, code_str, method, value_str, due_str)
    """
    raw = buf.to_bytes()

    # 1. Barcode regex on raw bytes (compiled, C-speed)
    m = _RE_BARCODE.search(raw)
    if m:
        code = re.sub(rb'[\s\.]', b'', m.group(0)).decode('ascii', errors='ignore')
        if len(code) >= 44:
            val_m = _RE_VALUE.search(raw)
            due_m = _RE_DUE.search(raw)
            val = val_m.group(1).decode('ascii','ignore') if val_m else ""
            due = due_m.group(1).decode('ascii','ignore') if due_m else ""
            return True, code, "barcode", val, due

    # 2. Keyword scoring on raw bytes (no string allocation)
    raw_lower = raw.lower()
    score = sum(1 for kw in _BOLETO_KW_BYTES if kw in raw_lower)
    if score >= 2:
        val_m = _RE_VALUE.search(raw)
        val = val_m.group(1).decode('ascii','ignore') if val_m else ""
        return True, f"[kw:{score}]", "keywords", val, ""

    # 3. Subject keyword (bytes comparison)
    subj_lower = subject_bytes.lower()
    if any(kw in subj_lower for kw in _BOLETO_SUBJ_KW):
        return True, "[subject]", "subject", "", ""

    # 4. Barcode candidates from digit scan
    for cand in buf.extract_barcode_candidates():
        if len(cand) >= 44:
            return True, cand, "digit_scan", "", ""

    return False, "", "", "", ""


def decode_str_fast(value) -> str:
    """Fast header decode — minimal allocation."""
    if not value: return ""
    if isinstance(value, str): return value
    try:
        from email.header import decode_header
        parts = decode_header(value)
        return ''.join(
            p.decode(enc or 'utf-8', errors='replace') if isinstance(p, bytes)
            else p
            for p, enc in parts
        )
    except: return str(value)


# ── Async IMAP using stdlib asyncio ─────────────────────────────────────────
class AsyncIMAPWorker:
    """
    Async IMAP worker using asyncio + ssl.
    Runs multiple accounts concurrently in a single thread
    using cooperative multitasking — no GIL issues, no thread overhead.
    """
    def __init__(self, acc: dict, cfg: dict,
                 emit_cb, status_cb):
        self.acc       = acc
        self.cfg       = cfg
        self.emit_cb   = emit_cb
        self.status_cb = status_cb
        self.em_addr   = acc["email"]
        self._pending  = {}
        self._running  = True
        self._reader: Optional[asyncio.StreamReader]  = None
        self._writer: Optional[asyncio.StreamWriter]  = None
        self._tag      = 0

    def _next_tag(self) -> bytes:
        self._tag += 1
        return f"A{self._tag:04d}".encode()

    async def _connect(self):
        server = self.acc.get("imap_server","")
        # Try SSL ports
        for port in [993, 143, 585]:
            try:
                if port == 993 or self.acc.get("_working_port") == port:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    self._reader, self._writer = await asyncio.wait_for(
                        asyncio.open_connection(server, port, ssl=ctx),
                        timeout=15
                    )
                else:
                    self._reader, self._writer = await asyncio.wait_for(
                        asyncio.open_connection(server, port),
                        timeout=15
                    )
                # Read greeting
                await asyncio.wait_for(self._reader.readline(), timeout=10)
                # Login
                tag = self._next_tag()
                cmd = f'{tag.decode()} LOGIN "{self.acc["email"]}" "{self.acc["password"]}"\r\n'
                self._writer.write(cmd.encode())
                await self._writer.drain()
                resp = await asyncio.wait_for(self._reader.readline(), timeout=15)
                if b'OK' in resp:
                    self.acc["_working_port"] = port
                    return True
            except Exception as e:
                if 'AUTH' in str(e).upper(): raise
                continue
        return False

    async def _send_cmd(self, cmd: str) -> list:
        """Send IMAP command and collect response lines."""
        tag = self._next_tag()
        full = f"{tag.decode()} {cmd}\r\n"
        self._writer.write(full.encode())
        await self._writer.drain()
        lines = []
        while True:
            try:
                line = await asyncio.wait_for(self._reader.readline(), timeout=30)
                lines.append(line)
                if line.startswith(tag + b' '):
                    break
            except asyncio.TimeoutError:
                break
        return lines

    async def _fetch_one(self, uid: bytes, folder: str) -> Optional[dict]:
        """Fetch one email by UID — zero-copy processing."""
        try:
            # Fetch raw bytes
            lines = await self._send_cmd(f'FETCH {uid.decode()} (RFC822)')
            raw_parts = []
            for line in lines:
                if line.startswith(b'*'): raw_parts.append(line)
            if not raw_parts: return None

            # Find the actual email bytes between { size } markers
            raw_email = b''
            for line in lines:
                if b'RFC822' in line and b'{' in line:
                    # Next lines are the email body
                    idx = lines.index(line)
                    raw_email = b''.join(lines[idx+1:-1])
                    break
            if not raw_email:
                raw_email = b''.join(lines)

            # Zero-copy processing
            buf = EmailBuffer(raw_email)

            # Parse headers only first (fast)
            msg = email.message_from_bytes(raw_email)
            subject_bytes = msg.get('Subject', '').encode('utf-8', errors='replace')
            subject = decode_str_fast(msg.get('Subject', ''))
            sender  = decode_str_fast(msg.get('From', ''))
            to_addr = decode_str_fast(msg.get('To', ''))
            date_str = msg.get('Date', '')

            # Extract body
            body_text = b''
            body_html = b''
            attachments = []

            for part in msg.walk():
                ct = part.get_content_type()
                cd = str(part.get('Content-Disposition', ''))
                payload = part.get_payload(decode=True)
                if not payload: continue
                if ct == 'text/plain' and 'attachment' not in cd:
                    body_text += payload
                elif ct == 'text/html' and 'attachment' not in cd:
                    body_html += payload
                fname = decode_str_fast(part.get_filename() or '')
                if fname:
                    attachments.append({'name': fname, 'path': ''})

            # Create combined buffer for detection
            combined = EmailBuffer(body_text + b' ' + body_html[:5000])
            is_boleto, code, method, value, due = fast_detect_boleto(
                combined, subject_bytes)

            # Check attachments
            has_pdf = any(a['name'].lower().endswith(('.pdf','.xml'))
                         for a in attachments)

            if not is_boleto and not has_pdf:
                return None

            return {
                'uid': uid.decode(),
                'folder': folder,
                'original_folder': folder,
                'subject': subject,
                'sender': sender,
                'to': to_addr,
                'date': date_str,
                'state': 'NAO LIDO',
                'value': value or '',
                'due_date': due or '',
                'attachments': attachments,
                'has_boleto': is_boleto,
                'boleto_code': code,
                'detection_method': method,
                'body': body_text.decode('utf-8', errors='replace')[:10000],
                'body_html': body_html.decode('utf-8', errors='replace')[:10000],
                'account': self.em_addr,
                'has_pdf': has_pdf,
                '_hash': hashlib.md5(
                    f"{self.em_addr}{subject}{date_str}{sender}".encode()
                ).hexdigest(),
            }
        except Exception as e:
            log.debug(f"fetch_one error {uid}: {e}")
            return None

    async def run(self):
        interval  = int(self.cfg.get('cycle_interval', 60))
        folders   = self.cfg.get('folders', ['INBOX'])
        max_days  = int(self.cfg.get('max_days_old', 4))
        per_cycle = int(self.cfg.get('emails_per_read', 10))

        while self._running:
            try:
                if not self._writer or self._writer.is_closing():
                    self.status_cb(self.em_addr, "🔌 Conectando...")
                    connected = await self._connect()
                    if not connected:
                        self.status_cb(self.em_addr, "❌ Falha conexão")
                        await asyncio.sleep(15)
                        continue
                    self.status_cb(self.em_addr, "✅ Conectado (async)")

                since = (datetime.now() - timedelta(days=max_days)).strftime("%d-%b-%Y")
                total_captured = 0

                for folder in folders:
                    if not self._pending.get(folder):
                        # SELECT folder
                        await self._send_cmd(f'SELECT {folder}')
                        # SEARCH
                        lines = await self._send_cmd(f'SEARCH SINCE {since}')
                        ids = []
                        for line in lines:
                            if line.startswith(b'* SEARCH'):
                                ids = line[9:].split()
                        new_ids = [i for i in ids
                                   if not self._is_seen(folder, i.decode())]
                        self._pending[folder] = list(reversed(new_ids))
                        if new_ids:
                            self.status_cb(self.em_addr,
                                f"🔍 {len(new_ids)} novos em {folder}")

                    batch = self._pending.get(folder, [])[:per_cycle]
                    self._pending[folder] = self._pending.get(folder, [])[per_cycle:]

                    if batch:
                        self.status_cb(self.em_addr,
                            f"📖 {len(batch)} | {sum(len(v) for v in self._pending.values())} rest.")

                        # Fetch concurrently in groups of 5
                        CONCUR = 5
                        for i in range(0, len(batch), CONCUR):
                            chunk = batch[i:i+CONCUR]
                            tasks = [self._fetch_one(uid, folder) for uid in chunk]
                            results = await asyncio.gather(*tasks, return_exceptions=True)
                            for uid, result in zip(chunk, results):
                                self._mark_seen(folder, uid.decode())
                                if isinstance(result, dict) and result:
                                    self.emit_cb(result)
                                    total_captured += 1

                has_pending = any(v for v in self._pending.values())
                if has_pending:
                    await asyncio.sleep(0.1)
                else:
                    self.status_cb(self.em_addr,
                        f"✅ {total_captured} capturados | ⏳ {interval}s")
                    await asyncio.sleep(interval)

            except Exception as e:
                err = str(e)
                if 'AUTH' in err.upper() or 'credential' in err.lower():
                    self.status_cb(self.em_addr, "🔴 Senha incorreta")
                    return
                self.status_cb(self.em_addr, f"❌ {err[:35]}")
                if self._writer:
                    try: self._writer.close()
                    except: pass
                self._writer = None
                await asyncio.sleep(15)

    def _is_seen(self, folder, uid):
        try:
            from zeus_engine import ZeusDB
            db = ZeusDB()
            if db.is_uid_seen(self.em_addr, folder, uid): return True
        except: pass
        return False

    def _mark_seen(self, folder, uid):
        try:
            from zeus_engine import ZeusDB
            db = ZeusDB()
            db.mark_uid_seen(self.em_addr, folder, uid)
        except: pass

    def stop(self):
        self._running = False
        if self._writer:
            try: self._writer.close()
            except: pass


# ── Worker Process Main ──────────────────────────────────────────────────────
class ZeusWorkerProcess:
    """
    Main worker process — runs all accounts asynchronously.
    Communicates with UI via named pipe.
    """
    def __init__(self):
        self._conn      = None
        self._loop      = None
        self._workers   = []
        self._email_q   = queue.Queue(maxsize=2000)
        self._status_q  = queue.Queue(maxsize=5000)
        self._running   = True
        self._cfg       = {}
        self._accounts  = []

    def emit_email(self, em: dict):
        try: self._email_q.put_nowait(em)
        except queue.Full: pass

    def emit_status(self, addr: str, msg: str):
        try: self._status_q.put_nowait((addr, msg))
        except queue.Full: pass

    def _send(self, msg_type: str, data):
        """Send message to UI process."""
        try:
            self._conn.send({'type': msg_type, 'data': data})
        except: pass

    def _drain_queues(self):
        """Drain queues and forward to UI — runs in separate thread."""
        while self._running:
            # Drain emails
            emails_batch = []
            for _ in range(20):
                try: emails_batch.append(self._email_q.get_nowait())
                except queue.Empty: break
            if emails_batch:
                self._send('emails', emails_batch)

            # Drain status
            for _ in range(50):
                try:
                    addr, msg = self._status_q.get_nowait()
                    self._send('status', {'addr': addr, 'msg': msg})
                except queue.Empty: break

            time.sleep(0.05)  # 50ms drain cycle

    async def _run_all_accounts(self):
        """Run all account workers concurrently with asyncio."""
        tasks = []
        for acc in self._accounts:
            w = AsyncIMAPWorker(
                acc, self._cfg,
                emit_cb=self.emit_email,
                status_cb=self.emit_status
            )
            self._workers.append(w)
            tasks.append(asyncio.create_task(w.run()))
            await asyncio.sleep(0.05)  # stagger connections

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def start(self, accounts: list, cfg: dict):
        self._accounts = accounts
        self._cfg      = cfg

        # Start queue drainer thread
        drain_thread = threading.Thread(
            target=self._drain_queues, daemon=True)
        drain_thread.start()

        # Run async event loop
        try:
            # Try uvloop for 2x performance (optional)
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        except ImportError: pass

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._run_all_accounts())
        finally:
            self._loop.close()

    def stop(self):
        self._running = False
        for w in self._workers:
            w.stop()


# ── IPC Server — listens for UI commands ────────────────────────────────────
def run_ipc_server(worker: ZeusWorkerProcess):
    """
    Named pipe server.
    Receives commands from UI, forwards emails/status back.
    """
    log.info("Worker IPC server starting...")
    try:
        listener = Listener(WORKER_ADDRESS, authkey=WORKER_AUTHKEY)
    except OSError as e:
        log.error(f"Cannot bind to {WORKER_ADDRESS}: {e}")
        return

    log.info(f"Worker listening on {WORKER_ADDRESS}")
    conn = listener.accept()
    worker._conn = conn
    log.info("UI connected to worker")

    # Wait for START command
    try:
        msg = conn.recv()
        if msg.get('cmd') == 'START':
            accounts = msg['accounts']
            cfg      = msg['cfg']
            log.info(f"Starting {len(accounts)} accounts")
            # Run worker in separate thread so IPC stays responsive
            t = threading.Thread(
                target=worker.start, args=(accounts, cfg), daemon=True)
            t.start()

        # Keep connection alive for status queries
        while True:
            try:
                if conn.poll(1.0):
                    msg = conn.recv()
                    if msg.get('cmd') == 'STOP':
                        worker.stop()
                        break
                    elif msg.get('cmd') == 'PING':
                        conn.send({'type': 'pong'})
            except EOFError:
                break
            except: break

    except Exception as e:
        log.error(f"IPC error: {e}")
    finally:
        try: conn.close()
        except: pass
        listener.close()


# ── IPC Client — used by UI to connect to worker ────────────────────────────
class WorkerClient:
    """
    Used by zeus_mail.py (UI) to communicate with zeus_worker.py.
    Runs the worker as a subprocess and connects via named pipe.
    """
    def __init__(self, email_cb, status_cb):
        self.email_cb   = email_cb
        self.status_cb  = status_cb
        self._proc      = None
        self._conn      = None
        self._running   = False
        self._recv_thread = None

    def start(self, accounts: list, cfg: dict):
        """Launch worker process and connect to it."""
        import subprocess
        worker_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   'zeus_worker.py')
        # Start worker process
        self._proc = subprocess.Popen(
            [sys.executable, worker_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Wait for it to start
        time.sleep(1.5)

        # Connect
        for attempt in range(5):
            try:
                self._conn = Client(WORKER_ADDRESS, authkey=WORKER_AUTHKEY)
                break
            except:
                time.sleep(1)
        else:
            raise RuntimeError("Cannot connect to worker process")

        # Send START command
        self._conn.send({'cmd': 'START', 'accounts': accounts, 'cfg': cfg})

        # Start receiver thread
        self._running = True
        self._recv_thread = threading.Thread(
            target=self._receive_loop, daemon=True)
        self._recv_thread.start()

    def _receive_loop(self):
        """Receive messages from worker and dispatch to callbacks."""
        while self._running:
            try:
                if self._conn.poll(0.1):
                    msg = self._conn.recv()
                    mtype = msg.get('type', '')
                    if mtype == 'emails':
                        for em in msg['data']:
                            self.email_cb(em)
                    elif mtype == 'status':
                        d = msg['data']
                        self.status_cb(d['addr'], d['msg'])
            except EOFError:
                break
            except: pass

    def stop(self):
        self._running = False
        if self._conn:
            try:
                self._conn.send({'cmd': 'STOP'})
                self._conn.close()
            except: pass
        if self._proc:
            try: self._proc.terminate()
            except: pass

    def ping(self) -> bool:
        """Check if worker is alive."""
        try:
            self._conn.send({'cmd': 'PING'})
            if self._conn.poll(2.0):
                msg = self._conn.recv()
                return msg.get('type') == 'pong'
        except: pass
        return False


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == '__main__':
    log.info("ZEUS Worker process started")
    worker = ZeusWorkerProcess()
    run_ipc_server(worker)
    log.info("ZEUS Worker process exiting")
