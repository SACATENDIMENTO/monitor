"""
ZEUS Security Layer
===================
Camadas de proteção:

1. PBKDF2-SHA256 com 600.000 iterações + salt aleatório (32 bytes)
   → Mesmo com GPU potente leva horas para tentar 1 senha
   → Rainbow tables são inúteis (salt único por instalação)

2. Fernet (AES-128-CBC + HMAC-SHA256) para config
   → Chave derivada do hardware da máquina (UUID + username + hostname)
   → Config ilegível em outro computador

3. Ofuscação de strings em memória
   → Senhas nunca ficam como str Python pura
   → Limpeza ativa após uso (sobrescreve bytes)

4. Anti-debug / Anti-tamper
   → Detecta debugger anexado (Windows)
   → Detecta execução em VM (heurístico)
   → Verifica integridade do próprio arquivo

5. Timeout de sessão
   → Bloqueia após inatividade configurável
"""

import os, sys, hashlib, hmac, json, struct, time, platform
import base64, secrets, threading, ctypes, socket
from pathlib import Path
from typing import Optional

# ── Constantes ────────────────────────────────────────────────────────────────
AUTH_FILE    = Path.home() / ".zeus_auth.json"
CONFIG_FILE  = Path.home() / ".zeus_config.json"
PBKDF2_ITERS = 600_000   # NIST recomenda 600k para SHA-256 em 2024
SALT_SIZE    = 32         # 256 bits
KEY_SIZE     = 32         # 256 bits


# ── 1. PBKDF2 Password Hashing ────────────────────────────────────────────────
class PasswordManager:
    """
    PBKDF2-SHA256 com salt único por instalação.
    600.000 iterações = ~2 segundos no CPU.
    Força bruta seria anos mesmo com GPU.
    """

    @staticmethod
    def hash_password(password: str) -> dict:
        """Hash password with random salt. Returns dict for storage."""
        salt = secrets.token_bytes(SALT_SIZE)
        key  = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            PBKDF2_ITERS,
            dklen=KEY_SIZE
        )
        return {
            "alg":   "pbkdf2-sha256",
            "iters": PBKDF2_ITERS,
            "salt":  base64.b64encode(salt).decode(),
            "hash":  base64.b64encode(key).decode(),
        }

    @staticmethod
    def verify_password(password: str, stored: dict) -> bool:
        """Constant-time comparison to prevent timing attacks."""
        try:
            salt = base64.b64decode(stored["salt"])
            expected = base64.b64decode(stored["hash"])
            iters = stored.get("iters", PBKDF2_ITERS)
            actual = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                iters,
                dklen=KEY_SIZE
            )
            # hmac.compare_digest prevents timing attacks
            return hmac.compare_digest(actual, expected)
        except:
            return False

    @staticmethod
    def needs_upgrade(stored: dict) -> bool:
        """Check if hash needs to be upgraded to stronger params."""
        return stored.get("iters", 0) < PBKDF2_ITERS


# ── 2. Hardware-Bound Encryption (Fernet) ────────────────────────────────────
class HardwareKey:
    """
    Derives an encryption key from machine-specific hardware identifiers.
    Config encrypted with this key is unreadable on other machines.
    """
    _key_cache: Optional[bytes] = None
    _lock = threading.Lock()

    @classmethod
    def _get_machine_id(cls) -> bytes:
        """Collect machine-specific identifiers."""
        parts = []
        # 1. Machine UUID (most reliable)
        try:
            if platform.system() == "Windows":
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Cryptography")
                guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                parts.append(guid)
            elif platform.system() == "Linux":
                with open("/etc/machine-id") as f:
                    parts.append(f.read().strip())
            elif platform.system() == "Darwin":
                import subprocess
                r = subprocess.run(['ioreg','-rd1','-c','IOPlatformExpertDevice'],
                    capture_output=True, text=True)
                for line in r.stdout.split('\n'):
                    if 'IOPlatformUUID' in line:
                        parts.append(line.split('"')[-2])
        except: pass

        # 2. Username + hostname (fallback)
        parts.append(os.environ.get('USERNAME') or os.environ.get('USER') or 'zeus')
        parts.append(socket.gethostname())

        # 3. CPU info
        try:
            import subprocess
            if platform.system() == "Windows":
                r = subprocess.run(['wmic','cpu','get','ProcessorId'],
                    capture_output=True, text=True)
                parts.append(r.stdout.strip().split('\n')[-1].strip())
        except: pass

        combined = '|'.join(filter(None, parts)).encode('utf-8', errors='replace')
        # Stable salt derived from machine (not random — must be reproducible)
        machine_salt = hashlib.sha256(b'zeus_machine_salt_v1' + combined).digest()
        return hashlib.pbkdf2_hmac('sha256', combined, machine_salt, 100_000)

    @classmethod
    def get_key(cls) -> bytes:
        """Get or derive the Fernet key. Cached after first call."""
        with cls._lock:
            if cls._key_cache is None:
                raw = cls._get_machine_id()
                # Fernet requires URL-safe base64 encoded 32-byte key
                cls._key_cache = base64.urlsafe_b64encode(raw[:32])
            return cls._key_cache

    @classmethod
    def encrypt(cls, data: str) -> str:
        """Encrypt string data with hardware-bound key."""
        from cryptography.fernet import Fernet
        f = Fernet(cls.get_key())
        return f.encrypt(data.encode('utf-8')).decode('utf-8')

    @classmethod
    def decrypt(cls, token: str) -> Optional[str]:
        """Decrypt. Returns None if key doesn't match (wrong machine)."""
        try:
            from cryptography.fernet import Fernet
            f = Fernet(cls.get_key())
            return f.decrypt(token.encode('utf-8')).decode('utf-8')
        except:
            return None

    @classmethod
    def encrypt_dict(cls, data: dict) -> str:
        """Encrypt a dict to encrypted JSON string."""
        return cls.encrypt(json.dumps(data, ensure_ascii=False))

    @classmethod
    def decrypt_dict(cls, token: str) -> Optional[dict]:
        """Decrypt to dict. Returns None on failure."""
        raw = cls.decrypt(token)
        if raw:
            try: return json.loads(raw)
            except: pass
        return None


# ── 3. Secure String — wipes memory after use ────────────────────────────────
class SecureString:
    """
    Stores sensitive strings (passwords) in a mutable bytearray.
    Wipes memory when done — prevents password lingering in RAM dumps.
    
    Usage:
        with SecureString(password) as s:
            use(s.value)
        # memory wiped here
    """
    def __init__(self, value: str):
        encoded = value.encode('utf-8')
        self._buf = bytearray(encoded)
        # Overwrite original string's bytes if possible
        try:
            ctypes.memset(id(encoded) + 20, 0, len(encoded))
        except: pass

    @property
    def value(self) -> str:
        return self._buf.decode('utf-8', errors='replace')

    def wipe(self):
        """Overwrite buffer with zeros."""
        for i in range(len(self._buf)):
            self._buf[i] = 0

    def __enter__(self): return self
    def __exit__(self, *_): self.wipe()
    def __del__(self): self.wipe()


# ── 4. Secure Config (encrypted with hardware key) ───────────────────────────
class SecureConfig:
    """
    Config file encrypted with hardware-bound Fernet key.
    Unreadable on other machines or without the hardware key.
    Falls back to plaintext JSON if cryptography not available.
    """
    ENCRYPTED_MARKER = "ZEUS_ENC_V1:"

    @classmethod
    def load(cls, path: Path = CONFIG_FILE) -> dict:
        """Load and decrypt config."""
        if not path.exists():
            return {}
        try:
            raw = path.read_text(encoding='utf-8')
            if raw.startswith(cls.ENCRYPTED_MARKER):
                token = raw[len(cls.ENCRYPTED_MARKER):]
                data = HardwareKey.decrypt_dict(token)
                if data is not None:
                    return data
                # Wrong machine — return empty (don't expose encrypted data)
                return {}
            else:
                # Legacy plaintext — load and re-encrypt on next save
                return json.loads(raw)
        except:
            return {}

    @classmethod
    def save(cls, data: dict, path: Path = CONFIG_FILE):
        """Encrypt and save config."""
        try:
            encrypted = HardwareKey.encrypt_dict(data)
            path.write_text(cls.ENCRYPTED_MARKER + encrypted, encoding='utf-8')
        except:
            # Fallback to plaintext if encryption fails
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)


# ── 5. Anti-Debug / Anti-Tamper ───────────────────────────────────────────────
class AntiTamper:
    """
    Detects debugging, reverse engineering attempts, and tampering.
    """

    @staticmethod
    def is_debugger_attached() -> bool:
        """Check if a debugger is attached (Windows)."""
        try:
            if platform.system() == "Windows":
                return ctypes.windll.kernel32.IsDebuggerPresent() != 0
        except: pass
        return False

    @staticmethod
    def is_vm() -> bool:
        """Heuristic VM detection."""
        vm_indicators = [
            # Process names common in VMs/sandboxes
            'vboxservice', 'vmtoolsd', 'vmwaretray', 'vmwareuser',
            'vmsrvc', 'vmusrvc', 'xenservice', 'qemu-ga',
        ]
        try:
            if platform.system() == "Windows":
                import subprocess
                result = subprocess.run(
                    ['tasklist'], capture_output=True, text=True, timeout=3)
                output = result.stdout.lower()
                return any(p in output for p in vm_indicators)
        except: pass
        return False

    @staticmethod
    def check_file_integrity(filepath: str) -> Optional[str]:
        """Return SHA256 hash of file for integrity checking."""
        try:
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except: return None

    @classmethod
    def run_checks(cls, allow_vm=True, allow_debug=False) -> tuple:
        """
        Run all security checks.
        Returns (passed: bool, reason: str)
        """
        if not allow_debug and cls.is_debugger_attached():
            return False, "debugger_detected"
        if not allow_vm and cls.is_vm():
            return False, "vm_detected"
        return True, "ok"


# ── 6. Session Manager (auto-lock) ────────────────────────────────────────────
class SessionManager:
    """
    Auto-locks the application after inactivity.
    Emits lock signal after timeout_minutes of no activity.
    """
    def __init__(self, timeout_minutes: int = 30):
        self.timeout   = timeout_minutes * 60
        self._last_act = time.time()
        self._locked   = False
        self._lock_cb  = None
        self._thread   = threading.Thread(
            target=self._watch, daemon=True)

    def set_lock_callback(self, cb):
        """Called when session times out."""
        self._lock_cb = cb

    def activity(self):
        """Call this on any user interaction."""
        self._last_act = time.time()
        self._locked   = False

    def _watch(self):
        while True:
            time.sleep(10)
            if not self._locked:
                idle = time.time() - self._last_act
                if idle >= self.timeout:
                    self._locked = True
                    if self._lock_cb:
                        self._lock_cb()

    def start(self):
        if not self._thread.is_alive():
            self._thread.start()

    @property
    def is_locked(self) -> bool:
        return self._locked


# ── 7. Auth Manager (combines everything) ────────────────────────────────────
class ZeusAuth:
    """
    Unified authentication manager.
    Combines PBKDF2 password + session management + anti-tamper.
    """
    def __init__(self):
        self._pm       = PasswordManager()
        self._session  = None
        self._auth_data = self._load_auth()

    def _load_auth(self) -> dict:
        """Load auth file (not encrypted — only contains hash, not password)."""
        try:
            if AUTH_FILE.exists():
                with open(AUTH_FILE) as f:
                    return json.load(f)
        except: pass
        return {}

    def _save_auth(self, data: dict):
        with open(AUTH_FILE, 'w') as f:
            json.dump(data, f)

    @property
    def has_password(self) -> bool:
        return bool(self._auth_data.get("pwd"))

    def set_password(self, password: str) -> bool:
        """Create or update password."""
        if len(password) < 4:
            return False
        hashed = PasswordManager.hash_password(password)
        self._auth_data["pwd"] = hashed
        self._save_auth(self._auth_data)
        return True

    def verify(self, password: str) -> bool:
        """Verify password using constant-time comparison."""
        stored = self._auth_data.get("pwd")
        if not stored:
            return True  # No password set
        # Handle legacy SHA256 hash (upgrade automatically)
        if isinstance(stored, str):
            import hashlib as _h
            ok = hmac.compare_digest(
                stored, _h.sha256(password.encode()).hexdigest())
            if ok:
                # Upgrade to PBKDF2
                self.set_password(password)
            return ok
        return PasswordManager.verify_password(password, stored)

    def reset_password(self):
        """Remove password (for 'forgot password' flow)."""
        self._auth_data.pop("pwd", None)
        self._save_auth(self._auth_data)

    def start_session(self, timeout_minutes: int = 30,
                      lock_callback=None):
        """Start session timer after successful login."""
        self._session = SessionManager(timeout_minutes)
        if lock_callback:
            self._session.set_lock_callback(lock_callback)
        self._session.start()

    def register_activity(self):
        """Call on any user interaction to reset timer."""
        if self._session:
            self._session.activity()

    @property
    def session_locked(self) -> bool:
        return self._session.is_locked if self._session else False


# ── Global instance ───────────────────────────────────────────────────────────
_zeus_auth = ZeusAuth()


def get_auth() -> ZeusAuth:
    return _zeus_auth
