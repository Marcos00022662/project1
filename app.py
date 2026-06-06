import json
import hashlib
import hmac
import os
import re
import secrets
import smtplib
import ssl
import time
import uuid
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
from ipaddress import ip_address, ip_network

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

try:
    import redis
except ImportError:
    redis = None

try:
    import mercadopago
except ImportError:
    mercadopago = None

try:
    import pymysql
    from pymysql.cursors import DictCursor
except ImportError:
    pymysql = None
    DictCursor = None


BASE_DIR = Path(__file__).resolve().parent

if load_dotenv:
    load_dotenv(BASE_DIR / ".env")

UPLOAD_FOLDER = Path(os.environ.get("UPLOAD_FOLDER", BASE_DIR / "static" / "uploads"))
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
MAX_EXTRA_PHOTOS = 5
MIN_PASSWORD_LENGTH = 6
EMAIL_PATTERN = re.compile(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}$", re.IGNORECASE)
YOUTUBE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{6,16}$")
DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "frame-src https://www.youtube.com https://www.youtube-nocookie.com; "
    "connect-src 'self'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def parse_money_env(name, default):
    raw_value = os.environ.get(name, default).replace(",", ".")
    try:
        value = Decimal(raw_value)
    except (InvalidOperation, ValueError) as exc:
        raise RuntimeError(f"{name} precisa ser um valor monetario valido") from exc
    if value <= 0:
        raise RuntimeError(f"{name} precisa ser maior que zero")
    return value.quantize(Decimal("0.01"))


def format_brl(value):
    return f"R$ {value:.2f}".replace(".", ",")


def mysql_config():
    database_url = os.environ.get("MYSQL_URL") or os.environ.get("DATABASE_URL")
    if database_url:
        parsed = urlparse(database_url)
        if parsed.scheme not in {"mysql", "mysql+pymysql"}:
            raise RuntimeError("MYSQL_URL/DATABASE_URL precisa usar mysql:// ou mysql+pymysql://")
        return {
            "host": parsed.hostname or "localhost",
            "port": parsed.port or 3306,
            "user": unquote(parsed.username or ""),
            "password": unquote(parsed.password or ""),
            "database": parsed.path.lstrip("/"),
        }
    return {
        "host": os.environ.get("MYSQL_HOST", "localhost"),
        "port": int(os.environ.get("MYSQL_PORT", "3306")),
        "user": os.environ.get("MYSQL_USER", "root"),
        "password": os.environ.get("MYSQL_PASSWORD", ""),
        "database": os.environ.get("MYSQL_DATABASE", "meulove"),
    }


class MySQLDatabase:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, sql, params=None):
        cursor = self.connection.cursor()
        cursor.execute(sql.replace("?", "%s"), params or ())
        return cursor

    def commit(self):
        self.connection.commit()

    def close(self):
        self.connection.close()


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
if os.environ.get("APP_ENV") == "production" and not os.environ.get("SECRET_KEY"):
    raise RuntimeError("SECRET_KEY precisa ser definido em producao")
if os.environ.get("APP_ENV") == "production" and not PUBLIC_BASE_URL:
    raise RuntimeError("PUBLIC_BASE_URL precisa ser definido em producao")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["WTF_CSRF_ENABLED"] = True
app.config["WTF_CSRF_TIME_LIMIT"] = int(os.environ.get("WTF_CSRF_TIME_LIMIT", "3600"))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("SESSION_COOKIE_SECURE", "1" if os.environ.get("APP_ENV") == "production" else "0")
    == "1"
)
app.permanent_session_lifetime = timedelta(days=7)

csrf = CSRFProtect(app)

MP_ACCESS_TOKEN = os.environ.get("MP_ACCESS_TOKEN")
MP_WEBHOOK_SECRET = os.environ.get("MP_WEBHOOK_SECRET")
MP_WEBHOOK_TOLERANCE_SECONDS = int(os.environ.get("MP_WEBHOOK_TOLERANCE_SECONDS", "600"))
sdk = mercadopago.SDK(MP_ACCESS_TOKEN) if mercadopago and MP_ACCESS_TOKEN else None
MP_PRODUCT_PRICE = parse_money_env("MP_PRODUCT_PRICE", "19.00")
PASSWORD_RESET_SECONDS = int(os.environ.get("PASSWORD_RESET_SECONDS", "3600"))
MAX_SURPRISES_PER_USER = int(os.environ.get("MAX_SURPRISES_PER_USER", "10"))
ADMIN_IP_ALLOWLIST = [
    item.strip()
    for item in os.environ.get("ADMIN_IP_ALLOWLIST", "").split(",")
    if item.strip()
]
CSP_HEADER = os.environ.get("CONTENT_SECURITY_POLICY", DEFAULT_CSP)
RATE_LIMITS = {}
RATE_LIMIT_BACKEND = os.environ.get("RATE_LIMIT_BACKEND", "redis" if os.environ.get("REDIS_URL") else "memory")
REDIS_URL = os.environ.get("REDIS_URL")
redis_client = None
if os.environ.get("APP_ENV") == "production" and RATE_LIMIT_BACKEND != "redis":
    raise RuntimeError("RATE_LIMIT_BACKEND=redis precisa ser usado em producao")
if RATE_LIMIT_BACKEND == "redis":
    if redis is None:
        raise RuntimeError("Instale redis ou use RATE_LIMIT_BACKEND=memory")
    if not REDIS_URL:
        raise RuntimeError("REDIS_URL precisa ser definido quando RATE_LIMIT_BACKEND=redis")
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)


@app.before_request
def block_public_uploads():
    if request.path.startswith("/static/uploads/"):
        abort(404)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Content-Security-Policy", CSP_HEADER)
    return response


def get_db():
    if "db" not in g:
        if pymysql is None:
            raise RuntimeError("Instale PyMySQL para usar MySQL")
        g.db = MySQLDatabase(
            pymysql.connect(
                **mysql_config(),
                charset="utf8mb4",
                cursorclass=DictCursor,
                autocommit=False,
            )
        )
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def column_exists(db, table, column):
    return bool(
        db.execute(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = ?
              AND column_name = ?
            """,
            (table, column),
        ).fetchone()
    )


def index_exists(db, table, index_name):
    return bool(
        db.execute(
            """
            SELECT 1
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = ?
              AND index_name = ?
            """,
            (table, index_name),
        ).fetchone()
    )


def create_index_if_missing(db, table, index_name, columns):
    if not index_exists(db, table, index_name):
        db.execute(f"CREATE INDEX {index_name} ON {table} ({columns})")


def init_db():
    UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(254) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            pago TINYINT DEFAULT 0,
            reset_token_hash VARCHAR(64),
            reset_token_expires INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS surprises (
            id INT PRIMARY KEY AUTO_INCREMENT,
            user_id INT,
            code VARCHAR(32) UNIQUE NOT NULL,
            name VARCHAR(255) NOT NULL,
            message TEXT NOT NULL,
            music TEXT,
            password VARCHAR(255),
            timeline LONGTEXT,
            extra_photos LONGTEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS payments_log (
            id INT PRIMARY KEY AUTO_INCREMENT,
            payment_id VARCHAR(64) UNIQUE NOT NULL,
            user_id INT,
            status VARCHAR(64),
            amount DECIMAL(10, 2),
            currency VARCHAR(8),
            payload LONGTEXT,
            processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        """
    )

    migrations = [
        ("users", "pago", "ALTER TABLE users ADD COLUMN pago TINYINT DEFAULT 0"),
        ("users", "reset_token_hash", "ALTER TABLE users ADD COLUMN reset_token_hash VARCHAR(64)"),
        ("users", "reset_token_expires", "ALTER TABLE users ADD COLUMN reset_token_expires INT"),
        ("surprises", "user_id", "ALTER TABLE surprises ADD COLUMN user_id INT"),
        ("surprises", "timeline", "ALTER TABLE surprises ADD COLUMN timeline TEXT"),
        ("surprises", "extra_photos", "ALTER TABLE surprises ADD COLUMN extra_photos TEXT"),
    ]
    for table, column, sql in migrations:
        if not column_exists(db, table, column):
            db.execute(sql)

    create_index_if_missing(db, "surprises", "idx_surprises_code", "code")
    create_index_if_missing(db, "surprises", "idx_surprises_user_id", "user_id")
    create_index_if_missing(db, "users", "idx_users_email", "email")
    create_index_if_missing(db, "payments_log", "idx_payments_log_payment_id", "payment_id")

    old_passwords = db.execute(
        "SELECT id, password FROM surprises WHERE password IS NOT NULL AND password != ''"
    ).fetchall()
    for surprise in old_passwords:
        if not password_is_hash(surprise["password"]):
            db.execute(
                "UPDATE surprises SET password = ? WHERE id = ?",
                (hash_optional_password(surprise["password"]), surprise["id"]),
            )
    db.commit()


@app.cli.command("init-db")
def init_db_command():
    init_db()
    print("Banco de dados inicializado.")


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def client_ip_allowed(allowlist):
    if not allowlist:
        return True
    remote_addr = request.remote_addr
    if not remote_addr:
        return False
    try:
        client_ip = ip_address(remote_addr)
    except ValueError:
        return False

    for item in allowlist:
        try:
            if "/" in item:
                if client_ip in ip_network(item, strict=False):
                    return True
            elif client_ip == ip_address(item):
                return True
        except ValueError:
            app.logger.warning("ADMIN_IP_ALLOWLIST inválido: %s", item)
    return False


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


def pago_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if not user["pago"]:
            flash("Você precisa assinar para acessar.", "warning")
            return redirect(url_for("assinatura"))
        return view(**kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if not client_ip_allowed(ADMIN_IP_ALLOWLIST):
            abort(404)
        if not session.get("admin_logged"):
            return redirect(url_for("admin_login"))
        return view(**kwargs)

    return wrapped_view


def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_IMAGE_EXTENSIONS


def is_valid_email(email):
    if not email or len(email) > 254:
        return False
    if email.count("@") != 1:
        return False
    local_part, domain = email.rsplit("@", 1)
    if not local_part or len(local_part) > 64:
        return False
    if domain.startswith("-") or domain.endswith("-") or ".." in domain:
        return False
    return bool(EMAIL_PATTERN.fullmatch(email))


def image_type_from_header(header):
    if header.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        return "webp"
    return None


def validate_image_file(file):
    suffix = Path(file.filename).suffix.lower()
    if suffix not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError("Formato de imagem inválido.")

    header = file.stream.read(16)
    file.stream.seek(0)
    image_type = image_type_from_header(header)
    if not image_type:
        raise ValueError("Arquivo enviado não parece ser uma imagem válida.")

    valid_suffixes = {
        "jpeg": {".jpg", ".jpeg"},
        "png": {".png"},
        "gif": {".gif"},
        "webp": {".webp"},
    }
    if suffix not in valid_suffixes[image_type]:
        raise ValueError("A extensão do arquivo não confere com a imagem enviada.")


def save_image(file, saved_paths=None):
    if not file or not file.filename:
        return None
    validate_image_file(file)

    suffix = Path(file.filename).suffix.lower()
    filename = secure_filename(f"{uuid.uuid4().hex}{suffix}")
    file.save(UPLOAD_FOLDER / filename)
    path = f"uploads/{filename}"
    if saved_paths is not None:
        saved_paths.append(path)
    return path


def save_images(files, limit, saved_paths=None):
    paths = []
    for file in files[:limit]:
        if not file.filename:
            continue
        path = save_image(file, saved_paths)
        if path is not None:
            paths.append(path)
    return paths


def parse_json_list(value):
    if not value:
        return []
    try:
        data = json.loads(value)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def hash_optional_password(password):
    return generate_password_hash(password) if password else None


def hash_reset_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def make_password_reset_token(user_id):
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + PASSWORD_RESET_SECONDS
    db = get_db()
    db.execute(
        "UPDATE users SET reset_token_hash = ?, reset_token_expires = ? WHERE id = ?",
        (hash_reset_token(token), expires_at, user_id),
    )
    db.commit()
    return token


def find_user_by_reset_token(token):
    if not token:
        return None
    token_hash = hash_reset_token(token)
    return get_db().execute(
        """
        SELECT * FROM users
        WHERE reset_token_hash = ?
          AND reset_token_expires IS NOT NULL
          AND reset_token_expires >= ?
        """,
        (token_hash, int(time.time())),
    ).fetchone()



def smtp_is_configured():
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("SMTP_FROM"))


def send_password_reset_email(email, reset_url):
    if not smtp_is_configured():
        return False

    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    username = os.environ.get("SMTP_USERNAME", "")
    password = os.environ.get("SMTP_PASSWORD", "")
    sender = os.environ["SMTP_FROM"]
    subject = "Redefinir sua senha - MeuLove"

    body_plain = (
        "Recebemos um pedido para redefinir sua senha no MeuLove.\n\n"
        f"Acesse este link para criar uma nova senha:\n{reset_url}\n\n"
        "O link expira em 1 hora.\n\n"
        "Se você não pediu isso, pode ignorar este e-mail com segurança."
    )

    body_html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,sans-serif;">
  <div style="max-width:480px;margin:40px auto;background:#ffffff;border-radius:8px;padding:40px;border:1px solid #e5e5e5;">
    <h1 style="font-size:20px;font-weight:600;color:#111111;margin:0 0 16px;">Redefinir sua senha</h1>
    <p style="font-size:15px;color:#444444;line-height:1.6;margin:0 0 24px;">
      Recebemos um pedido para redefinir a senha da sua conta no <strong>MeuLove</strong>.
      Clique no botão abaixo para criar uma nova senha.
    </p>
    <a href="{reset_url}"
       style="display:inline-block;background:#e84393;color:#ffffff;text-decoration:none;
              padding:12px 28px;border-radius:6px;font-size:15px;font-weight:500;">
      Redefinir senha
    </a>
    <p style="font-size:13px;color:#888888;margin:24px 0 0;line-height:1.6;">
      O link expira em <strong>1 hora</strong>. Se você não solicitou isso, pode ignorar
      este e-mail com segurança — sua senha não será alterada.
    </p>
    <hr style="border:none;border-top:1px solid #eeeeee;margin:28px 0;">
    <p style="font-size:12px;color:#aaaaaa;margin:0;">MeuLove &mdash; seu projeto de amor 💕</p>
  </div>
</body>
</html>"""

    boundary = "===============meulove001=="
    message = (
        f"From: {sender}\r\n"
        f"To: {email}\r\n"
        f"Subject: {subject}\r\n"
        "MIME-Version: 1.0\r\n"
        f"Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n"
        "\r\n"
        f"--{boundary}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        f"{body_plain}\r\n"
        f"--{boundary}\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        f"{body_html}\r\n"
        f"--{boundary}--"
    )

    context = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=10) as server:
        server.starttls(context=context)
        if username or password:
            server.login(username, password)
        server.sendmail(sender, [email], message.encode("utf-8"))
    return True


def password_is_hash(value):
    return bool(value and (value.startswith("scrypt:") or value.startswith("pbkdf2:")))


def verify_stored_password(stored_password, provided_password):
    if not stored_password or not provided_password:
        return False
    if password_is_hash(stored_password):
        return check_password_hash(stored_password, provided_password)
    return hmac.compare_digest(stored_password, provided_password)


def external_url(endpoint, **values):
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL + url_for(endpoint, **values)
    return url_for(endpoint, _external=True, **values)


def rate_limit_key(action):
    return f"{action}:{request.remote_addr or 'unknown'}"


def redis_rate_limited(key, limit, window):
    pipe = redis_client.pipeline()
    pipe.incr(key)
    pipe.expire(key, window, nx=True)
    count, _ = pipe.execute()
    return int(count) > limit


def memory_rate_limited(key, limit, window):
    now = time.time()
    attempts = [created_at for created_at in RATE_LIMITS.get(key, []) if now - created_at < window]
    if len(attempts) >= limit:
        RATE_LIMITS[key] = attempts
        return True
    attempts.append(now)
    RATE_LIMITS[key] = attempts
    return False


def is_rate_limited(action, limit=8, window=60):
    key = rate_limit_key(action)
    if redis_client:
        return redis_rate_limited(key, limit, window)
    return memory_rate_limited(key, limit, window)


def parse_mp_signature(signature):
    values = {}
    for part in (signature or "").split(","):
        key_value = part.split("=", 1)
        if len(key_value) == 2:
            values[key_value[0].strip().lower()] = key_value[1].strip()
    return values.get("ts"), values.get("v1")


def timestamp_is_fresh(ts):
    try:
        timestamp = int(ts)
    except (TypeError, ValueError):
        return False

    if timestamp > 10**12:
        timestamp = timestamp / 1000
    return abs(time.time() - timestamp) <= MP_WEBHOOK_TOLERANCE_SECONDS


def build_mp_signature_manifest(data_id, request_id, ts):
    parts = []
    if data_id:
        parts.append(f"id:{data_id};")
    if request_id:
        parts.append(f"request-id:{request_id};")
    if ts:
        parts.append(f"ts:{ts};")
    return "".join(parts)


def mp_notification_data_id(payload=None):
    data_id = request.args.get("data.id") or request.args.get("id")
    if data_id:
        return str(data_id)

    payload = payload if payload is not None else request.get_json(silent=True) or {}
    body_data_id = payload.get("data", {}).get("id") if isinstance(payload, dict) else None
    return str(body_data_id) if body_data_id else ""


def valid_mp_webhook_signature():
    if not MP_WEBHOOK_SECRET:
        return os.environ.get("APP_ENV") != "production"

    ts, received_signature = parse_mp_signature(request.headers.get("x-signature", ""))
    request_id = request.headers.get("x-request-id", "")
    data_id = mp_notification_data_id()

    if not ts or not received_signature or not request_id or not data_id:
        return False
    if not timestamp_is_fresh(ts):
        return False

    manifest = build_mp_signature_manifest(data_id, request_id, ts)
    expected_signature = hmac.HMAC(
        MP_WEBHOOK_SECRET.encode(),
        manifest.encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected_signature, received_signature)


def log_payment_event(payment_id, payment):
    db = get_db()
    user_id = str(payment.get("external_reference", ""))
    previous = db.execute(
        "SELECT status FROM payments_log WHERE payment_id = ?",
        (str(payment_id),),
    ).fetchone()
    db.execute(
        """
        INSERT INTO payments_log (payment_id, user_id, status, amount, currency, payload)
        VALUES (?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            user_id = VALUES(user_id),
            status = VALUES(status),
            amount = VALUES(amount),
            currency = VALUES(currency),
            payload = VALUES(payload),
            processed_at = CURRENT_TIMESTAMP
        """,
        (
            str(payment_id),
            int(user_id) if user_id.isdigit() else None,
            payment.get("status"),
            payment.get("transaction_amount"),
            payment.get("currency_id"),
            json.dumps(payment),
        ),
    )
    db.commit()
    return previous["status"] if previous else None


def build_timeline(form, files, existing=None, saved_paths=None):
    existing = existing or []
    timeline = []
    for index in range(1, 4):
        old = existing[index - 1] if index - 1 < len(existing) else {}
        text = form.get(f"momento{index}", "").strip()
        photo = old.get("photo")
        uploaded = files.get(f"fotoMomento{index}")
        if uploaded and uploaded.filename:
            photo = save_image(uploaded, saved_paths)
        if text or photo:
            timeline.append({"text": text, "photo": photo})
    return timeline


def build_youtube(link):
    if not link:
        return {"watch": "", "embed": ""}

    parsed = urlparse(link)
    video_id = ""
    if parsed.netloc.endswith("youtu.be"):
        video_id = parsed.path.strip("/")
    elif "youtube.com" in parsed.netloc:
        video_id = parse_qs(parsed.query).get("v", [""])[0]
        if not video_id and parsed.path.startswith("/shorts/"):
            video_id = parsed.path.split("/")[2]

    if not video_id or not YOUTUBE_ID_PATTERN.match(video_id):
        return {"watch": "", "embed": ""}

    return {
        "watch": f"https://www.youtube.com/watch?v={video_id}",
        "embed": f"https://www.youtube.com/embed/{video_id}",
    }


def user_owns_surprise(surprise):
    return surprise and surprise["user_id"] == session.get("user_id")


def user_surprise_count(user_id):
    return get_db().execute(
        "SELECT COUNT(*) AS total FROM surprises WHERE user_id = ?",
        (user_id,),
    ).fetchone()["total"]


def user_reached_surprise_limit(user_id):
    return MAX_SURPRISES_PER_USER > 0 and user_surprise_count(user_id) >= MAX_SURPRISES_PER_USER


def normalize_upload_name(filename):
    if not filename:
        abort(404)
    clean_name = secure_filename(Path(filename).name)
    if clean_name != filename:
        abort(404)
    return clean_name


def surprise_contains_file(surprise, filename):
    upload_path = f"uploads/{filename}"
    if upload_path in parse_json_list(surprise["extra_photos"]):
        return True
    for item in parse_json_list(surprise["timeline"]):
        if isinstance(item, dict) and item.get("photo") == upload_path:
            return True
    return False


def can_view_surprise_media(surprise):
    return not surprise["password"] or session.get(f"surprise_{surprise['code']}")


def surprise_upload_paths(surprise):
    paths = set()
    paths.update(path for path in parse_json_list(surprise["extra_photos"]) if isinstance(path, str))
    for item in parse_json_list(surprise["timeline"]):
        if isinstance(item, dict) and item.get("photo"):
            paths.add(item["photo"])
    return paths


def delete_upload_files(paths):
    for upload_path in paths:
        filename = secure_filename(Path(upload_path).name)
        if not filename:
            continue
        try:
            (UPLOAD_FOLDER / filename).unlink(missing_ok=True)
        except OSError:
            app.logger.warning("Não foi possível remover upload %s", upload_path, exc_info=True)


@app.route("/style.css")
def style_css():
    return send_from_directory(BASE_DIR / "templates", "style.css", mimetype="text/css")


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(BASE_DIR / "static", "favicon.ico")


@app.route("/")
def home():
    return render_template("index.html", product_price_label=format_brl(MP_PRODUCT_PRICE))


@app.route("/assinatura")
def assinatura():
    user = current_user()
    if user and user["pago"]:
        return redirect(url_for("create"))
    return render_template("assinatura.html", user=user, product_price_label=format_brl(MP_PRODUCT_PRICE))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("create"))

    error = ""
    if request.method == "POST":
        if is_rate_limited("login", limit=10, window=300):
            error = "Muitas tentativas. Aguarde alguns minutos e tente novamente."
            return render_template("login.html", error=error), 429

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            return redirect(url_for("create"))
        error = "Email ou senha inválidos"
    return render_template("login.html", error=error)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    reset_url = ""
    sent = False
    if request.method == "POST":
        if is_rate_limited("forgot_password", limit=5, window=300):
            return render_template("forgot_password.html", sent=True), 429

        email = request.form.get("email", "").strip().lower()
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            token = make_password_reset_token(user["id"])
            reset_url = external_url("reset_password", token=token)
            try:
                sent = send_password_reset_email(user["email"], reset_url)
            except Exception:
                app.logger.warning("Falha ao enviar email de redefinicao", exc_info=True)

        show_dev_link = bool(reset_url and not sent and os.environ.get("APP_ENV") != "production")
        return render_template(
            "forgot_password.html",
            sent=True,
            reset_url=reset_url if show_dev_link else "",
        )
    return render_template("forgot_password.html", sent=False)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = find_user_by_reset_token(token)
    if not user:
        return render_template(
            "reset_password.html",
            invalid=True,
            error="Link inválido ou expirado. Solicite uma nova redefinição.",
        ), 400

    error = ""
    if request.method == "POST":
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")
        if len(password) < MIN_PASSWORD_LENGTH:
            error = f"Use uma senha com pelo menos {MIN_PASSWORD_LENGTH} caracteres."
        elif password != password_confirm:
            error = "As senhas não conferem."
        else:
            db = get_db()
            db.execute(
                """
                UPDATE users
                SET password_hash = ?, reset_token_hash = NULL, reset_token_expires = NULL
                WHERE id = ?
                """,
                (generate_password_hash(password), user["id"]),
            )
            db.commit()
            flash("Senha redefinida. Faça login com a nova senha.", "success")
            return redirect(url_for("login"))

    return render_template("reset_password.html", invalid=False, error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("create"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            return render_template("register.html", error="Preencha todos os campos.")

        if not is_valid_email(email):
            return render_template("register.html", error="Digite um e-mail valido.")

        if len(password) < MIN_PASSWORD_LENGTH:
            return render_template(
                "register.html",
                error=f"Use uma senha com pelo menos {MIN_PASSWORD_LENGTH} caracteres.",
            )

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                (name, email, generate_password_hash(password)),
            )
            db.commit()
        except pymysql.IntegrityError:
            return render_template("register.html", error="Esse e-mail já está cadastrado.")

        flash("Conta criada! Faça login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    user = current_user()
    if user["pago"]:
        return redirect(url_for("create"))
    if not sdk:
        flash("Pagamento indisponivel: configure MP_ACCESS_TOKEN e instale mercadopago.", "danger")
        return redirect(url_for("assinatura"))

    preference = {
        "items": [
            {
                "title": "MeuLove - Acesso Vitalicio",
                "quantity": 1,
                "currency_id": "BRL",
                "unit_price": float(MP_PRODUCT_PRICE),
            }
        ],
        "payer": {"email": user["email"]},
        "external_reference": str(user["id"]),
        "back_urls": {
            "success": external_url("pagamento_processando"),
            "failure": external_url("pagamento_falha"),
            "pending": external_url("pagamento_pendente"),
        },
        "auto_return": "approved",
        "notification_url": external_url("webhook_mp"),
    }

    response = sdk.preference().create(preference)
    if response.get("status") != 201:
        flash("Erro ao criar pagamento. Tente novamente.", "danger")
        return redirect(url_for("assinatura"))

    return redirect(response["response"]["init_point"])


@app.route("/pagamento/processando")
@login_required
def pagamento_processando():
    return render_template("pagamento_pendente.html")


@app.route("/pagamento/pendente")
@login_required
def pagamento_pendente():
    return render_template("pagamento_pendente.html")


@app.route("/pagamento/falha")
@login_required
def pagamento_falha():
    return render_template("error.html", message="Pagamento não aprovado. Tente novamente.")


@app.route("/webhook/mercadopago", methods=["POST"])
@csrf.exempt
def webhook_mp():
    if not valid_mp_webhook_signature():
        return "invalid signature", 401

    if not sdk:
        return "ok", 200

    data = request.get_json(silent=True) or {}
    payment_id = mp_notification_data_id(data)
    if (data.get("type") == "payment" or payment_id) and payment_id:
        payment_info = sdk.payment().get(payment_id)
        if payment_info.get("status") == 200:
            payment = payment_info["response"]
            previous_status = log_payment_event(payment_id, payment)
            user_id = str(payment.get("external_reference", ""))
            try:
                paid_amount = Decimal(str(payment.get("transaction_amount") or "0"))
            except InvalidOperation:
                paid_amount = Decimal("0")
            amount_ok = paid_amount >= MP_PRODUCT_PRICE
            currency_ok = payment.get("currency_id") == "BRL"
            if (
                payment.get("status") == "approved"
                and previous_status != "approved"
                and user_id.isdigit()
                and amount_ok
                and currency_ok
            ):
                db = get_db()
                db.execute("UPDATE users SET pago = 1 WHERE id = ?", (user_id,))
                db.commit()
    return "ok", 200


@app.route("/create", methods=["GET", "POST"])
@pago_required
def create():
    if request.method == "POST":
        return create_surprise()
    return render_template("create.html", user=current_user())


@app.route("/surprises", methods=["POST"])
@pago_required
def create_surprise():
    name = request.form.get("nome", request.form.get("name", "")).strip()
    message = request.form.get("mensagem", request.form.get("message", "")).strip()
    music = request.form.get("musica", request.form.get("music", "")).strip()
    password = request.form.get("senha", request.form.get("password", "")).strip()

    if not name or not message:
        flash("Nome e mensagem são obrigatórios.", "danger")
        return render_template("create.html", user=current_user())

    if user_reached_surprise_limit(session["user_id"]):
        flash(f"Você atingiu o limite de {MAX_SURPRISES_PER_USER} surpresas.", "danger")
        return redirect(url_for("my_surprises"))

    saved_paths = []
    try:
        timeline = build_timeline(request.form, request.files, saved_paths=saved_paths)
        extra_photos = save_images(request.files.getlist("fotos"), MAX_EXTRA_PHOTOS, saved_paths)
    except ValueError as error:
        delete_upload_files(saved_paths)
        flash(str(error), "danger")
        return render_template("create.html", user=current_user())

    code = uuid.uuid4().hex[:8]
    db = get_db()
    db.execute(
        """
        INSERT INTO surprises (user_id, code, name, message, music, password, timeline, extra_photos)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session["user_id"],
            code,
            name,
            message,
            music,
            hash_optional_password(password),
            json.dumps(timeline),
            json.dumps(extra_photos),
        ),
    )
    db.commit()

    surprise = db.execute("SELECT * FROM surprises WHERE code = ?", (code,)).fetchone()
    url = external_url("view_surprise", code=code)
    return render_template("success.html", surprise=surprise, url=url)


@app.route("/minhas-surpresas")
@login_required
def my_surprises():
    surprises = get_db().execute(
        "SELECT * FROM surprises WHERE user_id = ? ORDER BY created_at DESC",
        (session["user_id"],),
    ).fetchall()
    surprise_links = {
        surprise["code"]: external_url("view_surprise", code=surprise["code"])
        for surprise in surprises
    }
    return render_template("my_surprises.html", surprises=surprises, surprise_links=surprise_links)


@app.route("/surprises/<int:surprise_id>/edit", methods=["GET", "POST"])
@login_required
def edit_surprise(surprise_id):
    db = get_db()
    surprise = db.execute("SELECT * FROM surprises WHERE id = ?", (surprise_id,)).fetchone()
    if not user_owns_surprise(surprise):
        abort(404)

    timeline = parse_json_list(surprise["timeline"])
    extra_photos = parse_json_list(surprise["extra_photos"])

    if request.method == "POST":
        name = request.form.get("nome", "").strip()
        message = request.form.get("mensagem", "").strip()
        music = request.form.get("musica", "").strip()
        password = request.form.get("senha", "").strip()
        remove_password = request.form.get("remover_senha") == "1"

        if not name or not message:
            flash("Nome e mensagem são obrigatórios.", "danger")
            return render_template(
                "edit_surprise.html",
                surprise=surprise,
                user=current_user(),
                timeline=timeline,
                extra_photos=extra_photos,
            )

        saved_paths = []
        try:
            timeline = build_timeline(request.form, request.files, timeline, saved_paths)
            available_photo_slots = max(MAX_EXTRA_PHOTOS - len(extra_photos), 0)
            new_photos = save_images(request.files.getlist("fotos"), available_photo_slots, saved_paths)
        except ValueError as error:
            delete_upload_files(saved_paths)
            flash(str(error), "danger")
            return redirect(url_for("edit_surprise", surprise_id=surprise_id))

        old_uploads = surprise_upload_paths(surprise)
        extra_photos.extend(new_photos)
        updated_uploads = set(extra_photos)
        updated_uploads.update(item.get("photo") for item in timeline if isinstance(item, dict) and item.get("photo"))
        db.execute(
            """
            UPDATE surprises
            SET name = ?, message = ?, music = ?, password = ?, timeline = ?, extra_photos = ?
            WHERE id = ?
            """,
            (
                name,
                message,
                music,
                None if remove_password else hash_optional_password(password) or surprise["password"],
                json.dumps(timeline),
                json.dumps(extra_photos),
                surprise_id,
            ),
        )
        db.commit()
        delete_upload_files(old_uploads - updated_uploads)
        flash("Surpresa atualizada com sucesso.", "success")
        return redirect(url_for("my_surprises"))

    return render_template(
        "edit_surprise.html",
        surprise=surprise,
        user=current_user(),
        timeline=timeline,
        extra_photos=extra_photos,
    )


@app.route("/surprises/<int:surprise_id>/delete", methods=["POST"])
@login_required
def delete_surprise(surprise_id):
    db = get_db()
    surprise = db.execute("SELECT * FROM surprises WHERE id = ?", (surprise_id,)).fetchone()
    if not user_owns_surprise(surprise):
        abort(404)

    upload_paths = surprise_upload_paths(surprise)
    db.execute("DELETE FROM surprises WHERE id = ?", (surprise_id,))
    db.commit()
    delete_upload_files(upload_paths)
    flash("Surpresa excluída.", "success")
    return redirect(url_for("my_surprises"))


@app.route("/s/<code>")
@app.route("/surpresa/<code>")
def view_surprise(code):
    surprise = get_db().execute("SELECT * FROM surprises WHERE code = ?", (code,)).fetchone()
    if not surprise:
        abort(404)

    locked = not can_view_surprise_media(surprise)
    return render_template(
        "surprise.html",
        surprise=surprise,
        locked=locked,
        timeline=[] if locked else parse_json_list(surprise["timeline"]),
        extra_photos=[] if locked else parse_json_list(surprise["extra_photos"]),
        youtube={"watch": "", "embed": ""} if locked else build_youtube(surprise["music"]),
    )


@app.route("/uploads/<code>/<filename>")
def protected_upload(code, filename):
    filename = normalize_upload_name(filename)
    surprise = get_db().execute("SELECT * FROM surprises WHERE code = ?", (code,)).fetchone()
    if not surprise or not surprise_contains_file(surprise, filename):
        abort(404)
    if not can_view_surprise_media(surprise):
        abort(403)

    file_path = UPLOAD_FOLDER / filename
    if not file_path.is_file():
        abort(404)
    return send_file(file_path, max_age=60 * 60 * 24 * 30)


@app.route("/surpresa/<code>/verificar-senha", methods=["POST"])
def verify_surprise_password(code):
    if is_rate_limited(f"surprise_password:{code}", limit=8, window=300):
        return jsonify({"ok": False, "error": "Muitas tentativas. Tente novamente em alguns minutos."}), 429

    surprise = get_db().execute("SELECT * FROM surprises WHERE code = ?", (code,)).fetchone()
    if not surprise:
        abort(404)

    data = request.get_json(silent=True) or {}
    password_ok = verify_stored_password(surprise["password"], data.get("password", ""))
    if password_ok and not password_is_hash(surprise["password"]):
        db = get_db()
        db.execute(
            "UPDATE surprises SET password = ? WHERE id = ?",
            (hash_optional_password(data.get("password", "")), surprise["id"]),
        )
        db.commit()
    if password_ok:
        session[f"surprise_{code}"] = True
    return jsonify({"ok": password_ok})


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if not client_ip_allowed(ADMIN_IP_ALLOWLIST):
        abort(404)

    if request.method == "POST":
        if is_rate_limited("admin_login", limit=6, window=300):
            flash("Muitas tentativas. Aguarde alguns minutos e tente novamente.", "danger")
            return render_template("admin_login.html"), 429

        configured_hash = os.environ.get("ADMIN_PASSWORD_HASH")
        provided_password = request.form.get("password", "")
        password_ok = bool(configured_hash and check_password_hash(configured_hash, provided_password))

        if password_ok:
            session["admin_logged"] = True
            return redirect(url_for("admin"))
        flash("Senha de admin inválida ou ADMIN_PASSWORD_HASH não configurada.", "danger")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged", None)
    return redirect(url_for("home"))


@app.route("/admin")
@admin_required
def admin():
    per_page = 10
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        page = 1
    page = max(page, 1)

    db = get_db()
    total = db.execute("SELECT COUNT(*) AS total FROM surprises").fetchone()["total"]
    total_pages = max((total + per_page - 1) // per_page, 1)
    page = min(page, total_pages)
    offset = (page - 1) * per_page

    surprises = db.execute(
        """
        SELECT s.*, u.name AS user_name, u.email AS user_email
        FROM surprises s
        LEFT JOIN users u ON u.id = s.user_id
        ORDER BY s.created_at DESC
        LIMIT ? OFFSET ?
        """,
        (per_page, offset),
    ).fetchall()
    return render_template(
        "admin.html",
        surprises=surprises,
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages,
        start_index=offset + 1 if total else 0,
        end_index=min(offset + per_page, total),
    )


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", message="Página não encontrada."), 404


@app.errorhandler(413)
def too_large(error):
    return render_template("error.html", message="Arquivo muito grande. Envie imagens menores."), 413


@app.errorhandler(500)
def internal_error(error):
    app.logger.error("Erro interno: %s", error, exc_info=True)
    return render_template("error.html", message="Erro interno. Tente novamente em alguns instantes."), 500


init_db_default = "1" if os.environ.get("APP_ENV") == "production" else "0"
if os.environ.get("INIT_DB_ON_STARTUP", init_db_default) == "1":
    with app.app_context():
        init_db()


if __name__ == "__main__":
    app.run(debug=False)
