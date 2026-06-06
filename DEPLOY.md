# Deploy

## Start command

```bash
gunicorn app:app
```

## Docker

The project includes a `Dockerfile` for container platforms:

```bash
docker build -t meulove .
docker run -p 5000:5000 --env-file .env meulove
```

## Render Blueprint

This project includes `render.yaml`.

1. Push the repository to GitHub.
2. In Render, choose **New > Blueprint**.
3. Select this repository.
4. Fill the secret values marked with `sync: false`.
5. Deploy.

The blueprint creates:

- A Python web service.
- A 1 GB persistent disk mounted at `/var/data`.
- A Redis-compatible Key Value service for rate limiting.

## Required environment variables

```env
APP_ENV=production
SECRET_KEY=uma_chave_grande_aleatoria
PUBLIC_BASE_URL=https://seudominio.com
SESSION_COOKIE_SECURE=1
MYSQL_HOST=host_mysql
MYSQL_PORT=3306
MYSQL_USER=usuario_mysql
MYSQL_PASSWORD=senha_mysql
MYSQL_DATABASE=meulove
INIT_DB_ON_STARTUP=1
UPLOAD_FOLDER=/var/data/uploads
ADMIN_PASSWORD_HASH=hash_gerado_com_werkzeug
MP_ACCESS_TOKEN=token_real_do_mercado_pago
MP_WEBHOOK_SECRET=secret_do_webhook_mercado_pago
MP_PRODUCT_PRICE=19.00
MP_WEBHOOK_TOLERANCE_SECONDS=600
PASSWORD_RESET_SECONDS=3600
WTF_CSRF_TIME_LIMIT=3600
MAX_SURPRISES_PER_USER=10
ADMIN_IP_ALLOWLIST=
CONTENT_SECURITY_POLICY=
RATE_LIMIT_BACKEND=redis
REDIS_URL=redis://...
SMTP_HOST=smtp.seudominio.com
SMTP_PORT=587
SMTP_USERNAME=usuario_smtp
SMTP_PASSWORD=senha_smtp
SMTP_FROM=contato@seudominio.com
```

## MySQL

This app uses MySQL. Create the database before starting the app and configure one of these options:

- `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD`, and `MYSQL_DATABASE`.
- Or `MYSQL_URL`/`DATABASE_URL` in the format `mysql://usuario:senha@host:3306/banco`.

The app creates/updates the required tables at startup. Uploaded photos still use local storage, so keep `UPLOAD_FOLDER` on a persistent disk if your host uses ephemeral filesystems.

For local visual preview without MySQL running, use `APP_ENV=development` with `INIT_DB_ON_STARTUP=0`. Pages that read/write data still require MySQL.

## Mercado Pago

After publishing the app with HTTPS, configure the Mercado Pago webhook URL as:

```text
https://seudominio.com/webhook/mercadopago
```

Set `PUBLIC_BASE_URL` to the final HTTPS domain. The app uses this fixed value for password reset links, payment return URLs, Mercado Pago webhooks, and shared surprise links.
