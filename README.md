# Ollama AD Chat (LDAPS)

## Projektstruktur

```
app/
  main.py
  config.py
  ldap_client.py
  security.py
  templates/
  static/

deploy/
  systemd/
  nginx/
.env.example
requirements.txt
```

## Lokale Installation & Runbook

1. **Python venv + Dependencies**

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

2. **Ollama Setup**

```bash
ollama pull llama3
```

3. **Konfiguration**

```bash
cp .env.example .env
# Werte anpassen (LDAPS, Secrets, Gruppen etc.)
```

4. **Start (Dev)**

```bash
export $(grep -v '^#' .env | xargs)
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

5. **Ports / Firewall**

* App: `8000/tcp`
* Ollama lokal: `11434/tcp` (nur localhost)
* LDAPS: `636/tcp` zum AD

6. **Logs**

* Dev: stdout
* systemd: `journalctl -u ollama-chat.service -f`

## Security-Notizen (Umgesetzt)

* **LDAPS mit Zertifikatsprüfung** (optional CA-Path).
* **LDAP Injection Schutz** durch `escape_filter_chars`.
* **Service-Account Bind + User Bind** nach DN-Auflösung.
* **Generische Fehlermeldungen** (keine User Enumeration).
* **Serverseitige Session** mit **Signed Cookie** + Rotation nach Login.
* **Inactivity + Absolute Timeout** konfigurierbar.
* **CSRF Schutz** für Login/Logout/Chat/Clear (Token + Origin Check).
* **Security Header** inkl. CSP, XFO, nosniff, Permissions-Policy.
* **Rate Limits & Lockout** (IP+User), inkl. Spray-Detection Logging.
* **Keine Persistenz von Chat-Inhalten**, keine Payload-Logs.

## AD Auth Strategie

1. Service-Account bindet (read-only).
2. User-DN wird per konfigurierbarem Filter gesucht (Default sAMAccountName).
3. User bindet mit DN (oder optional UPN) zur Passwortprüfung.
4. Attribute werden aus dem Lookup gelesen (displayName, mail, memberOf, objectGUID).
5. Optionaler Gruppen-Check via `REQUIRED_AD_GROUP_DN`.

## Deployment (Bare Metal)

### systemd

Siehe `deploy/systemd/ollama-chat.service`. Platzieren Sie:

* App: `/opt/ollama-ad-chat`
* Env: `/etc/ollama-ad-chat/ollama-ad-chat.env` (root-readable)
* User/Group: `ollama-chat`

### Nginx (optional)

Beispiel in `deploy/nginx/ollama-chat.conf` mit TLS-Termination und Redirect.

## Produktionsparameter

* Uvicorn single-process (für einfache Deployments). Für höhere Last: Gunicorn + Uvicorn workers.
* `SESSION_COOKIE_SECURE=true` setzen hinter TLS.
* `RATE_LIMIT_*` anpassen, wenn Nutzung wächst.

## Next Hardening Steps

* Redis Session Store (persistente serverseitige Sessions, TTL).
* Zentralisiertes Security-Logging (SIEM / audit trail).
* mTLS zwischen Nginx und App.
* MFA / Conditional Access vor dem Login.
* IP-allowlist für Admin-Netze.
