import json
import os
import time
import ipaddress
from flask import Flask, request, render_template_string


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SESSION_FILE = os.path.join(BASE_DIR, 'sessions.json')
SESSION_TTL_SECONDS = 60

app = Flask(__name__)


def load_sessions():
    try:
        with open(SESSION_FILE, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        return {}

    sessions = data.get('sessions', {})
    if not isinstance(sessions, dict):
        return {}

    now = time.time()
    cleaned = {}
    for ip, expires_at in sessions.items():
        try:
            if now < float(expires_at):
                cleaned[ip] = float(expires_at)
        except (TypeError, ValueError):
            continue
    return cleaned


def save_sessions(sessions):
    tmp_path = SESSION_FILE + '.tmp'
    payload = {'sessions': sessions}
    with open(tmp_path, 'w') as f:
        json.dump(payload, f, indent=4)
    os.replace(tmp_path, SESSION_FILE)


def detect_client_ip():
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        candidate = forwarded_for.split(',')[0].strip()
        if candidate:
            return candidate
    return request.remote_addr or ''


def validate_ip(value):
    return str(ipaddress.ip_address(value))


PAGE = """
<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SDN Auth Portal</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 720px; margin: 48px auto; padding: 0 20px; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 24px; }
    button { padding: 12px 18px; border: 0; border-radius: 8px; cursor: pointer; }
    .ok { color: #0a7; }
    .warn { color: #b60; }
    input { padding: 10px; width: 100%; margin: 10px 0 16px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>SDN Authentication Portal</h1>
    <p>IP phát hiện: <strong>{{ client_ip }}</strong></p>
    {% if message %}
      <p class="ok">{{ message }}</p>
    {% endif %}
    {% if error %}
      <p class="warn">{{ error }}</p>
    {% endif %}
    <form method="post" action="/authenticate">
      <label for="ip">IP cần xác thực</label>
      <input id="ip" name="ip" placeholder="{{ client_ip }}" value="{{ client_ip }}">
      <button type="submit">Xác thực IP của tôi</button>
    </form>
    <p>Phiên hợp lệ trong {{ ttl }} giây.</p>
  </div>
</body>
</html>
"""


@app.route('/', methods=['GET'])
def index():
    client_ip = detect_client_ip()
    return render_template_string(PAGE, client_ip=client_ip, message=None, error=None, ttl=SESSION_TTL_SECONDS)


@app.route('/authenticate', methods=['POST'])
def authenticate():
    sessions = load_sessions()
    client_ip = (request.form.get('ip') or detect_client_ip()).strip()

    try:
        normalized_ip = validate_ip(client_ip)
    except ValueError:
        return render_template_string(PAGE, client_ip=client_ip, message=None, error='IP không hợp lệ.', ttl=SESSION_TTL_SECONDS), 400

    expires_at = time.time() + SESSION_TTL_SECONDS
    sessions[normalized_ip] = expires_at
    save_sessions(sessions)

    remaining = int(expires_at - time.time())
    message = f'Da xac thuc {normalized_ip}. Quyen truy cap con hieu luc trong {remaining} giay.'
    return render_template_string(PAGE, client_ip=normalized_ip, message=message, error=None, ttl=SESSION_TTL_SECONDS)


@app.route('/sessions', methods=['GET'])
def sessions_view():
    sessions = load_sessions()
    return {
        'sessions': sessions,
        'count': len(sessions),
    }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)