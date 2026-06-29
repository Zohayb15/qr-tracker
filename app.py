import os
import logging

# Without this, Flask's app.logger can end up with no configured output
# under gunicorn (unlike Flask's own dev server, which sets this up
# automatically) — meaning logger.info/warning/error calls go nowhere
# and never show up in Render's log viewer.
logging.basicConfig(level=logging.INFO)
import io
import csv
import uuid
import secrets
from datetime import datetime, timedelta
from functools import wraps

import qrcode
import qrcode.image.svg
import requests
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, send_file, abort, make_response, flash, g
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from user_agents import parse as parse_ua

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

# Use a real hosted database (e.g. Render Postgres) when DATABASE_URL is set —
# this is what makes accounts/scan data survive redeploys and restarts.
# Falls back to a local SQLite file for local development only.
database_url = os.environ.get("DATABASE_URL")
if database_url:
    # Render (and some other hosts) hand out URLs starting with "postgres://",
    # but SQLAlchemy 2.x requires the "postgresql://" scheme.
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "scans.db")

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Serverless Postgres providers (like Neon) close idle connections
# aggressively. pool_pre_ping tests each connection before using it and
# transparently reconnects if it's gone stale, instead of crashing with
# "SSL connection has been closed unexpectedly".
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 280,
}
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

db = SQLAlchemy(app)

VISITOR_COOKIE = "qr_visitor_id"
COOKIE_MAX_AGE = 60 * 60 * 24 * 365 * 2  # 2 years

RESET_TOKEN_SALT = "password-reset"
RESET_TOKEN_MAX_AGE = 3600  # 1 hour


def get_reset_serializer():
    return URLSafeTimedSerializer(app.secret_key)


def send_email(to_address, subject, body):
    """Send a plain-text email via Resend's HTTP API.

    Render's free tier blocks outbound SMTP (ports 25/465/587) entirely, so
    sending via smtplib/Gmail can never work there — connections just hang
    until they time out. Resend sends over regular HTTPS instead, which
    isn't affected by that block.

    Requires RESEND_API_KEY to be set. Without it, this logs the email
    content instead of sending it, so the flow is still testable before
    real sending is wired up. RESEND_FROM_EMAIL defaults to Resend's shared
    testing address, which works without verifying your own domain — it
    can send TO any real address, it just shows as coming from
    onboarding@resend.dev until a domain is verified."""
    api_key = os.environ.get("RESEND_API_KEY")
    from_email = os.environ.get("RESEND_FROM_EMAIL", "onboarding@resend.dev")

    if not api_key:
        app.logger.warning(
            "RESEND_API_KEY not set — logging email instead of sending it.\n"
            "To: %s\nSubject: %s\n\n%s", to_address, subject, body
        )
        return False

    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "from": from_email,
                "to": [to_address],
                "subject": subject,
                "text": body,
            },
            timeout=10,
        )
        if resp.status_code in (200, 201):
            return True
        app.logger.error("Resend API error (%s): %s", resp.status_code, resp.text)
        return False
    except requests.RequestException as e:
        app.logger.error("Failed to send email via Resend: %s", e)
        return False


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), nullable=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    campaigns = db.relationship("Campaign", backref="owner", lazy="dynamic",
                                 cascade="all, delete-orphan")

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)


class Campaign(db.Model):
    __tablename__ = "campaigns"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    code = db.Column(db.String(16), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    destination_url = db.Column(db.String(2000), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    scans = db.relationship("Scan", backref="campaign", lazy="dynamic",
                             cascade="all, delete-orphan")


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaigns.id"), nullable=False, index=True)
    visitor_id = db.Column(db.String(64), nullable=False, index=True)
    is_repeat = db.Column(db.Boolean, default=False)

    ip_address = db.Column(db.String(64))
    city = db.Column(db.String(120))
    region = db.Column(db.String(120))
    country = db.Column(db.String(120))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)

    device_type = db.Column(db.String(40))
    os_family = db.Column(db.String(80))
    browser = db.Column(db.String(80))

    referrer = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

@app.before_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user = User.query.get(user_id) if user_id else None


@app.context_processor
def inject_user():
    return {"current_user": g.get("user")}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def owns_campaign_or_404(code):
    campaign = Campaign.query.filter_by(code=code).first_or_404()
    if campaign.owner_id != g.user.id:
        abort(404)
    return campaign


# ---------------------------------------------------------------------------
# Other helpers
# ---------------------------------------------------------------------------

def generate_code(length=7):
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    while True:
        code = "".join(secrets.choice(alphabet) for _ in range(length))
        if not Campaign.query.filter_by(code=code).first():
            return code


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def lookup_geo(ip):
    """Look up approximate city-level location for an IP address.
    Falls back gracefully for local/private IPs or if the lookup fails."""
    private_prefixes = ("127.", "10.", "192.168.", "::1")
    if ip in ("unknown", "") or ip.startswith(private_prefixes):
        return {"city": "Local/dev", "region": "", "country": "", "lat": None, "lon": None}
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,city,region,country,lat,lon"},
            timeout=2.5,
        )
        data = resp.json()
        if data.get("status") == "success":
            return {
                "city": data.get("city") or "Unknown",
                "region": data.get("region") or "",
                "country": data.get("country") or "",
                "lat": data.get("lat"),
                "lon": data.get("lon"),
            }
    except requests.RequestException:
        pass
    return {"city": "Unknown", "region": "", "country": "", "lat": None, "lon": None}


def parse_device(user_agent_string):
    ua = parse_ua(user_agent_string or "")
    if ua.is_mobile:
        device_type = "Mobile"
    elif ua.is_tablet:
        device_type = "Tablet"
    elif ua.is_pc:
        device_type = "Desktop"
    else:
        device_type = "Other"
    os_family = f"{ua.os.family} {ua.os.version_string}".strip()
    browser = f"{ua.browser.family} {ua.browser.version_string}".strip()
    return device_type, os_family, browser


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not password or not email:
            flash("Username, email, and password are required.")
        elif "@" not in email or "." not in email.split("@")[-1]:
            flash("Please enter a valid email address.")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.")
        elif password != confirm:
            flash("Passwords don't match.")
        elif User.query.filter_by(username=username).first():
            flash("That username is already taken.")
        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists.")
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            session["user_id"] = user.id
            return redirect(url_for("index"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        flash("Incorrect username or password.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first() if email else None
        app.logger.info("Password reset requested for email=%r, found_user=%s", email, bool(user))

        if user:
            serializer = get_reset_serializer()
            token = serializer.dumps(user.id, salt=RESET_TOKEN_SALT)
            reset_url = url_for("reset_password", token=token, _external=True)
            sent_ok = send_email(
                user.email,
                "Reset your QR scan tracker password",
                f"Hi {user.username},\n\n"
                f"Click the link below to reset your password. This link "
                f"expires in 1 hour.\n\n{reset_url}\n\n"
                f"If you didn't request this, you can safely ignore this email."
            )
            app.logger.info("send_email returned %s for %r", sent_ok, user.email)

        # Always show the same message whether or not the email matched —
        # this avoids revealing which emails have accounts on this app.
        flash("If that email is associated with an account, we've sent a password reset link.", "success")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    serializer = get_reset_serializer()
    try:
        user_id = serializer.loads(token, salt=RESET_TOKEN_SALT, max_age=RESET_TOKEN_MAX_AGE)
    except SignatureExpired:
        flash("That reset link has expired. Please request a new one.")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("That reset link isn't valid.")
        return redirect(url_for("forgot_password"))

    user = User.query.get(user_id)
    if not user:
        flash("That reset link isn't valid.")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if len(password) < 6:
            flash("Password must be at least 6 characters.")
        elif password != confirm:
            flash("Passwords don't match.")
        else:
            user.set_password(password)
            db.session.commit()
            flash("Your password has been reset \u2014 log in with your new password.", "success")
            return redirect(url_for("login"))

    return render_template("reset_password.html")


# ---------------------------------------------------------------------------
# Campaign creation / list (per-user)
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        name = request.form.get("name", "").strip() or "Untitled campaign"
        dest = request.form.get("destination_url", "").strip()
        if not dest:
            flash("Please enter a destination URL.")
            return redirect(url_for("index"))
        if not dest.startswith(("http://", "https://")):
            dest = "https://" + dest
        code = generate_code()
        campaign = Campaign(owner_id=g.user.id, code=code, name=name, destination_url=dest)
        db.session.add(campaign)
        db.session.commit()
        flash(f"QR code created for \u201c{name}\u201d \u2014 scroll down to download it.", "success")
        return redirect(url_for("index"))

    campaigns = Campaign.query.filter_by(owner_id=g.user.id).order_by(Campaign.created_at.desc()).all()
    return render_template("index.html", campaigns=campaigns)


# ---------------------------------------------------------------------------
# QR image generation (PNG + SVG download)
# ---------------------------------------------------------------------------

@app.route("/qr/<code>.png")
def qr_image_png(code):
    campaign = Campaign.query.filter_by(code=code).first_or_404()
    tracking_url = url_for("scan", code=campaign.code, _external=True)
    img = qrcode.make(tracking_url, box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    download = request.args.get("download")
    return send_file(
        buf, mimetype="image/png",
        as_attachment=bool(download),
        download_name=f"{campaign.code}-qr.png" if download else None,
    )


@app.route("/qr/<code>.svg")
def qr_image_svg(code):
    campaign = Campaign.query.filter_by(code=code).first_or_404()
    tracking_url = url_for("scan", code=campaign.code, _external=True)
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(tracking_url, image_factory=factory, box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    download = request.args.get("download")
    return send_file(
        buf, mimetype="image/svg+xml",
        as_attachment=bool(download),
        download_name=f"{campaign.code}-qr.svg" if download else None,
    )


# ---------------------------------------------------------------------------
# The actual tracked scan (always public — this is what the QR points to)
# ---------------------------------------------------------------------------

@app.route("/q/<code>")
def scan(code):
    campaign = Campaign.query.filter_by(code=code).first_or_404()

    visitor_id = request.cookies.get(VISITOR_COOKIE)
    is_new_cookie = False
    if not visitor_id:
        visitor_id = uuid.uuid4().hex
        is_new_cookie = True

    seen_before = db.session.query(Scan.id).filter_by(
        campaign_id=campaign.id, visitor_id=visitor_id
    ).first() is not None

    ip = get_client_ip()
    geo = lookup_geo(ip)
    device_type, os_family, browser = parse_device(request.headers.get("User-Agent", ""))

    scan_row = Scan(
        campaign_id=campaign.id,
        visitor_id=visitor_id,
        is_repeat=seen_before,
        ip_address=ip,
        city=geo["city"],
        region=geo["region"],
        country=geo["country"],
        latitude=geo["lat"],
        longitude=geo["lon"],
        device_type=device_type,
        os_family=os_family,
        browser=browser,
        referrer=request.headers.get("Referer", ""),
    )
    db.session.add(scan_row)
    db.session.commit()

    resp = make_response(redirect(campaign.destination_url))
    if is_new_cookie:
        resp.set_cookie(VISITOR_COOKIE, visitor_id, max_age=COOKIE_MAX_AGE, samesite="Lax")
    return resp


# ---------------------------------------------------------------------------
# Dashboard (per-user)
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    campaigns = Campaign.query.filter_by(owner_id=g.user.id).order_by(Campaign.created_at.desc()).all()
    summary = []
    for c in campaigns:
        total = c.scans.count()
        unique = db.session.query(Scan.visitor_id).filter_by(campaign_id=c.id).distinct().count()
        summary.append({"campaign": c, "total": total, "unique": unique})
    return render_template("dashboard.html", summary=summary)


@app.route("/dashboard/<code>")
@login_required
def dashboard_detail(code):
    campaign = owns_campaign_or_404(code)
    scans = campaign.scans.order_by(Scan.timestamp.desc()).all()

    # Number scans in the order they actually happened (#1 = earliest ever),
    # independent of which device/visitor made each scan.
    total = len(scans)
    for s in scans:
        s.scan_number = total - scans.index(s)

    unique_visitors = len({s.visitor_id for s in scans})
    repeat_scans = sum(1 for s in scans if s.is_repeat)

    location_counts = {}
    device_counts = {}
    browser_counts = {}
    daily_counts = {}

    for s in scans:
        loc = ", ".join([p for p in [s.city, s.region] if p]) or "Unknown"
        location_counts[loc] = location_counts.get(loc, 0) + 1
        device_counts[s.device_type or "Unknown"] = device_counts.get(s.device_type or "Unknown", 0) + 1
        browser_counts[s.browser or "Unknown"] = browser_counts.get(s.browser or "Unknown", 0) + 1
        day = s.timestamp.strftime("%Y-%m-%d")
        daily_counts[day] = daily_counts.get(day, 0) + 1

    today = datetime.utcnow().date()
    daily_series = []
    for i in range(13, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        daily_series.append({"date": d, "count": daily_counts.get(d, 0)})

    return render_template(
        "detail.html",
        campaign=campaign,
        scans=scans,
        total=total,
        unique_visitors=unique_visitors,
        repeat_scans=repeat_scans,
        location_counts=sorted(location_counts.items(), key=lambda x: -x[1]),
        device_counts=sorted(device_counts.items(), key=lambda x: -x[1]),
        browser_counts=sorted(browser_counts.items(), key=lambda x: -x[1]),
        daily_series=daily_series,
    )


@app.route("/dashboard/<code>/export.csv")
@login_required
def export_csv(code):
    campaign = owns_campaign_or_404(code)
    scans = campaign.scans.order_by(Scan.timestamp.desc()).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "timestamp_utc", "visitor_id", "is_repeat", "ip_address",
        "city", "region", "country", "latitude", "longitude",
        "device_type", "os", "browser", "referrer"
    ])
    for s in scans:
        writer.writerow([
            s.timestamp.isoformat(), s.visitor_id, s.is_repeat, s.ip_address,
            s.city, s.region, s.country, s.latitude, s.longitude,
            s.device_type, s.os_family, s.browser, s.referrer
        ])

    out = io.BytesIO(buf.getvalue().encode("utf-8"))
    out.seek(0)
    return send_file(
        out, mimetype="text/csv", as_attachment=True,
        download_name=f"{campaign.code}_scans.csv"
    )


@app.route("/dashboard/<code>/delete", methods=["POST"])
@login_required
def delete_campaign(code):
    campaign = owns_campaign_or_404(code)
    db.session.delete(campaign)
    db.session.commit()
    return redirect(url_for("dashboard"))


with app.app_context():
    db.create_all()

    # db.create_all() only creates missing tables — it won't add new columns
    # to a table that already exists (e.g. your live database). This adds
    # the 'email' column on startup if it's not already there, so existing
    # deployments pick up the new feature without a manual migration step.
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)
    if "users" in inspector.get_table_names():
        existing_columns = [col["name"] for col in inspector.get_columns("users")]
        if "email" not in existing_columns:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR(255)"))
                conn.commit()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
