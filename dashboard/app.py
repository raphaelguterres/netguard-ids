import os
import secrets
import sys

import requests
from flask import Flask, redirect, render_template, request, session

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

from engine.attack_timeline import AttackTimelineEngine

BASE_DIR = os.path.dirname(__file__)
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

API_BASE = os.environ.get("NETGUARD_API_BASE", "http://127.0.0.1:5000").rstrip("/")
REQUEST_TIMEOUT = float(os.environ.get("NETGUARD_DASHBOARD_TIMEOUT", "5"))
DEBUG = os.environ.get("NETGUARD_DASHBOARD_DEBUG", "").lower() in {"1", "true", "yes", "on"}
USERNAME = os.environ.get("NETGUARD_DASHBOARD_USERNAME", "").strip()
PASSWORD = os.environ.get("NETGUARD_DASHBOARD_PASSWORD", "").strip()

app = Flask(__name__, template_folder=TEMPLATES_DIR)
app.secret_key = os.environ.get("NETGUARD_DASHBOARD_SECRET_KEY") or secrets.token_urlsafe(32)


def password_login_enabled():
    return bool(USERNAME and PASSWORD)


def is_logged_in():
    return "user" in session


def fetch_json(path, headers=None, default=None):
    try:
        response = requests.get(
            f"{API_BASE}{path}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        return default if default is not None else {}


@app.route("/", methods=["GET", "POST"])
def login():
    if is_logged_in():
        return redirect("/dashboard")

    error = None

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        token = request.form.get("token")

        if password_login_enabled() and username == USERNAME and password == PASSWORD:
            session["user"] = {"username": username}
            return redirect("/dashboard")

        if token:
            session["user"] = {"token": token}
            return redirect("/dashboard")

        error = "login invalido"

    return render_template("login.html", error=error)


@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect("/")

    return render_template("dashboard.html")


@app.route("/events")
def events():
    if not is_logged_in():
        return redirect("/")

    data = fetch_json("/api/soc/events?limit=50", default={"events": []})

    return render_template(
        "events.html",
        events=data.get("events", []),
    )


@app.route("/tickets")
def tickets():
    if not is_logged_in():
        return redirect("/")

    return render_template("tickets.html")


@app.route("/timeline")
def timeline():
    if not is_logged_in():
        return redirect("/")

    token = session.get("user", {}).get("token")

    if not token:
        return render_template("timeline.html", timelines=[])

    engine = AttackTimelineEngine()
    data = fetch_json(
        "/api/soc/events?limit=200",
        headers={"Authorization": f"Bearer {token}"},
        default={"events": []},
    )
    events = data.get("events", [])
    timelines = engine.build_timelines(events)

    return render_template(
        "timeline.html",
        timelines=[timeline.to_dict() for timeline in timelines],
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(port=5001, debug=DEBUG)
