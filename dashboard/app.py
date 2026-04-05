import os
import sys
import requests

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

from flask import Flask, render_template, request, redirect, session, url_for  # noqa: F401

from engine.attack_timeline import AttackTimelineEngine

BASE_DIR = os.path.dirname(__file__)
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

app = Flask(__name__, template_folder=TEMPLATES_DIR)
app.secret_key = "netguard-secret"

USERNAME = "admin"
PASSWORD = "netguard123"

API_BASE = "http://127.0.0.1:5000"


def is_logged_in():
    return "user" in session


@app.route("/", methods=["GET", "POST"])
def login():

    if is_logged_in():
        return redirect("/dashboard")

    error = None

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        token = request.form.get("token")

        if username == USERNAME and password == PASSWORD:

            session["user"] = {
                "username": username
            }

            return redirect("/dashboard")

        if token:

            session["user"] = {
                "token": token
            }

            return redirect("/dashboard")

        error = "login inválido"

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

    r = requests.get(f"{API_BASE}/api/soc/events?limit=50")

    data = r.json()

    return render_template(
        "events.html",
        events=data.get("events", [])
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

    r = requests.get(
        f"{API_BASE}/api/soc/events?limit=200",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    events = r.json().get("events", [])

    timelines = engine.build_timelines(events)

    return render_template(
        "timeline.html",
        timelines=[t.to_dict() for t in timelines]
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


if __name__ == "__main__":
    app.run(port=5001, debug=True)