"""
NetGuard Tray v3.0
Ícone na bandeja do sistema com menu, notificações nativas
e abertura automática do dashboard no navegador.
"""

import threading
import webbrowser
import time
import json
import urllib.request
import urllib.error
import sys
import os
import subprocess

# Tenta importar pystray e PIL — instalados via requirements
try:
    import pystray
    from pystray import MenuItem, Menu
    from PIL import Image, ImageDraw
    TRAY_OK = True
except ImportError:
    TRAY_OK = False

# Notificações nativas do Windows
try:
    from plyer import notification
    NOTIFY_OK = True
except ImportError:
    NOTIFY_OK = False

API = "http://localhost:5000/api"

# ── Estado global ─────────────────────────────────────────────────

state = {
    "critical": 0,
    "high":     0,
    "total":    0,
    "monitor":  "iniciando",
    "last_check": None,
    "icon_ref": None,
}

# IDs de detecções já notificadas (evita repetir)
_notificados = set()


# ── Ícone dinâmico (desenhado em código) ─────────────────────────

def criar_icone(cor="#00c97a"):
    """
    Desenha um escudo simples como ícone.
    Verde = tudo ok | Amarelo = alertas | Vermelho = crítico
    """
    tam = 64
    img = Image.new("RGBA", (tam, tam), (0, 0, 0, 0))
    d   = ImageDraw.Draw(img)

    # Fundo escuro do escudo
    d.polygon([
        (8, 4), (56, 4), (56, 36),
        (32, 60), (8, 36)
    ], fill="#0d1628")

    # Borda colorida
    d.polygon([
        (8, 4), (56, 4), (56, 36),
        (32, 60), (8, 36)
    ], outline=cor, width=4)

    # Letra N no centro
    d.text((22, 18), "N", fill=cor)

    return img


def icone_para_estado(critical, high):
    if critical > 0:
        return criar_icone("#f03e3e")   # vermelho
    if high > 0:
        return criar_icone("#ff8c42")   # laranja
    return criar_icone("#00c97a")       # verde


# ── Notificações ──────────────────────────────────────────────────

def notificar(titulo, mensagem, urgente=False):
    """Envia notificação nativa do Windows."""
    if NOTIFY_OK:
        try:
            notification.notify(
                title=titulo,
                message=mensagem,
                app_name="NetGuard IDS",
                timeout=8 if urgente else 5,
            )
        except Exception:
            pass
    else:
        # Fallback: PowerShell balloon notification
        try:
            script = f"""
            Add-Type -AssemblyName System.Windows.Forms
            $n = New-Object System.Windows.Forms.NotifyIcon
            $n.Icon = [System.Drawing.SystemIcons]::Shield
            $n.Visible = $true
            $n.BalloonTipTitle = '{titulo}'
            $n.BalloonTipText = '{mensagem}'
            $n.BalloonTipIcon = 'Warning'
            $n.ShowBalloonTip(6000)
            Start-Sleep -Seconds 6
            $n.Dispose()
            """
            subprocess.Popen(
                ["powershell", "-WindowStyle", "Hidden", "-Command", script],
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
        except Exception:
            pass


# ── Polling de detecções ──────────────────────────────────────────

def checar_novas_deteccoes():
    """Busca detecções novas e notifica se necessário."""
    try:
        url  = f"{API}/detections?limit=20&status=active"
        req  = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=3)
        data = json.loads(resp.read())

        deteccoes = data.get("detections", [])
        for d in deteccoes:
            did = d.get("detection_id")
            if did in _notificados:
                continue
            _notificados.add(did)

            sev  = d.get("severity","").upper()
            nome = d.get("threat_name","")
            ip   = d.get("source_ip","?")

            if d.get("severity") == "critical":
                notificar(
                    f"🔴 CRÍTICO — {nome}",
                    f"IP: {ip}\n{d.get('description','')}",
                    urgente=True
                )
            elif d.get("severity") == "high":
                notificar(
                    f"🟠 ALTO — {nome}",
                    f"IP: {ip}",
                )

    except Exception:
        pass


def loop_polling(intervalo=15):
    """Verifica novas detecções a cada N segundos."""
    while True:
        try:
            # Atualiza estatísticas
            url  = f"{API}/statistics"
            req  = urllib.request.Request(url)
            resp = urllib.request.urlopen(req, timeout=3)
            stats = json.loads(resp.read())

            state["critical"] = stats.get("critical", 0)
            state["high"]     = stats.get("high", 0)
            state["total"]    = stats.get("total", 0)
            state["last_check"] = time.strftime('%H:%M:%S')

            # Atualiza ícone conforme estado
            if state["icon_ref"]:
                novo_icone = icone_para_estado(state["critical"], state["high"])
                state["icon_ref"].icon = novo_icone
                state["icon_ref"].title = titulo_tray()

            # Verifica novas detecções para notificar
            checar_novas_deteccoes()

        except Exception:
            state["monitor"] = "offline"
            if state["icon_ref"]:
                state["icon_ref"].icon = criar_icone("#5a7a9a")  # cinza = offline

        time.sleep(intervalo)


def titulo_tray():
    c = state["critical"]
    h = state["high"]
    t = state["total"]
    if c > 0:
        return f"NetGuard — ⚠ {c} CRÍTICO(S)"
    if h > 0:
        return f"NetGuard — {h} alto(s) | Total: {t}"
    return f"NetGuard IDS — Rede segura | {t} eventos"


# ── Menu do tray ─────────────────────────────────────────────────

def abrir_dashboard(icon, item):
    webbrowser.open("http://localhost:5000")

def abrir_deteccoes(icon, item):
    webbrowser.open("http://localhost:5000#deteccoes")

def mostrar_status(icon, item):
    c = state["critical"]
    h = state["high"]
    t = state["total"]
    chk = state["last_check"] or "—"
    msg = (f"Total: {t} detecções\n"
           f"Crítico: {c} | Alto: {h}\n"
           f"Última verificação: {chk}")
    notificar("NetGuard IDS — Status", msg)

def sair(icon, item):
    icon.stop()
    # Encerra o servidor Flask se rodando junto
    try:
        urllib.request.urlopen(f"{API}/shutdown", timeout=1)
    except Exception:
        pass
    os._exit(0)


def criar_menu():
    return Menu(
        MenuItem("Abrir Dashboard",    abrir_dashboard, default=True),
        MenuItem("Ver Detecções",      abrir_deteccoes),
        Menu.SEPARATOR,
        MenuItem("Status da Rede",     mostrar_status),
        Menu.SEPARATOR,
        MenuItem("Sair",               sair),
    )


# ── Entry point do tray ───────────────────────────────────────────

def iniciar_tray():
    if not TRAY_OK:
        print("[tray] pystray não instalado — rodando sem ícone")
        print("[tray] instale com: pip install pystray pillow")
        # Abre dashboard direto
        time.sleep(2)
        webbrowser.open("http://localhost:5000")
        return

    icone_img = criar_icone("#5a7a9a")  # cinza enquanto conecta
    icon = pystray.Icon(
        name="netguard",
        icon=icone_img,
        title="NetGuard IDS — Conectando...",
        menu=criar_menu(),
    )
    state["icon_ref"] = icon

    # Polling em background
    threading.Thread(target=loop_polling, daemon=True).start()

    # Abre dashboard automaticamente na primeira vez
    threading.Timer(2.0, lambda: webbrowser.open("http://localhost:5000")).start()

    # Notificação de inicialização
    threading.Timer(3.0, lambda: notificar(
        "NetGuard IDS iniciado",
        "Monitorando sua rede. Clique no ícone para abrir o dashboard."
    )).start()

    icon.run()
