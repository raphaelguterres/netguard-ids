"""
NetGuard IDS v3.0 — Launcher Principal
Janela nativa via pywebview.
"""

import sys, os, threading, time, subprocess, pathlib, argparse

# Fix Windows DPI scaling so pywebview renders at correct size
if sys.platform == 'win32':
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # Per-monitor DPI aware
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

BASE = pathlib.Path(__file__).parent.resolve()
sys.path.insert(0, str(BASE))

def parse_args():
    p = argparse.ArgumentParser(prog="NetGuard IDS")
    p.add_argument("--port",     type=int, default=5000)
    p.add_argument("--no-tray",  action="store_true")
    p.add_argument("--install",  action="store_true")
    p.add_argument("--uninstall",action="store_true")
    return p.parse_args()

def instalar_autostart():
    exe    = sys.executable
    script = str(BASE / "netguard.py")
    cmd = ["schtasks","/create","/tn","NetGuard_IDS",
           "/tr", f'"{exe}" "{script}"',
           "/sc","ONLOGON","/rl","HIGHEST","/f"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    print("✓ Registrado" if r.returncode==0 else f"✗ Erro: {r.stderr.strip()}")

def desinstalar_autostart():
    r = subprocess.run(["schtasks","/delete","/tn","NetGuard_IDS","/f"],
                       capture_output=True, text=True)
    print("✓ Removido" if r.returncode==0 else "✗ Não encontrado")

def iniciar_servidor(port):
    import app
    app.app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)

def aguardar_servidor(port, timeout=20):
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1)
            return True
        except:
            time.sleep(0.3)
    return False

def abrir_janela(port):
    try:
        import webview

        window = webview.create_window(
            title            = "NetGuard IDS v3.0",
            url              = f"http://127.0.0.1:{port}",
            width            = 1440,
            height           = 900,
            min_size         = (1280, 720),
            resizable        = True,
            on_top           = False,
            background_color = "#060e1a",
            text_select      = True,
        )

        webview.start(
            debug            = False,
            http_server      = False,
            gui              = 'edgechromium',
        )

    except ImportError:
        print("  pywebview não instalado. Execute: pip install pywebview")
        print("  Abrindo no browser padrão...")
        import webbrowser
        webbrowser.open(f"http://127.0.0.1:{port}")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            pass

def iniciar_tray(port):
    try:
        import pystray
        from pystray import MenuItem, Menu
        from PIL import Image, ImageDraw
        import urllib.request, json

        def criar_icone(cor="#00c97a"):
            img = Image.new("RGBA", (64,64), (0,0,0,0))
            d   = ImageDraw.Draw(img)
            pts = [(8,4),(56,4),(56,36),(32,60),(8,36)]
            d.polygon(pts, fill="#0d1628")
            d.polygon(pts, outline=cor, width=4)
            return img

        _notificados = set()

        def sair(icon, item):
            icon.stop()
            os._exit(0)

        def poll():
            while True:
                try:
                    r  = urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/api/statistics", timeout=2)
                    s  = json.loads(r.read())
                    cr = s.get("by_severity",{}).get("critical",0)
                    hi = s.get("by_severity",{}).get("high",0)
                    cor = "#f03e3e" if cr>0 else "#ff8c42" if hi>0 else "#00c97a"
                    icon.icon  = criar_icone(cor)
                    icon.title = (
                        f"NetGuard — ⚠ {cr} CRÍTICO(S)" if cr>0 else
                        f"NetGuard — {hi} alto(s)"       if hi>0 else
                        "NetGuard IDS — Rede segura"
                    )
                except:
                    pass
                time.sleep(15)

        icon = pystray.Icon(
            "netguard", criar_icone("#5a7a9a"), "NetGuard IDS",
            menu=Menu(
                Menu.SEPARATOR,
                MenuItem("Sair", sair),
            )
        )
        threading.Thread(target=poll, daemon=True).start()
        icon.run()
    except ImportError:
        print("  [tray] pystray não disponível")

BANNER = """
  ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
  IDS v3.0  |  Janela Nativa  |  Sem Navegador
"""

def main():
    args = parse_args()
    if args.install:   instalar_autostart(); return
    if args.uninstall: desinstalar_autostart(); return

    print(BANNER)
    print(f"  Iniciando servidor em 127.0.0.1:{args.port}...")

    threading.Thread(
        target=iniciar_servidor, args=(args.port,),
        daemon=True, name="netguard-server"
    ).start()

    print("  Aguardando servidor...", end="", flush=True)
    if aguardar_servidor(args.port):
        print(" pronto!")
    else:
        print(" timeout!")
        return

    if not args.no_tray:
        threading.Thread(
            target=iniciar_tray, args=(args.port,),
            daemon=True, name="netguard-tray"
        ).start()

    print("  Abrindo janela...")
    abrir_janela(args.port)
    print("  NetGuard encerrado.")

if __name__ == "__main__":
    main()
