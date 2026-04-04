"""
build.py — Gera NetGuard.exe
Empacota todos os módulos em um único executável.

Como usar:
  python build.py

Saída:
  dist/NetGuard.exe
"""

import subprocess
import sys
import pathlib
import os
import shutil

BASE = pathlib.Path(__file__).parent.resolve()
DIST = BASE / "dist"
BUILD = BASE / "build"


def verificar_deps():
    deps = [
        ("PyInstaller", "pyinstaller"),
        ("pystray",     "pystray"),
        ("PIL",         "pillow"),
        ("plyer",       "plyer"),
        ("flask",       "flask"),
        ("flask_cors",  "flask-cors"),
        ("webview",     "pywebview"),
        ("scapy",       "scapy"),
    ]
    faltando = []
    for mod, pkg in deps:
        try:
            __import__(mod)
        except ImportError:
            faltando.append(pkg)
    if faltando:
        print(f"Instale as dependências faltando:")
        print(f"  pip install {' '.join(faltando)}")
        return False
    return True


def gerar_icone():
    try:
        from PIL import Image, ImageDraw
        tam = 64
        img = Image.new("RGBA", (tam, tam), (0, 0, 0, 0))
        d   = ImageDraw.Draw(img)
        pts = [(8,4),(56,4),(56,36),(32,60),(8,36)]
        d.polygon(pts, fill="#0d1628")
        d.polygon(pts, outline="#00d4ff", width=4)
        ico_path = BASE / "netguard.ico"
        img.save(str(ico_path), format="ICO")
        print(f"  ✓ Ícone gerado")
        return str(ico_path)
    except Exception as e:
        print(f"  ⚠ Ícone não gerado ({e})")
        return None


def criar_atalho(exe_path):
    try:
        desktop = pathlib.Path.home() / "Desktop"
        if not desktop.exists():
            desktop = pathlib.Path.home() / "OneDrive" / "Área de Trabalho"
        if not desktop.exists():
            desktop = pathlib.Path.home() / "OneDrive" / "Desktop"

        atalho = desktop / "NetGuard IDS.lnk"
        script = f"""
        $ws = New-Object -ComObject WScript.Shell
        $s  = $ws.CreateShortcut('{atalho}')
        $s.TargetPath   = '{exe_path}'
        $s.IconLocation = '{exe_path}'
        $s.Description  = 'NetGuard IDS - Sistema de Deteccao de Intrusao'
        $s.Save()
        """
        result = subprocess.run(
            ["powershell", "-Command", script],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print(f"  ✓ Atalho criado: {atalho}")
        else:
            # Fallback — cria na pasta do projeto
            print(f"  ⚠ Atalho não criado no Desktop — copie manualmente o NetGuard.exe")
    except Exception as e:
        print(f"  ⚠ Atalho: {e}")


def build():
    print("""
  ╔══════════════════════════════════════════════╗
  ║  NetGuard IDS v3.0 — Build Final            ║
  ╚══════════════════════════════════════════════╝
    """)

    print("Verificando dependências...")
    if not verificar_deps():
        sys.exit(1)
    print("  ✓ Dependências OK\n")

    print("Gerando ícone...")
    ico = gerar_icone()
    print()

    # Todos os arquivos de dados a incluir no exe
    DATAS = [
        ("dashboard.html",     "."),
        ("ids_engine.py",      "."),
        ("app.py",             "."),
        ("tray.py",            "."),
        ("packet_capture.py",  "."),
        ("threat_intel.py",    "."),
    ]

    # Hidden imports necessários
    HIDDEN = [
        # pystray
        "pystray._win32",
        # plyer
        "plyer.platforms.win.notification",
        # webview
        "webview",
        "webview.platforms.winforms",
        "clr",
        # flask
        "flask",
        "flask_cors",
        "flask.templating",
        "jinja2",
        # scapy
        "scapy",
        "scapy.all",
        "scapy.layers.inet",
        "scapy.layers.dns",
        "scapy.layers.l2",
        # outros
        "sqlite3",
        "PIL",
        "PIL.Image",
        "PIL.ImageDraw",
        "ipaddress",
        "collections",
        "threading",
        "subprocess",
    ]

    # Monta comando PyInstaller
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--noconsole",
        "--name", "NetGuard",
        "--distpath", str(DIST),
        "--workpath", str(BUILD),
        "--specpath", str(BASE),
        "--clean",
    ]

    if ico:
        cmd += ["--icon", ico]

    for src, dst in DATAS:
        src_path = BASE / src
        if src_path.exists():
            cmd += ["--add-data", f"{src_path}{os.pathsep}{dst}"]
        else:
            print(f"  ⚠ {src} não encontrado — pulando")

    for h in HIDDEN:
        cmd += ["--hidden-import", h]

    # Script principal
    cmd.append(str(BASE / "netguard.py"))

    print("Iniciando PyInstaller...")
    print(f"  Arquivos incluídos: {len(DATAS)}")
    print(f"  Hidden imports: {len(HIDDEN)}\n")

    result = subprocess.run(cmd, cwd=str(BASE))

    print()
    if result.returncode == 0:
        exe = DIST / "NetGuard.exe"
        tam = exe.stat().st_size / 1024 / 1024 if exe.exists() else 0
        print(f"  ✓ Build concluído!")
        print(f"  Arquivo : {exe}")
        print(f"  Tamanho : {tam:.1f} MB")
        print()
        criar_atalho(str(exe))
        print(f"""
  Como usar:
    Duplo clique em dist\\NetGuard.exe

  Para iniciar com o Windows (como Administrador):
    dist\\NetGuard.exe --install

  Para remover do autostart:
    dist\\NetGuard.exe --uninstall
        """)
    else:
        print("  ✗ Build falhou — verifique os erros acima")
        sys.exit(1)


if __name__ == "__main__":
    build()
