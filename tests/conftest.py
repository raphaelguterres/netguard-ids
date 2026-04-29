"""
NetGuard Test Suite — conftest.py
Configurações e fixtures compartilhadas.
"""
import sys, os

# Garante que o root do projeto está no path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Some tests import app.py before the bootstrap contract module has a
# chance to set this env var. Keep the modular /api/events test key stable
# regardless of pytest collection/import order.
os.environ.setdefault("NETGUARD_AGENT_KEYS", "nga_bootstrap_test_key")
