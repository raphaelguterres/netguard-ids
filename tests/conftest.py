"""
NetGuard Test Suite — conftest.py
Configurações e fixtures compartilhadas.
"""
import sys, os

# Garante que o root do projeto está no path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
