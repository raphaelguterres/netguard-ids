"""
NetGuard IDS — ML Anomaly Detection (Isolation Forest)
Detecta anomalias comportamentais usando machine learning real.

Diferente do ml_baseline.py (z-score estatístico), este módulo usa
Isolation Forest do scikit-learn para detectar comportamentos que
regras convencionais não capturam.

Features analisadas por janela de 1 hora:
  - event_count          : total de eventos
  - critical_count       : eventos CRITICAL
  - high_count           : eventos HIGH
  - unique_ips           : IPs únicos
  - unique_hosts         : hosts ativos
  - process_alerts       : alertas de processo
  - network_alerts       : alertas de rede
  - correlation_alerts   : correlações disparadas
  - avg_severity_score   : score médio (LOW=1, MED=2, HIGH=3, CRIT=4)

Uso:
    from engine.ml_anomaly import MLAnomalyEngine
    engine = MLAnomalyEngine(repo, tenant_id="abc")
    engine.train()
    anomalies = engine.detect_current()
"""

from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("ids.ml_anomaly")

# Severidade → score numérico
_SEV_SCORE = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Threshold de anomalia (quanto menor, mais anômalo)
# Isolation Forest retorna scores entre -1 e 0 (anomalias < -0.1)
ANOMALY_THRESHOLD = float("-0.15")

# Mínimo de janelas para treinar o modelo
MIN_TRAIN_WINDOWS = 24  # 24 horas mínimo


def _try_import():
    """Importa scikit-learn com fallback gracioso."""
    try:
        from sklearn.ensemble import IsolationForest
        import numpy as np
        return IsolationForest, np
    except ImportError:
        return None, None


class HourlyWindow:
    """Feature vector para uma janela de 1 hora."""

    def __init__(self, hour_key: str):
        self.hour_key         = hour_key  # "2026-03-15T14"
        self.event_count      = 0
        self.critical_count   = 0
        self.high_count       = 0
        self.medium_count     = 0
        self.low_count        = 0
        self.unique_ips:  set = set()
        self.unique_hosts: set = set()
        self.process_alerts   = 0
        self.network_alerts   = 0
        self.correlation_alerts = 0
        self.severity_scores: list = []

    def add_event(self, event: dict) -> None:
        self.event_count += 1
        sev = (event.get("severity") or "LOW").upper()
        score = _SEV_SCORE.get(sev, 1)
        self.severity_scores.append(score)

        if sev == "CRITICAL":
            self.critical_count += 1
        elif sev == "HIGH":
            self.high_count += 1
        elif sev == "MEDIUM":
            self.medium_count += 1
        else:
            self.low_count += 1

        src = event.get("source", "")
        if isinstance(src, str):
            self.unique_ips.add(src)
        host = event.get("host_id", "")
        if host:
            self.unique_hosts.add(host)

        etype = (event.get("event_type") or "").lower()
        if "process" in etype:
            self.process_alerts += 1
        elif any(x in etype for x in ("network", "connection", "port", "scan")):
            self.network_alerts += 1
        elif "correlation" in etype or "cor" in (event.get("rule_id") or "").lower():
            self.correlation_alerts += 1

    def to_vector(self) -> list[float]:
        avg_sev = (sum(self.severity_scores) / len(self.severity_scores)
                   if self.severity_scores else 0.0)
        return [
            float(self.event_count),
            float(self.critical_count),
            float(self.high_count),
            float(self.medium_count),
            float(len(self.unique_ips)),
            float(len(self.unique_hosts)),
            float(self.process_alerts),
            float(self.network_alerts),
            float(self.correlation_alerts),
            avg_sev,
        ]


class MLAnomalyEngine:
    """
    Motor de detecção de anomalias com Isolation Forest.

    O modelo treina com janelas históricas de 1 hora e detecta
    comportamentos que se desviam do padrão aprendido.
    """

    FEATURE_NAMES = [
        "event_count", "critical_count", "high_count", "medium_count",
        "unique_ips", "unique_hosts", "process_alerts",
        "network_alerts", "correlation_alerts", "avg_severity_score",
    ]

    def __init__(self, repo=None, tenant_id: str = "default",
                 contamination: float = 0.05):
        self.repo         = repo
        self.tenant_id    = tenant_id
        self.contamination = contamination  # % esperado de anomalias

        self._model       = None
        self._np          = None
        self._IsoForest   = None
        self._trained     = False
        self._train_size  = 0
        self._trained_at  = None
        self._lock        = threading.Lock()

        # Janelas históricas em memória
        self._windows: dict[str, HourlyWindow] = {}

        # Anomalias detectadas recentes
        self._anomalies: list[dict] = []

        IsoForest, np = _try_import()
        if IsoForest is None:
            logger.warning(
                "scikit-learn não instalado. "
                "Instale com: pip install scikit-learn "
                "O ML Anomaly Engine ficará em modo degradado."
            )
        else:
            self._IsoForest = IsoForest
            self._np        = np
            logger.info("ML Anomaly Engine inicializado (Isolation Forest)")

    @property
    def available(self) -> bool:
        return self._IsoForest is not None

    # ── Feed de eventos ───────────────────────────────────────────────────────

    def feed(self, event: dict) -> Optional[dict]:
        """
        Ingere um evento. Retorna anomalia detectada ou None.
        Chamado em tempo real a cada evento persistido.
        """
        if not self.available:
            return None

        ts = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            dt = datetime.now(timezone.utc)

        hour_key = dt.strftime("%Y-%m-%dT%H")
        window = self._windows.setdefault(hour_key, HourlyWindow(hour_key))
        window.add_event(event)

        # Detecta anomalia na janela atual se modelo treinado
        if self._trained:
            return self._score_window(window, hour_key)
        return None

    # ── Treino ────────────────────────────────────────────────────────────────

    def train(self, days_back: int = 30) -> dict:
        """
        Treina o modelo com dados históricos do banco.
        Retorna {"trained": bool, "windows": int, "message": str}
        """
        if not self.available:
            return {"trained": False, "windows": 0,
                    "message": "scikit-learn não disponível"}

        vectors, labels = self._load_historical_vectors(days_back)

        if len(vectors) < MIN_TRAIN_WINDOWS:
            return {
                "trained": False,
                "windows": len(vectors),
                "message": f"Dados insuficientes ({len(vectors)} janelas, "
                           f"mínimo {MIN_TRAIN_WINDOWS}). "
                           f"Aguarde mais {MIN_TRAIN_WINDOWS - len(vectors)} horas."
            }

        X = self._np.array(vectors)

        with self._lock:
            model = self._IsoForest(
                n_estimators=200,
                contamination=self.contamination,
                max_samples="auto",
                random_state=42,
                n_jobs=-1,
            )
            model.fit(X)
            self._model      = model
            self._trained    = True
            self._train_size = len(vectors)
            self._trained_at = datetime.now(timezone.utc).isoformat()

        logger.info(
            "Modelo treinado com %d janelas horárias (%d dias)",
            len(vectors), days_back
        )
        return {
            "trained":    True,
            "windows":    len(vectors),
            "days_back":  days_back,
            "trained_at": self._trained_at,
            "message":    f"Modelo treinado com {len(vectors)} janelas horárias.",
        }

    def _load_historical_vectors(self, days_back: int) -> tuple[list, list]:
        """Carrega eventos do banco e agrupa por hora."""
        if not self.repo:
            return self._windows_to_vectors(), []

        since = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat()

        try:
            events = self.repo.query(
                tenant_id=self.tenant_id,
                since=since,
                limit=50000,
            )
        except Exception as e:
            logger.warning("Falha ao carregar histórico: %s", e)
            return self._windows_to_vectors(), []

        # Agrupa por hora
        hourly: dict[str, HourlyWindow] = {}
        for ev in events:
            ts = (ev.get("timestamp") or "") if isinstance(ev, dict) else ""
            if not ts:
                continue
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                continue
            hour_key = dt.strftime("%Y-%m-%dT%H")
            win = hourly.setdefault(hour_key, HourlyWindow(hour_key))
            win.add_event(ev if isinstance(ev, dict) else ev.__dict__)

        # Mescla com janelas em memória
        for k, w in self._windows.items():
            if k not in hourly:
                hourly[k] = w

        vectors = [w.to_vector() for w in sorted(hourly.values(),
                                                   key=lambda x: x.hour_key)]
        return vectors, list(hourly.keys())

    def _windows_to_vectors(self) -> list:
        return [w.to_vector() for w in sorted(self._windows.values(),
                                               key=lambda x: x.hour_key)]

    # ── Detecção ──────────────────────────────────────────────────────────────

    def _score_window(self, window: HourlyWindow,
                      hour_key: str) -> Optional[dict]:
        """Pontua uma janela. Retorna anomalia se score < threshold."""
        if not self._trained or not self._model:
            return None
        try:
            X = self._np.array([window.to_vector()])
            score = float(self._model.score_samples(X)[0])
            if score < ANOMALY_THRESHOLD:
                return self._build_anomaly(window, hour_key, score)
        except Exception as e:
            logger.debug("Score failed: %s", e)
        return None

    def _build_anomaly(self, window: HourlyWindow,
                       hour_key: str, score: float) -> dict:
        severity = "HIGH" if score < -0.25 else "MEDIUM"
        vector   = window.to_vector()
        factors  = self._explain(vector)

        anomaly = {
            "anomaly_id":   f"ANO-{hour_key.replace(':', '').replace('-', '')}",
            "hour":         hour_key,
            "score":        round(score, 4),
            "severity":     severity,
            "event_count":  window.event_count,
            "factors":      factors,
            "detected_at":  datetime.now(timezone.utc).isoformat(),
            "vector":       {n: v for n, v in zip(self.FEATURE_NAMES, vector)},
        }

        # Evita duplicatas
        existing_ids = {a["anomaly_id"] for a in self._anomalies}
        if anomaly["anomaly_id"] not in existing_ids:
            self._anomalies.append(anomaly)
            if len(self._anomalies) > 200:
                self._anomalies = self._anomalies[-200:]
            logger.warning(
                "Anomalia ML detectada [%s] score=%.3f %s",
                hour_key, score, factors[:2]
            )

        return anomaly

    def _explain(self, vector: list[float]) -> list[str]:
        """Gera explicações humanas para os fatores da anomalia."""
        factors = []
        names   = self.FEATURE_NAMES
        for name, val in zip(names, vector):
            if name == "event_count" and val > 100:
                factors.append(f"Volume anômalo de eventos ({int(val)})")
            elif name == "critical_count" and val > 5:
                factors.append(f"{int(val)} eventos CRITICAL na hora")
            elif name == "high_count" and val > 15:
                factors.append(f"{int(val)} eventos HIGH na hora")
            elif name == "unique_ips" and val > 30:
                factors.append(f"{int(val)} IPs únicos ativos (possível scan)")
            elif name == "correlation_alerts" and val > 3:
                factors.append(f"{int(val)} correlações disparadas")
            elif name == "avg_severity_score" and val > 2.5:
                factors.append(f"Severidade média elevada ({val:.1f}/4.0)")
        return factors or ["Padrão comportamental incomum detectado"]

    def detect_current(self) -> list[dict]:
        """Detecta anomalias em todas as janelas do dia atual."""
        results = []
        if not self._trained:
            return results
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        for key, window in self._windows.items():
            if not key.startswith(today):
                continue
            anomaly = self._score_window(window, key)
            if anomaly:
                results.append(anomaly)
        return results

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> dict:
        return {
            "available":     self.available,
            "trained":       self._trained,
            "train_size":    self._train_size,
            "trained_at":    self._trained_at,
            "anomaly_threshold": ANOMALY_THRESHOLD,
            "contamination": self.contamination,
            "live_windows":  len(self._windows),
            "anomalies_detected": len(self._anomalies),
        }

    def get_anomalies(self, limit: int = 50) -> list[dict]:
        return sorted(self._anomalies, key=lambda x: x["score"])[:limit]

    def reset(self) -> None:
        with self._lock:
            self._model    = None
            self._trained  = False
            self._train_size = 0
            self._trained_at = None
        self._windows   = {}
        self._anomalies = []
        logger.info("ML Anomaly Engine resetado")
