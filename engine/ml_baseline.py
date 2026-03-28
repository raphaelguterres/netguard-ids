"""
NetGuard — ML Baseline Engine
Detecta anomalias de comportamento usando Isolation Forest (scikit-learn).

Conceito: aprende o padrão normal do sistema nas primeiras N amostras,
depois detecta desvios automaticamente sem precisar de thresholds fixos.

Equivalente ao que Elastic SIEM chama de "ML Jobs" e Darktrace de "AI baseline".
"""

import logging
import threading
import numpy as np
from datetime import datetime, timezone
from collections import deque
from typing import Optional

logger = logging.getLogger("netguard.ml")

# Tenta importar scikit-learn — graceful degradation se não instalado
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn não instalado — ML baseline desativado. "
                   "Instale com: pip install scikit-learn")


class MLBaseline:
    """
    Motor de detecção de anomalias baseado em Isolation Forest.

    Features monitoradas por amostra:
      - process_count     número de processos ativos
      - conn_count        número de conexões ativas
      - ext_conn_count    conexões para IPs externos
      - unique_ext_ips    IPs externos únicos
      - cpu_mean          média de CPU dos processos
      - cpu_max           CPU máxima de qualquer processo
      - port_count        número de portas em LISTEN
      - new_proc_rate     taxa de novos processos (últimas 2 amostras)

    Parâmetros:
      min_samples    amostras mínimas antes de começar a detectar (default: 50)
      contamination  fração esperada de anomalias (default: 0.05 = 5%)
      window_size    tamanho da janela de histórico (default: 500)
    """

    def __init__(self, host_id: str = "netguard-host",
                 min_samples: int = 50,
                 contamination: float = 0.05,
                 window_size: int = 500):
        self.host_id        = host_id
        self.min_samples    = min_samples
        self.contamination  = contamination
        self._lock          = threading.RLock()
        self._available     = SKLEARN_AVAILABLE

        # Histórico de amostras
        self._samples: deque = deque(maxlen=window_size)
        self._model: Optional[object] = None
        self._scaler: Optional[object] = None
        self._trained       = False
        self._last_trained  = 0.0
        self._train_every   = 20   # re-treina a cada N novas amostras
        self._sample_count  = 0
        self._anomaly_count = 0
        self._prev_proc_count = 0

        if self._available:
            logger.info("MLBaseline iniciado | host=%s | min_samples=%d",
                        host_id, min_samples)
        else:
            logger.warning("MLBaseline: scikit-learn ausente — modo passivo")

    def add_sample(self, snapshot: dict) -> Optional[dict]:
        """
        Adiciona snapshot do sistema e retorna alerta se anomalia detectada.

        snapshot deve ter:
          processes: list de dicts com 'cpu' key
          connections: list de dicts com 'dst_ip' key
          ports: list de dicts
        """
        if not self._available:
            return None

        features = self._extract_features(snapshot)
        if features is None:
            return None

        with self._lock:
            self._samples.append(features)
            self._sample_count += 1

            # Treina modelo quando tem amostras suficientes
            if (len(self._samples) >= self.min_samples and
                    self._sample_count % self._train_every == 0):
                self._train()

            # Detecta anomalia se modelo treinado
            if self._trained:
                return self._detect(features, snapshot)

        return None

    def _extract_features(self, snapshot: dict) -> Optional[np.ndarray]:
        """Extrai vetor de features numéricas do snapshot."""
        try:
            procs   = snapshot.get("processes", [])
            conns   = snapshot.get("connections", [])
            ports   = snapshot.get("ports", [])

            process_count   = len(procs)
            conn_count      = len(conns)

            # Conexões externas
            private_prefixes = ("192.168.", "10.", "172.", "127.", "0.")
            ext_conns = [c for c in conns
                         if c.get("dst_ip","") and
                         not any(c["dst_ip"].startswith(p) for p in private_prefixes)]
            ext_conn_count  = len(ext_conns)
            unique_ext_ips  = len({c.get("dst_ip","") for c in ext_conns})

            # CPU stats
            cpu_vals = [float(p.get("cpu") or p.get("cpu_usage") or 0)
                        for p in procs if p.get("cpu") or p.get("cpu_usage")]
            cpu_mean = float(np.mean(cpu_vals)) if cpu_vals else 0.0
            cpu_max  = float(np.max(cpu_vals))  if cpu_vals else 0.0

            port_count = len(ports)

            # Taxa de mudança de processos
            new_proc_rate = abs(process_count - self._prev_proc_count)
            self._prev_proc_count = process_count

            return np.array([
                process_count, conn_count, ext_conn_count, unique_ext_ips,
                cpu_mean, cpu_max, port_count, new_proc_rate
            ], dtype=float)

        except Exception as e:
            logger.debug("MLBaseline feature extraction error: %s", e)
            return None

    def _train(self):
        """Treina o modelo Isolation Forest com as amostras acumuladas."""
        try:
            X = np.array(list(self._samples))
            if len(X) < self.min_samples:
                return

            self._scaler = StandardScaler()
            X_scaled = self._scaler.fit_transform(X)

            self._model = IsolationForest(
                contamination = self.contamination,
                n_estimators  = 100,
                random_state  = 42,
                n_jobs        = -1,
            )
            self._model.fit(X_scaled)
            self._trained = True
            logger.info("MLBaseline modelo treinado | amostras=%d | host=%s",
                        len(X), self.host_id)
        except Exception as e:
            logger.error("MLBaseline training error: %s", e)

    def _detect(self, features: np.ndarray, snapshot: dict) -> Optional[dict]:
        """Roda detecção de anomalia na amostra atual."""
        try:
            X = features.reshape(1, -1)
            X_scaled = self._scaler.transform(X)

            prediction = self._model.predict(X_scaled)[0]  # 1=normal, -1=anomalia
            score      = self._model.decision_function(X_scaled)[0]
            # score negativo e baixo = mais anômalo

            if prediction == -1:
                self._anomaly_count += 1
                severity  = "CRITICAL" if score < -0.3 else "HIGH" if score < -0.1 else "MEDIUM"

                # Identifica quais features são mais anômalas
                feature_names = [
                    "process_count", "conn_count", "ext_conn_count",
                    "unique_ext_ips", "cpu_mean", "cpu_max",
                    "port_count", "new_proc_rate"
                ]
                # Compara com média histórica
                X_hist  = np.array(list(self._samples))
                means   = X_hist.mean(axis=0)
                stds    = X_hist.std(axis=0) + 1e-9
                z_scores = np.abs((features - means) / stds)
                top_idx  = np.argsort(z_scores)[-3:][::-1]
                anomalous_features = {
                    feature_names[i]: {
                        "current": round(float(features[i]), 2),
                        "mean":    round(float(means[i]), 2),
                        "z_score": round(float(z_scores[i]), 2),
                    }
                    for i in top_idx if z_scores[i] > 1.5
                }

                return {
                    "timestamp":    datetime.now(timezone.utc).isoformat(),
                    "host_id":      self.host_id,
                    "rule_id":      "ML-1",
                    "rule_name":    "Anomalia de Comportamento — ML",
                    "event_type":   "ml_anomaly",
                    "severity":     severity,
                    "source":       "engine.ml_baseline",
                    "description":  (f"Isolation Forest detectou comportamento anômalo "
                                     f"(score={score:.3f}). "
                                     f"Features: {list(anomalous_features.keys())}"),
                    "details": {
                        "anomaly_score":      round(float(score), 4),
                        "anomalous_features": anomalous_features,
                        "processes":          len(snapshot.get("processes", [])),
                        "connections":        len(snapshot.get("connections", [])),
                        "ext_connections":    features[2],
                    },
                    "mitre": {"tactic": "discovery", "technique": "T1082"},
                    "tags": ["ml", "anomaly", "baseline", "isolation-forest"],
                    "type": "ML_ANOMALY",
                }
        except Exception as e:
            logger.debug("MLBaseline detection error: %s", e)
        return None

    def stats(self) -> dict:
        with self._lock:
            return {
                "available":      self._available,
                "trained":        self._trained,
                "samples":        len(self._samples),
                "min_samples":    self.min_samples,
                "sample_count":   self._sample_count,
                "anomaly_count":  self._anomaly_count,
                "contamination":  self.contamination,
                "host_id":        self.host_id,
                "progress_pct":   min(100, int(len(self._samples) / self.min_samples * 100)),
            }

    def reset(self):
        with self._lock:
            self._samples.clear()
            self._model   = None
            self._scaler  = None
            self._trained = False
            self._sample_count  = 0
            self._anomaly_count = 0
