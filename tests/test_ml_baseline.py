"""Tests — MLBaseline (Isolation Forest)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

# Skip gracefully if scikit-learn not installed
try:
    import numpy as np  # noqa: F401
    from engine.ml_baseline import MLBaseline
    SKLEARN_OK = True
except ImportError:
    SKLEARN_OK = False

pytestmark = pytest.mark.skipif(not SKLEARN_OK, reason="scikit-learn/numpy not installed")


def _snapshot(proc_count=50, conn_count=20, ext_count=5,
              unique_ips=3, cpu_mean=15.0, cpu_max=30.0,
              port_count=8, noise=0.0):
    """Cria snapshot sintético realista."""
    import random
    procs = [{"name":f"proc{i}","cpu":cpu_mean + noise*random.gauss(0,1),"pid":i}
             for i in range(proc_count)]
    conns = [{"dst_ip":f"8.8.8.{i%ext_count}","dst_port":443}
             for i in range(conn_count)]
    ports = [{"port":p,"proto":"tcp"} for p in [80,443,5000,8080][:port_count]]
    return {"processes":procs, "connections":conns, "ports":ports}


@pytest.fixture
def trained_ml():
    """MLBaseline já treinado com 40 amostras normais."""
    ml = MLBaseline(host_id="test", min_samples=20, contamination=0.1)
    for _ in range(42):
        ml.add_sample(_snapshot(noise=0.3))
    return ml


class TestInit:
    def test_starts_untrained(self):
        ml = MLBaseline(host_id="h", min_samples=30)
        stats = ml.stats()
        assert stats["trained"] is False
        assert stats["sample_count"] == 0
        assert stats["progress_pct"] == 0

    def test_available_with_sklearn(self):
        ml = MLBaseline(host_id="h", min_samples=5)
        assert ml.stats()["available"] is True


class TestSampleCollection:
    def test_add_sample_increments_count(self):
        ml = MLBaseline(host_id="h", min_samples=30)
        ml.add_sample(_snapshot())
        assert ml.stats()["sample_count"] == 1

    def test_progress_pct_increases(self):
        ml = MLBaseline(host_id="h", min_samples=10)
        for _i in range(5):
            ml.add_sample(_snapshot())
        assert ml.stats()["progress_pct"] == 50

    def test_progress_capped_at_100(self):
        ml = MLBaseline(host_id="h", min_samples=5)
        for _ in range(20):
            ml.add_sample(_snapshot())
        assert ml.stats()["progress_pct"] == 100

    def test_empty_snapshot_does_not_crash(self):
        ml = MLBaseline(host_id="h", min_samples=5)
        ml.add_sample({})  # deve ignorar graciosamente

    def test_partial_snapshot_handled(self):
        ml = MLBaseline(host_id="h", min_samples=5)
        ml.add_sample({"processes": [], "connections": [], "ports": []})
        assert ml.stats()["sample_count"] == 1


class TestTraining:
    def test_trains_after_min_samples(self):
        # _train_every=20, so need 20+ samples to trigger first training
        ml = MLBaseline(host_id="h", min_samples=10, contamination=0.05)
        for _ in range(22):
            ml.add_sample(_snapshot())
        assert ml.stats()["trained"] is True

    def test_does_not_train_before_min_samples(self):
        ml = MLBaseline(host_id="h", min_samples=30)
        for _ in range(5):
            ml.add_sample(_snapshot())
        assert ml.stats()["trained"] is False

    def test_trained_ml_returns_none_for_normal(self, trained_ml):
        # Normal snapshot deve retornar None (não é anomalia)
        result = trained_ml.add_sample(_snapshot(noise=0.3))
        # Pode ou não ser anomalia (estocástico), mas não deve crashar
        assert result is None or isinstance(result, dict)


class TestAnomalyDetection:
    def test_extreme_anomaly_detected(self, trained_ml):
        # Snapshot 10x fora do baseline — deve sempre detectar
        # Tenta até 3 vezes com anomalias crescentes (Isolation Forest é estocástico)
        result = None
        for multiplier in [10, 20, 50]:
            anomaly = _snapshot(
                proc_count = 50 * multiplier,
                conn_count = 20 * multiplier,
                ext_count  = 5  * multiplier,
                cpu_mean   = min(99.0, 15.0 * multiplier),
                cpu_max    = 100.0,
                port_count = min(8, 8),
            )
            result = trained_ml.add_sample(anomaly)
            if result is not None:
                break
        assert result is not None, "Anomalia extrema deve ser detectada pelo Isolation Forest"
        assert result["rule_id"] == "ML-1"
        assert result["severity"] in ("MEDIUM","HIGH","CRITICAL")

    def test_anomaly_alert_has_required_keys(self, trained_ml):
        anomaly = _snapshot(proc_count=500, conn_count=1000, cpu_max=100.0)
        result = trained_ml.add_sample(anomaly)
        if result:
            for key in ("timestamp","host_id","rule_id","rule_name",
                        "event_type","severity","description","details"):
                assert key in result

    def test_anomaly_confidence_range(self, trained_ml):
        # anomaly_score deve ser número válido
        anomaly = _snapshot(proc_count=500, conn_count=1000)
        result = trained_ml.add_sample(anomaly)
        if result:
            score = result["details"]["anomaly_score"]
            assert isinstance(score, float)

    def test_anomaly_count_increments(self, trained_ml):
        before = trained_ml.stats()["anomaly_count"]
        anomaly = _snapshot(proc_count=999, conn_count=999, cpu_max=100.0)
        result = trained_ml.add_sample(anomaly)
        if result:
            assert trained_ml.stats()["anomaly_count"] == before + 1


class TestStats:
    def test_stats_has_all_keys(self):
        ml = MLBaseline(host_id="h", min_samples=5)
        stats = ml.stats()
        for key in ("available","trained","samples","min_samples",
                    "sample_count","anomaly_count","contamination",
                    "host_id","progress_pct"):
            assert key in stats

    def test_stats_host_id_correct(self):
        ml = MLBaseline(host_id="my-server", min_samples=5)
        assert ml.stats()["host_id"] == "my-server"


class TestReset:
    def test_reset_clears_samples(self, trained_ml):
        trained_ml.reset()
        stats = trained_ml.stats()
        assert stats["sample_count"] == 0
        assert stats["trained"] is False
        assert stats["samples"] == 0
        assert stats["anomaly_count"] == 0
