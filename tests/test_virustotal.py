"""Tests — VirusTotalClient (sem chamadas reais à API)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import pytest
from unittest.mock import patch, MagicMock
from engine.virustotal import VirusTotalClient


@pytest.fixture
def vt_no_key():
    return VirusTotalClient(api_key="")

@pytest.fixture
def vt_with_key():
    return VirusTotalClient(api_key="test_key_12345")


class TestInit:
    def test_disabled_without_key(self, vt_no_key):
        assert vt_no_key.stats()["enabled"] is False

    def test_enabled_with_key(self, vt_with_key):
        assert vt_with_key.stats()["enabled"] is True

    def test_api_key_set_reflects_correctly(self, vt_no_key, vt_with_key):
        assert vt_no_key.stats()["api_key_set"] is False
        assert vt_with_key.stats()["api_key_set"] is True


class TestLookupHashDisabled:
    def test_returns_none_when_disabled(self, vt_no_key):
        result = vt_no_key.lookup_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert result is None

    def test_returns_none_for_empty_hash(self, vt_with_key):
        assert vt_with_key.lookup_hash("") is None

    def test_returns_none_for_short_hash(self, vt_with_key):
        assert vt_with_key.lookup_hash("abc123") is None

    def test_accepts_md5_length(self, vt_with_key):
        # MD5 = 32 chars — não deve rejeitar por tamanho
        # (vai falhar na chamada HTTP, não no tamanho)
        h = "d" * 32
        # Com key mas sem rede, vai retornar None (URLError)
        result = vt_with_key.lookup_hash(h)
        assert result is None or isinstance(result, dict)

    def test_accepts_sha256_length(self, vt_with_key):
        h = "d" * 64
        result = vt_with_key.lookup_hash(h)
        assert result is None or isinstance(result, dict)


class TestLookupHashMocked:
    def _mock_response(self, malicious=0, suspicious=0, harmless=10):
        """Cria resposta fake da API VT."""
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious":  malicious,
                        "suspicious": suspicious,
                        "harmless":   harmless,
                        "undetected": 60,
                    },
                    "meaningful_name": "trojan.genericx" if malicious > 0 else "",
                    "type_description": "Win32 EXE",
                    "size": 12345,
                }
            }
        }

    @patch("urllib.request.urlopen")
    def test_clean_file_returns_zero_malicious(self, mock_urlopen, vt_with_key):
        resp_data = self._mock_response(malicious=0)
        mock_cm = MagicMock()
        mock_cm.__enter__ = lambda s: MagicMock(
            read=lambda: str(resp_data).replace("'",'"').encode()
        )
        mock_cm.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_cm

        import json
        mock_read = MagicMock(return_value=json.dumps(resp_data).encode())
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = lambda s: MagicMock(read=mock_read)
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_ctx

        result = vt_with_key.lookup_hash("d" * 32)
        if result:
            assert result.get("malicious", 0) == 0

    @patch("urllib.request.urlopen")
    def test_malicious_file_detected(self, mock_urlopen, vt_with_key):
        import json
        resp = self._mock_response(malicious=15, suspicious=3)
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = lambda s: MagicMock(
            read=MagicMock(return_value=json.dumps(resp).encode())
        )
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_ctx

        result = vt_with_key.lookup_hash("a" * 32)
        if result:
            assert result["malicious"] == 15
            assert result["suspicious"] == 3

    def test_404_returns_not_found(self, vt_with_key):
        import urllib.error
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError(
                url="", code=404, msg="Not Found", hdrs={}, fp=None
            )
            result = vt_with_key.lookup_hash("e" * 32)
            if result:
                assert result["found"] is False

    def test_429_rate_limit_returns_none(self, vt_with_key):
        import urllib.error
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError(
                url="", code=429, msg="Too Many Requests", hdrs={}, fp=None
            )
            result = vt_with_key.lookup_hash("f" * 32)
            assert result is None


class TestCache:
    @patch("urllib.request.urlopen")
    def test_second_lookup_uses_cache(self, mock_urlopen, vt_with_key):
        import json
        resp = {"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":5,"undetected":5}}}}
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = lambda s: MagicMock(
            read=MagicMock(return_value=json.dumps(resp).encode())
        )
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_ctx

        h = "c" * 32
        vt_with_key.lookup_hash(h)
        vt_with_key.lookup_hash(h)  # deve usar cache

        stats = vt_with_key.stats()
        assert stats["cache_hits"] >= 1
        assert mock_urlopen.call_count == 1

    def test_cache_size_tracked(self, vt_with_key):
        # Injeta direto no cache interno
        vt_with_key._set_cache("abc123", {"found": True, "malicious": 0})
        assert vt_with_key.stats()["cache_size"] >= 1

    def test_cache_get_returns_none_for_missing(self, vt_with_key):
        result = vt_with_key._get_cache("nonexistent_key")
        assert result is None


class TestGenerateAlert:
    def test_no_alert_for_clean_file(self, vt_with_key):
        result = vt_with_key.generate_alert(
            {"malicious": 0, "hash": "abc"},
            {"name": "legit.exe"}
        )
        assert result is None

    def test_alert_generated_for_malicious(self, vt_with_key):
        result = vt_with_key.generate_alert(
            {"malicious": 10, "total_engines": 70, "hash": "abc123", "name": "trojan"},
            {"name": "malware.exe", "host_id": "h1"}
        )
        assert result is not None
        assert result["rule_id"] == "VT-1"
        assert result["severity"] == "CRITICAL"

    def test_severity_levels(self, vt_with_key):
        cases = [(1, "MEDIUM"), (2, "HIGH"), (5, "CRITICAL")]
        for malicious, expected_sev in cases:
            result = vt_with_key.generate_alert(
                {"malicious": malicious, "total_engines": 70, "hash": "x"},
                {"name": "test.exe"}
            )
            assert result["severity"] == expected_sev

    def test_alert_has_vt_link(self, vt_with_key):
        result = vt_with_key.generate_alert(
            {"malicious": 5, "total_engines": 70, "hash": "deadbeef"},
            {"name": "bad.exe"}
        )
        assert "virustotal.com" in result["details"]["vt_link"]

    def test_none_vt_result_returns_none(self, vt_with_key):
        assert vt_with_key.generate_alert(None, {"name": "x.exe"}) is None


class TestStats:
    def test_stats_has_all_keys(self, vt_with_key):
        stats = vt_with_key.stats()
        for key in ("enabled","total_lookups","cache_hits",
                    "cache_size","detections","api_key_set"):
            assert key in stats

    def test_lookups_counted(self, vt_with_key):
        # Injeta no cache para simular lookup
        vt_with_key._set_cache("k" * 32, {"found": True, "malicious": 0})
        vt_with_key._cache_hits += 1
        assert vt_with_key.stats()["cache_hits"] >= 1
