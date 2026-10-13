"""Tracing must never break the pipeline. enable_tracing returns a bool and
never raises, whether or not mlflow is installed, and is_enabled agrees with it.
"""
import importlib
import eval.tracing as tracing


def test_enable_tracing_returns_bool_and_never_raises(tmp_path):
    importlib.reload(tracing)
    result = tracing.enable_tracing("vulnfix-test", tracking_dir=str(tmp_path / "mlruns"))
    assert isinstance(result, bool)


def test_is_enabled_matches_result(tmp_path):
    importlib.reload(tracing)
    r = tracing.enable_tracing("vulnfix-test", tracking_dir=str(tmp_path / "mlruns2"))
    assert tracing.is_enabled() == r


def test_second_call_is_idempotent(tmp_path):
    importlib.reload(tracing)
    r1 = tracing.enable_tracing("vulnfix-test", tracking_dir=str(tmp_path / "m3"))
    r2 = tracing.enable_tracing("vulnfix-test", tracking_dir=str(tmp_path / "m3"))
    assert r1 == r2
