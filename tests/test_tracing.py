"""Tracing must never break the pipeline. If mlflow is installed it returns
True; if not, it returns False and does nothing. Either way, no exception."""
import importlib
import eval.tracing as tracing


def test_enable_tracing_never_raises():
    # Reset module state so the test is deterministic regardless of import order.
    importlib.reload(tracing)
    result = tracing.enable_tracing("vulnfix-test", tracking_dir="/tmp/vulnfix_mlruns_test")
    assert result in (True, False)


def test_is_enabled_matches_result():
    importlib.reload(tracing)
    r = tracing.enable_tracing("vulnfix-test", tracking_dir="/tmp/vulnfix_mlruns_test2")
    assert tracing.is_enabled() == r
