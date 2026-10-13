"""Optional MLflow tracing for the VulnFix pipeline.

Off by default. When enabled, it turns on MLflow's LangChain autolog so every
agent LLM call is captured as a trace: prompt, response, token counts, latency
and the chain structure. Traces are stored locally under ./mlruns, so this
works offline and keeps the air-gapped guarantee (no data leaves the machine).

If mlflow is not installed, enable_tracing() prints a note and does nothing, so
the pipeline, the demo notebook and CI never need mlflow.

Usage (inside the eval notebook, before running the harness):

    from eval.tracing import enable_tracing
    enable_tracing("vulnfix-eval")
"""
from __future__ import annotations

import os

_ENABLED = False


def enable_tracing(experiment_name: str = "vulnfix",
                   tracking_dir: str = "mlruns") -> bool:
    """Turn on local MLflow autolog for LangChain. Returns True if tracing is
    now active, False if mlflow is unavailable. Safe to call more than once."""
    global _ENABLED
    if _ENABLED:
        return True
    try:
        import mlflow
        import mlflow.langchain
    except Exception as e:  # noqa: BLE001
        print(f"[tracing] mlflow not available ({type(e).__name__}); "
              "running without tracing")
        return False

    abspath = os.path.abspath(tracking_dir)
    mlflow.set_tracking_uri("file://" + abspath)
    mlflow.set_experiment(experiment_name)
    # log_models=False keeps traces light; we want the spans, not model artifacts.
    mlflow.langchain.autolog(log_models=False, silent=True)
    _ENABLED = True
    print(f"[tracing] MLflow autolog on; traces under {abspath} "
          f"(experiment: {experiment_name})")
    return True


def is_enabled() -> bool:
    return _ENABLED
