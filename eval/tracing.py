"""Optional MLflow tracing for the VulnFix pipeline.

Off by default. When enabled, MLflow's LangChain autolog captures every agent
LLM call as a trace: prompt, response, token counts, latency and chain
structure. Storage is a local SQLite database (mlflow.db) plus a local artifact
dir, so this works offline and keeps the air-gapped guarantee: no data leaves
the machine, and no tracking server is needed.

SQLite is used because MLflow is deprecating the plain file store. SQLite is
still a single local file, so the offline property is unchanged.

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
    """Turn on local MLflow autolog for LangChain, backed by a local SQLite db.
    Returns True if tracing is now active, False if mlflow is unavailable.
    Safe to call more than once."""
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

    root = os.path.abspath(tracking_dir)
    os.makedirs(root, exist_ok=True)
    db_uri = "sqlite:///" + os.path.join(root, "mlflow.db")
    try:
        mlflow.set_tracking_uri(db_uri)
        mlflow.set_experiment(experiment_name)
        mlflow.langchain.autolog(log_models=False, silent=True)
    except Exception as e:  # noqa: BLE001
        # Never let observability break the run.
        print(f"[tracing] could not enable mlflow tracing ({type(e).__name__}: {e}); "
              "running without tracing")
        return False

    _ENABLED = True
    print(f"[tracing] MLflow autolog on; SQLite backend at {db_uri} "
          f"(experiment: {experiment_name})")
    return True


def is_enabled() -> bool:
    return _ENABLED
