import os
from dataclasses import asdict, dataclass


_TRUE_VALUES = {"1", "true", "yes", "on", "enabled"}
_FALSE_VALUES = {"0", "false", "no", "off", "disabled"}


def _env_toggle(name, default=True):
    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default

    normalized = raw_value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(
        f"{name} must be one of {sorted(_TRUE_VALUES | _FALSE_VALUES)}; "
        f"received {raw_value!r}."
    )


@dataclass(frozen=True)
class OrchestrationToggles:
    dag_orchestrator: bool = True
    ioc_curator: bool = True
    ttp_relations_graph: bool = True

    def snapshot(self):
        return asdict(self)


def load_orchestration_toggles():
    """Load the three RQ2 ablation toggles; all layers default to enabled."""
    return OrchestrationToggles(
        dag_orchestrator=_env_toggle("ENABLE_DAG_ORCHESTRATOR", True),
        ioc_curator=_env_toggle("ENABLE_IOC_CURATOR", True),
        ttp_relations_graph=_env_toggle("ENABLE_TTP_RELATIONS_GRAPH", True),
    )


def disabled_ttp_graph_context():
    """Return an explicit empty graph artifact for audit-compatible runs."""
    return {
        "enabled": False,
        "source": "disabled_by_rq2_toggle",
        "policy": (
            "TTP Relations Graph is disabled. No graph seeds, relations, "
            "neighbors, or evidence hypotheses are injected into the pipeline."
        ),
        "seed_ttps": [],
        "relations": [],
        "evidence_hypotheses": [],
    }
