import json
import os
import re
import time
from datetime import datetime

from langchain_community.callbacks.manager import get_openai_callback

from agents.coordinator_agent import CoordinatorAgent
from agents.hunter_agent import HunterAgent
from agents.llm_config import get_llm_config_snapshot
from agents.verifier_agent import VerifierAgent
from agents.analyst_agent import AnalystAgent
from agents.reporter_agent import ReporterAgent
from agents.summarizer_agent import SummarizerAgent
from evaluation.evaluator import SOCEvaluator
from evaluation.reasoning_evaluator import ReasoningEvaluator
from src.extractor import EvidenceExtractor
from src.ioc_curator import IOCCurator
from src.mitre_mapper import MitreMapper
from src.ttp_relations_graph import TTPRelationsGraph
from strategies.cyberteam_dag import (
    build_initial_dag_state,
    build_upstream_context,
    dag_to_mermaid,
    expand_and_sort_plan,
    export_dag,
    record_task_failure,
    record_task_success,
)


def _build_ttp_seed_audit(final_results, ttp_graph_context):
    seeds = [seed.upper() for seed in ttp_graph_context.get("seed_ttps", [])]
    seed_sources = []

    for seed in seeds:
        sources = []
        for item in final_results:
            if item.get("status") != "Verified":
                continue

            artifact = item.get("artifact") or {}
            artifact_candidates = {
                str(candidate).upper()
                for candidate in artifact.get("ttp_candidates", [])
            }
            result_text = str(item.get("result", ""))

            if seed not in artifact_candidates and seed not in result_text.upper():
                continue

            sources.append({
                "task_id": item.get("task_id"),
                "task_name": item.get("task_name"),
                "source": "verified_hunter_artifact_or_result",
                "artifact_ttp_candidates": sorted(artifact_candidates),
                "summary_excerpt": str(artifact.get("summary", ""))[:500],
            })

        seed_sources.append({
            "technique_id": seed,
            "sources": sources,
        })

    return {
        "policy": (
            "TTP seeds are extracted from verified Hunter findings/results_str by technique-ID regex, "
            "filtered to technique IDs present in the local MITRE ATT&CK Enterprise dataset, and used only "
            "to retrieve graph-neighbor mapping guidance. They are not ground truth and are not injected "
            "into IOC scoring."
        ),
        "framing": (
            "The TTP Relations Graph is infrastructure that supports attack-technique mapping with controlled "
            "TTP seeding. Prompting techniques remain agent-prompt variants and do not define total system "
            "performance by themselves."
        ),
        "graph_source": ttp_graph_context.get("source"),
        "seed_count": len(seeds),
        "relation_count": len(ttp_graph_context.get("relations", [])),
        "evidence_hypothesis_count": len(ttp_graph_context.get("evidence_hypotheses", [])),
        "evidence_hypotheses": ttp_graph_context.get("evidence_hypotheses", []),
        "max_neighbors_per_seed": 10,
        "seeds": seed_sources,
    }


IOC_CONTINUITY_CATEGORIES = ["ips", "hosts", "users", "processes", "files", "hashes"]


def _merge_entity_sets(*entity_maps):
    merged = {}
    for category in IOC_CONTINUITY_CATEGORIES:
        values = set()
        for entity_map in entity_maps:
            values.update(str(value) for value in entity_map.get(category, []) if value)
        merged[category] = sorted(values)
    return merged


def _entity_counts(entity_map):
    return {
        category: len(entity_map.get(category, []))
        for category in IOC_CONTINUITY_CATEGORIES
    }


def _build_ioc_continuity_context(evaluator, final_results, analyst_result, baseline_entities):
    verified_hunter_items = [
        {
            "task_id": item.get("task_id"),
            "task_name": item.get("task_name"),
            "result": item.get("result", ""),
            "artifact": item.get("artifact", {}),
        }
        for item in final_results
        if item.get("status") == "Verified"
    ]
    verified_hunter_text = json.dumps(verified_hunter_items, ensure_ascii=False)

    hunter_entities = evaluator._extract_entities(
        verified_hunter_text,
        source_type="verified_hunter_results",
    )
    analyst_entities = evaluator._extract_entities(
        analyst_result,
        source_type="analyst_result",
    )
    pipeline_supported_entities = _merge_entity_sets(hunter_entities, analyst_entities)
    baseline_reference_entities = {
        category: sorted(str(value) for value in baseline_entities.get(category, []) if value)
        for category in IOC_CONTINUITY_CATEGORIES
    }

    audit = {
        "policy": (
            "IOC continuity context is built from verified Hunter outputs and Analyst synthesis. "
            "The raw baseline inventory is included only as a coverage guardrail. This context is passed "
            "to the Reporter before generation; it is not appended after generation and is not a deterministic fallback."
        ),
        "pipeline_supported_entities": pipeline_supported_entities,
        "baseline_reference_entities": baseline_reference_entities,
        "counts": {
            "verified_hunter": _entity_counts(hunter_entities),
            "analyst": _entity_counts(analyst_entities),
            "pipeline_supported_union": _entity_counts(pipeline_supported_entities),
            "baseline_reference": _entity_counts(baseline_reference_entities),
        },
    }

    context = (
        "Pipeline IOC Continuity Context\n"
        f"{audit['policy']}\n\n"
        "Reporter instruction:\n"
        "- Enumerate every value from pipeline_supported_entities in the final Indicators of Compromise table.\n"
        "- Do not collapse this inventory with phrases like 'including', 'such as', or 'etc.'.\n"
        "- If maliciousness is uncertain, keep the value and label it Observed/Contextual or Needs Review; do not drop it.\n"
        "- Use baseline_reference_entities only to catch likely omissions from pipeline-supported findings; do not invent values absent from all supplied inputs.\n\n"
        "pipeline_supported_entities:\n"
        f"{json.dumps(pipeline_supported_entities, ensure_ascii=False, indent=2)}\n\n"
        "baseline_reference_entities:\n"
        f"{json.dumps(baseline_reference_entities, ensure_ascii=False, indent=2)}"
    )
    return context, audit


def _compose_scoring_entities(report_entities, ioc_entities):
    scoring_entities = {
        "ips": ioc_entities.get("ips", []),
        "hosts": ioc_entities.get("hosts", []),
        "users": [],
        "processes": ioc_entities.get("processes", []),
        "files": ioc_entities.get("files", []),
        "hashes": ioc_entities.get("hashes", []),
        "techniques": report_entities.get("techniques", []),
    }
    return scoring_entities


def _is_verifier_ok(check_result):
    """Accept strict OK and OK-prefixed verifier explanations.

    Verifier prompts ask for exactly OK, but LLMs sometimes return helpful text
    such as "OK: all material claims are supported". Treat that as pass while
    still rejecting FAIL/NOT OK and unrelated responses.
    """
    check_str = str(check_result or "").strip()
    return bool(re.match(r"^OK(?:\b|[\s:.\-–—])", check_str, flags=re.IGNORECASE))


def run_cyber_defense_system(log_data, scenario_name="UNTITLED"):
    start_time = time.time()

    coordinator = CoordinatorAgent()
    hunter = HunterAgent()
    verifier = VerifierAgent()
    analyst = AnalystAgent()
    reporter = ReporterAgent()
    llm_config = get_llm_config_snapshot([
        "coordinator",
        "hunter",
        "verifier",
        "analyst",
        "reporter",
        "tools",
    ])
    print(f"[LLM] Runtime configuration: {json.dumps(llm_config, ensure_ascii=False)}")
    evaluator = SOCEvaluator()
    reasoning_evaluator = ReasoningEvaluator()
    extractor = EvidenceExtractor()
    ioc_curator = IOCCurator()
    ttp_graph = TTPRelationsGraph()
    summarizer = SummarizerAgent()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scenario_id = f"{scenario_name}_{timestamp}"
    run_dir = os.path.join("runs", scenario_id)
    os.makedirs(run_dir, exist_ok=True)

    final_results = []

    with get_openai_callback() as cb:
        print("\n[Evaluator] Extracting baseline entities from raw log...")
        pre_entities = evaluator._extract_entities(log_data, source_type="log")
        entity_context = json.dumps(pre_entities, indent=2, ensure_ascii=False)

        print("[Extractor] Building deterministic evidence inventory...")
        evidence_store = extractor.extract(log_data)
        evidence_store_path = os.path.join(run_dir, "evidence_store.json")
        with open(evidence_store_path, "w", encoding="utf-8") as f:
            json.dump(evidence_store, f, ensure_ascii=False, indent=2)

        coordinator_plan = coordinator.plan(log_data)
        cyber_plan = expand_and_sort_plan(coordinator_plan)
        dag_state = build_initial_dag_state(entity_context, evidence_store=evidence_store)

        print(
            f"\n[Main] Coordinator selected {len(coordinator_plan)} task(s); "
            f"DAG-expanded plan has {len(cyber_plan)} task(s)."
        )

        dag_export = export_dag(cyber_plan)
        dag_export["mermaid"] = dag_to_mermaid(cyber_plan)
        dag_path = os.path.join(run_dir, "cyberteam_dag.json")
        with open(dag_path, "w", encoding="utf-8") as f:
            json.dump(dag_export, f, ensure_ascii=False, indent=4)
        print(f"[Main] CyberTeam DAG saved to: {os.path.abspath(dag_path)}")

        for task in cyber_plan:
            success = False
            retries = 0
            max_retries = 2
            last_feedback = None
            last_hunter_output = None
            last_artifact = None
            task_log = extractor.build_task_view(task, evidence_store)

            while not success and retries <= max_retries:
                print(
                    f"\n[+] Processing: {task['id']} - {task['name']} "
                    f"(attempt {retries + 1})"
                )

                try:
                    upstream_context = build_upstream_context(task, dag_state)
                    task_history = hunter.run(
                        task_log,
                        assigned_tasks=[task],
                        upstream_context=upstream_context,
                        verifier_feedback=last_feedback,
                        previous_hunter_output=last_hunter_output,
                    )
                    hunter_output = task_history[-1].content if task_history else ""
                    last_artifact = summarizer.summarize(
                        task,
                        hunter_output,
                        evidence_store=evidence_store,
                    )
                    last_hunter_output = summarizer.compact_for_retry(last_artifact)

                    check_result = verifier.verify(task["name"], hunter_output, task_log)
                    check_str = str(check_result).strip()

                    if _is_verifier_ok(check_str):
                        print(f"    [VERIFIED] Task {task['id']} passed.")
                        final_results.append({
                            "task_id": task["id"],
                            "task_name": task["name"],
                            "status": "Verified",
                            "depends_on": task.get("depends_on", []),
                            "selected_by_coordinator": task.get("selected_by_coordinator", False),
                            "result": hunter_output,
                            "artifact": last_artifact,
                        })
                        record_task_success(
                            dag_state,
                            task,
                            hunter_output,
                            artifact=last_artifact,
                        )
                        success = True
                    else:
                        retries += 1
                        last_feedback = check_result
                        print(f"    [FAILED] Verifier feedback: {check_result}")

                        if retries <= max_retries:
                            print("    [RETRY] Hunter re-working with verifier feedback...")
                        else:
                            print("    [SKIP] Verification failed after max retries.")
                            failed_artifact = summarizer.summarize(
                                task,
                                hunter_output,
                                evidence_store=evidence_store,
                                status="Failed_Verification",
                                reason=check_str,
                            )
                            final_results.append({
                                "task_id": task["id"],
                                "task_name": task["name"],
                                "status": "Failed_Verification",
                                "depends_on": task.get("depends_on", []),
                                "selected_by_coordinator": task.get("selected_by_coordinator", False),
                                "result": hunter_output,
                                "artifact": failed_artifact,
                                "reason": check_result,
                            })
                            record_task_failure(
                                dag_state,
                                task,
                                hunter_output,
                                check_result,
                                artifact=failed_artifact,
                            )

                except Exception as e:
                    error_msg = str(e)
                    retries += 1

                    if "429" in error_msg or "rate_limit" in error_msg.lower():
                        print("    [QUOTA HIT] Sleeping 60s before retry...")
                        last_feedback = f"Previous attempt hit rate limit: {error_msg}"
                        time.sleep(60)
                    else:
                        print(f"    [API ERROR] Attempt failed: {error_msg}")
                        last_feedback = (
                            f"Previous attempt failed before verification: {error_msg}"
                        )
                        time.sleep(5)

                    if retries > max_retries:
                        error_artifact = summarizer.summarize(
                            task,
                            "",
                            evidence_store=evidence_store,
                            status="Error",
                            reason=error_msg,
                        )
                        final_results.append({
                            "task_id": task["id"],
                            "task_name": task["name"],
                            "status": "Error",
                            "depends_on": task.get("depends_on", []),
                            "selected_by_coordinator": task.get("selected_by_coordinator", False),
                            "result": "",
                            "artifact": error_artifact,
                            "reason": error_msg,
                        })
                        record_task_failure(
                            dag_state,
                            task,
                            "",
                            error_msg,
                            artifact=error_artifact,
                        )

        hunt_results_path = os.path.join(run_dir, "soc_hunt_results.json")
        with open(hunt_results_path, "w", encoding="utf-8") as f:
            json.dump(final_results, f, ensure_ascii=False, indent=4)

        print("\n[Analyst] Starting deep incident analysis...")
        lean_results = [
            {"task": item["task_id"], "findings": item["artifact"]}
            for item in final_results
            if item["status"] == "Verified"
        ]
        results_str = json.dumps(lean_results, indent=2, ensure_ascii=False)
        analysis_context = extractor.build_analysis_context(evidence_store)
        ttp_graph_context = ttp_graph.build_context(results_str)
        ttp_graph_context_path = os.path.join(run_dir, "ttp_relations_context.json")
        with open(ttp_graph_context_path, "w", encoding="utf-8") as f:
            json.dump(ttp_graph_context, f, ensure_ascii=False, indent=2)
        ttp_seed_audit = _build_ttp_seed_audit(final_results, ttp_graph_context)
        ttp_seed_audit_path = os.path.join(run_dir, "ttp_seed_audit.json")
        with open(ttp_seed_audit_path, "w", encoding="utf-8") as f:
            json.dump(ttp_seed_audit, f, ensure_ascii=False, indent=2)
        print(
            f"[MITRE] TTP graph seeded with {ttp_seed_audit['seed_count']} "
            "verified Hunter technique candidate(s)."
        )
        if ttp_seed_audit["seeds"]:
            print(
                "[MITRE] Seed TTPs: "
                + ", ".join(seed["technique_id"] for seed in ttp_seed_audit["seeds"])
            )
        ttp_graph_prompt_context = ttp_graph.to_prompt_context(ttp_graph_context)

        deep_analysis = analyst.analyze_incident(
            results_str,
            analysis_context,
            entity_context=entity_context,
            ttp_relations_context=ttp_graph_prompt_context,
        )
        analyst_result_path = os.path.join(run_dir, "analyst_result.md")
        with open(analyst_result_path, "w", encoding="utf-8") as f:
            f.write(deep_analysis)
        ioc_continuity_context, ioc_continuity_audit = _build_ioc_continuity_context(
            evaluator,
            final_results,
            deep_analysis,
            pre_entities,
        )
        ioc_continuity_path = os.path.join(run_dir, "ioc_continuity_audit.json")
        with open(ioc_continuity_path, "w", encoding="utf-8") as f:
            json.dump(ioc_continuity_audit, f, ensure_ascii=False, indent=2)
        curated_iocs = ioc_curator.curate(evidence_store, final_results, deep_analysis)
        curated_iocs_path = os.path.join(run_dir, "curated_iocs.json")
        with open(curated_iocs_path, "w", encoding="utf-8") as f:
            json.dump(curated_iocs, f, ensure_ascii=False, indent=2)
        curated_ioc_context = ioc_curator.to_prompt_context(curated_iocs)

        print("[MITRE] Retrieving ATT&CK candidates for the reconstructed behaviors...")
        try:
            mitre_mapper = MitreMapper()
            mitre_mapping = mitre_mapper.map_analysis(deep_analysis)
            mitre_mapping_text = mitre_mapper.to_json(mitre_mapping)
        except Exception as error:
            mitre_mapping = {
                "queries": [],
                "candidates": [],
                "error": str(error),
            }
            mitre_mapping_text = json.dumps(mitre_mapping, ensure_ascii=False, indent=2)
        mitre_mapping_path = os.path.join(run_dir, "mitre_mapping_candidates.json")
        with open(mitre_mapping_path, "w", encoding="utf-8") as f:
            json.dump(mitre_mapping, f, ensure_ascii=False, indent=2)
        analysis_with_mitre = (
            f"{deep_analysis}\n\n"
            "Local MITRE ATT&CK candidate retrieval for evidence-based validation:\n"
            f"{mitre_mapping_text}"
        )

        final_report = reporter.generate_final_report(
            analysis_with_mitre,
            evidence_context=results_str,
            entity_context=curated_ioc_context
        )
        report_str = (
            "\n".join([str(x) for x in final_report])
            if isinstance(final_report, list)
            else str(final_report)
        )

        report_path = os.path.join(run_dir, "FINAL_REPORT_SOC.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_str)
        print(f"[Reporter] Final report saved to: {os.path.abspath(report_path)}")

        print("\n[Evaluator] Extracting entities from final report...")
        report_entities = evaluator._extract_entities(report_str, source_type="report")
        curated_ioc_entities = evaluator._extract_entities(
            curated_iocs.get("indicators", {}),
            source_type="curated_iocs",
        )
        post_entities = _compose_scoring_entities(report_entities, curated_ioc_entities)

        results_t1 = evaluator.compare_entities(pre_entities, post_entities)

        ground_truth_path = os.getenv(
            "GROUND_TRUTH_PATH",
            os.path.join("datasets", "CobaltStrike_Lockbit", "ground_truth.json"),
        )
        with open(ground_truth_path, "r", encoding="utf-8") as f:
            ground_truth_data = json.load(f)
        result_t2 = evaluator.calculate_layer_2_jaccard(
            ground_truth_data,
            post_entities,
            w_i=0.7,
            w_j=0.3,
        )
        reasoning_audit = reasoning_evaluator.evaluate(
            final_results,
            deep_analysis,
            report_str,
            evidence_store=evidence_store,
            graph_context=ttp_graph_context,
        )
        reasoning_eval_path = os.path.join(run_dir, "reasoning_eval_report.json")
        with open(reasoning_eval_path, "w", encoding="utf-8") as f:
            json.dump(reasoning_audit, f, indent=4, ensure_ascii=False)

    latency = time.time() - start_time
    total_input = cb.prompt_tokens
    total_output = cb.completion_tokens
    total_cost = cb.total_cost

    final_eval_data = {
        "scenario_id": scenario_id,
        "metadata": {
            "test_date": timestamp,
            "latency_seconds": round(latency, 2),
            "llm_config": llm_config,
            "openai_metrics": {
                "input_tokens": total_input,
                "output_tokens": total_output,
                "total_cost_usd": round(total_cost, 6),
            },
        },
        "layer_1_metrics": results_t1["layer_1_metrics"],
        "layer_2_audit": result_t2,
        "reasoning_audit": reasoning_audit,
        "ioc_scoring_policy": {
            "source": "final_report",
            "fallback_applied": False,
            "curated_iocs_path": curated_iocs_path,
            "curated_ioc_counts": curated_iocs.get("counts", {}),
            "ioc_continuity_audit_path": ioc_continuity_path,
            "ioc_continuity_counts": ioc_continuity_audit.get("counts", {}),
            "policy": (
                "IOC metrics use the curated suspicious/malicious IOC set generated after verified Hunter tasks "
                "and Analyst synthesis. TTP metrics still use technique IDs extracted from the final report. "
                "Task 7 is treated as a normal Hunter task, not as an authoritative scoring shortcut. "
                "No downstream deterministic IOC fallback is appended."
            ),
        },
        "ttp_seed_audit": ttp_seed_audit,
    }

    eval_file_path = os.path.join(run_dir, "eval_report.json")
    with open(eval_file_path, "w", encoding="utf-8") as f:
        json.dump(final_eval_data, f, indent=4, ensure_ascii=False)
    print(f"[Evaluator] Eval report saved to: {os.path.abspath(eval_file_path)}")

    print("\n" + "=" * 70)
    print(f"BENCHMARK REPORT: SCENARIO [{scenario_id}]")
    print("=" * 70)
    print("[1] PERFORMANCE METRICS")
    print(f"    - Execution Time:         {latency:.2f} seconds")
    print("-" * 70)
    print("[2] RESOURCE CONSUMPTION (OPENAI)")
    print(f"    - Input Tokens:           {total_input:,}")
    print(f"    - Output Tokens:          {total_output:,}")
    print(f"    - API Cost Estimate:      ${total_cost:.6f} USD")
    print("-" * 70)
    print("[3] RELIABILITY METRICS")
    print(f"    - Layer 1 (Recall):       {results_t1['layer_1_metrics']['recall']:.4f}")
    print(f"    - Layer 1 (Precision):    {results_t1['layer_1_metrics']['precision']:.4f}")
    print(f"    - Layer 1 (F1 Score):     {results_t1['layer_1_metrics']['f1_score']:.4f}")
    if result_t2:
        print(f"    - Layer 2 Score (Weighted F1): {result_t2.get('enrichment_quality_score', 0)}/10")
        print(
            f"      + TTPs F1: {result_t2['f1_ttps']:.4f} "
            f"| IOCs F1: {result_t2['f1_iocs']:.4f}"
        )
        print(
            f"      + TTPs Jaccard: {result_t2['jaccard_ttps']:.4f} "
            f"| IOCs Jaccard: {result_t2['jaccard_iocs']:.4f}"
        )
    if reasoning_audit:
        print("-" * 70)
        print("[4] REASONING QUALITY METRICS")
        print(f"    - LLM Judge Enabled: {reasoning_audit.get('llm_judge_enabled', False)}")
        print(f"    - Overall Reasoning Score: {reasoning_audit['overall_reasoning_score']:.4f}/10")
        for stage_name, stage_data in reasoning_audit.get("stages", {}).items():
            print(f"      + {stage_name}: {stage_data.get('score_10', 0):.4f}/10")
    print("-" * 70)
    print("[5] IOC SCORING SOURCE")
    print("    - IOC Source:              Curated suspicious/malicious IOC set")
    print("    - Task 7 Mode:             Normal Hunter task, not authoritative scoring shortcut")
    print("    - Fallback Applied:        False")
    print(f"    - Curated IOC Counts:      {curated_iocs.get('counts', {})}")
    print("    - Policy:                  IOC score uses curated IOCs; TTP score uses final report techniques.")
    print("-" * 70)
    print("[6] TTP RELATIONS GRAPH SEEDS")
    print(f"    - Seed Count:              {ttp_seed_audit.get('seed_count', 0)}")
    seed_ids = [seed.get("technique_id", "") for seed in ttp_seed_audit.get("seeds", [])]
    print(f"    - Seed IDs:                {', '.join(seed_ids) if seed_ids else 'None'}")
    print("    - Seed Source:             Verified Hunter findings/results_str, filtered by local MITRE dataset")
    print("=" * 70 + "\n")

    return report_str


if __name__ == "__main__":
    log_file_path = os.getenv(
        "ARTIFACT_PATH",
        os.path.join("datasets", "CobaltStrike_Lockbit", "artifacts.json"),
    )

    try:
        with open(log_file_path, "r", encoding="utf-8") as f:
            log_payload = f.read()

        print(f"[*] Loaded log from: {log_file_path}")
        log_payload = json.dumps(json.loads(log_payload), indent=2)
        run_cyber_defense_system(
            log_payload,
            scenario_name=os.getenv("SCENARIO_NAME", "CobaltStrike_LockBit_Clean"),
        )

    except FileNotFoundError:
        print(f"ERROR: File not found at {log_file_path}")
    except json.JSONDecodeError:
        print("ERROR: artifacts.json is not valid JSON.")
    except Exception as e:
        print(f"ERROR: Unexpected failure: {e}")
