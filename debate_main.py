import json
import os
import time
from datetime import datetime

from langchain_community.callbacks.manager import get_openai_callback

from agents.analyst_agent import AnalystAgent
from agents.coordinator_agent import CoordinatorAgent
from agents.debate_judge_agent import DebateFeedbackAgent, DebateJudgeAgent
from agents.hunter_agent import HunterAgent
from agents.llm_config import get_llm_config_snapshot
from agents.reporter_agent import ReporterAgent
from agents.summarizer_agent import SummarizerAgent
from agents.task_catalog import TASK_BY_ID, clone_task
from agents.verifier_agent import VerifierAgent
from evaluation.evaluator import SOCEvaluator
from evaluation.reasoning_evaluator import ReasoningEvaluator
from main import (
    _build_ioc_continuity_context,
    _build_ttp_seed_audit,
    _compose_scoring_entities,
    _is_verifier_ok,
)
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
from strategies.debate_strategy import DebateStrategy


def _ensure_debate_prompt_family():
    os.environ.setdefault("PROMPT_ARCHITECTURE", "debate_based")


def _normalize_concerns(feedback):
    concerns = (feedback or {}).get("point_of_concern", [])
    return concerns if isinstance(concerns, list) else []


def _has_concerns(feedback):
    """Track any debate disagreement for audit visibility."""
    if not feedback:
        return False
    return (
        bool(_normalize_concerns(feedback))
        or feedback.get("consensus") is False
        or bool(feedback.get("requires_judge"))
    )


def _has_blocking_concerns(feedback):
    """Only high-severity concerns are allowed to trigger expensive rework."""
    return any(
        str(concern.get("severity", "")).strip().lower() == "high"
        for concern in _normalize_concerns(feedback)
        if isinstance(concern, dict)
    )


def _should_revise(feedback, debate_strategy, started_at):
    return (
        _has_blocking_concerns(feedback)
        and not bool((feedback or {}).get("requires_judge"))
        and debate_strategy.can_revise(started_at)
    )


def _should_judge(feedback, debate_strategy, started_at):
    return bool((feedback or {}).get("requires_judge")) or (
        _has_blocking_concerns(feedback)
        and not debate_strategy.can_revise(started_at)
    )


def _feedback_text(feedback):
    concerns = (feedback or {}).get("point_of_concern", [])
    if not concerns:
        return "No debate concerns."
    lines = ["Debate point-of-concern list:"]
    for index, concern in enumerate(concerns, start=1):
        lines.append(
            "{index}. [{severity}] {claim} | issue={issue} | required_fix={required_fix}".format(
                index=index,
                severity=concern.get("severity", "medium"),
                claim=concern.get("claim", ""),
                issue=concern.get("issue", ""),
                required_fix=concern.get("required_fix", ""),
            )
        )
    return "\n".join(lines)


def _run_review(feedback_agent, stage, reviewer_role, prior_role, prior_output, context, focus):
    return feedback_agent.review(
        stage=stage,
        reviewer_role=reviewer_role,
        prior_role=prior_role,
        prior_output=prior_output,
        context=context,
        focus=focus,
    )


def _run_judge(judge_agent, stage, first_role, second_role, first_output, second_output, context):
    return judge_agent.resolve(
        stage=stage,
        first_role=first_role,
        second_role=second_role,
        first_output=first_output,
        second_output=second_output,
        context=context,
    )


def _plan_to_text(plan):
    return json.dumps(
        [
            {
                "id": task.get("id"),
                "name": task.get("name"),
                "reason": task.get("coordinator_reason", ""),
                "tools": task.get("tools", []),
                "depends_on": task.get("depends_on", []),
            }
            for task in plan
        ],
        ensure_ascii=False,
        indent=2,
    )


def _plan_from_judge_output(judge_result):
    accepted_output = str((judge_result or {}).get("accepted_output", "") or "")
    if not accepted_output:
        return []

    try:
        parsed = json.loads(accepted_output)
    except json.JSONDecodeError:
        start = accepted_output.find("{")
        end = accepted_output.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return []
        try:
            parsed = json.loads(accepted_output[start:end + 1])
        except json.JSONDecodeError:
            return []

    selected = parsed.get("selected_tasks", []) if isinstance(parsed, dict) else []
    if not isinstance(selected, list):
        return []

    plan = []
    seen = set()
    for item in selected:
        if not isinstance(item, dict):
            continue
        task_id = str(item.get("id", "")).strip()
        if task_id not in TASK_BY_ID or task_id in seen:
            continue
        task = clone_task(task_id)
        task["coordinator_reason"] = str(item.get("reason", "") or "Selected by Debate Judge.")
        plan.append(task)
        seen.add(task_id)
    return plan


def run_debate_soft_tests():
    _ensure_debate_prompt_family()
    feedback_agent = DebateFeedbackAgent()
    cases = [
        {
            "name": "correct_arithmetic",
            "test_message": "Hi, just tell the Hunter 1+1=2 and request the evaluation and provide feedback if there are any errors.",
            "expected_answer": "1+1=2 is correct.",
        },
        {
            "name": "incorrect_arithmetic",
            "test_message": "Hi, just tell the Hunter 1+1=3, request the evaluation and provide feedback if there are any errors.",
            "expected_answer": "1+1=2, so 1+1=3 should be flagged as incorrect.",
        },
    ]
    results = []
    for case in cases:
        result = feedback_agent.soft_test(
            test_message=case["test_message"],
            expected_answer=case["expected_answer"],
        )
        results.append({"case": case["name"], "result": result})
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return results


def run_debate_cyber_defense_system(log_data, scenario_name="UNTITLED_DEBATE"):
    _ensure_debate_prompt_family()
    start_time = time.time()
    debate_timeout = int(os.getenv("DEBATE_TIMEOUT_SECONDS", "300"))
    debate_strategy = DebateStrategy(timeout_seconds=debate_timeout, max_revision_rounds=1)

    coordinator = CoordinatorAgent()
    hunter = HunterAgent()
    verifier = VerifierAgent()
    analyst = AnalystAgent()
    reporter = ReporterAgent()
    feedback_agent = DebateFeedbackAgent()
    judge_agent = DebateJudgeAgent()
    llm_config = get_llm_config_snapshot([
        "coordinator",
        "hunter",
        "verifier",
        "analyst",
        "reporter",
        "tools",
        "debate_feedback",
        "debate_judge",
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
    debate_records = []

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
        plan_debate_started = time.time()
        plan_feedback = _run_review(
            feedback_agent,
            stage="coordinator_plan",
            reviewer_role="Hunter",
            prior_role="Coordinator",
            prior_output=_plan_to_text(coordinator_plan),
            context=log_data[:12000],
            focus="Check whether the selected tasks are evidence-backed, sufficient, non-redundant, and within the 8-12 task budget.",
        )
        plan_debate_record = {
            "stage": "coordinator_plan",
            "feedback": plan_feedback,
            "judge_result": None,
            "revision_applied": False,
        }
        if _should_revise(plan_feedback, debate_strategy, plan_debate_started):
            revised_log = (
                f"{log_data}\n\n"
                "Coordinator debate feedback from downstream Hunter reviewer:\n"
                f"{_feedback_text(plan_feedback)}\n"
                "Revise the task plan only when the concern is supported by the raw artifact."
            )
            coordinator_plan = coordinator.plan(revised_log)
            plan_debate_record["revision_applied"] = True
        elif _should_judge(plan_feedback, debate_strategy, plan_debate_started):
            plan_debate_record["judge_result"] = _run_judge(
                judge_agent,
                stage="coordinator_plan",
                first_role="Coordinator",
                second_role="Hunter",
                first_output=_plan_to_text(coordinator_plan),
                second_output=json.dumps(plan_feedback, ensure_ascii=False, indent=2),
                context=log_data[:12000],
            )
            judge_plan = _plan_from_judge_output(plan_debate_record["judge_result"])
            if judge_plan:
                coordinator_plan = judge_plan
                plan_debate_record["judge_plan_applied"] = True
        elif _has_concerns(plan_feedback):
            plan_debate_record["nonblocking_concerns_accepted"] = True
        debate_records.append(plan_debate_record)

        cyber_plan = expand_and_sort_plan(coordinator_plan)
        dag_state = build_initial_dag_state(entity_context, evidence_store=evidence_store)

        print(
            f"\n[Debate Main] Coordinator selected {len(coordinator_plan)} task(s); "
            f"DAG-expanded plan has {len(cyber_plan)} task(s)."
        )

        dag_export = export_dag(cyber_plan)
        dag_export["mermaid"] = dag_to_mermaid(cyber_plan)
        dag_path = os.path.join(run_dir, "cyberteam_dag.json")
        with open(dag_path, "w", encoding="utf-8") as f:
            json.dump(dag_export, f, ensure_ascii=False, indent=4)
        print(f"[Debate Main] CyberTeam DAG saved to: {os.path.abspath(dag_path)}")

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
                    f"\n[+] Debate Processing: {task['id']} - {task['name']} "
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

                    hunter_debate_started = time.time()
                    hunter_feedback = _run_review(
                        feedback_agent,
                        stage=f"hunter_task_{task['id']}",
                        reviewer_role="Verifier",
                        prior_role="Hunter",
                        prior_output=hunter_output,
                        context=task_log,
                        focus="Check unsupported claims, missing task-critical IOCs, weak MITRE mappings, missing tool audit, and task drift.",
                    )
                    task_debate_record = {
                        "stage": f"hunter_task_{task['id']}",
                        "feedback": hunter_feedback,
                        "judge_result": None,
                        "revision_applied": False,
                    }

                    if _should_revise(hunter_feedback, debate_strategy, hunter_debate_started):
                        debate_feedback_text = _feedback_text(hunter_feedback)
                        task_history = hunter.run(
                            task_log,
                            assigned_tasks=[task],
                            upstream_context=upstream_context,
                            verifier_feedback=debate_feedback_text,
                            previous_hunter_output=hunter_output,
                        )
                        hunter_output = task_history[-1].content if task_history else hunter_output
                        task_debate_record["revision_applied"] = True
                    elif _should_judge(hunter_feedback, debate_strategy, hunter_debate_started):
                        task_debate_record["judge_result"] = _run_judge(
                            judge_agent,
                            stage=f"hunter_task_{task['id']}",
                            first_role="Hunter",
                            second_role="Verifier",
                            first_output=hunter_output,
                            second_output=json.dumps(hunter_feedback, ensure_ascii=False, indent=2),
                            context=task_log,
                        )
                        accepted = task_debate_record["judge_result"].get("accepted_output")
                        if accepted:
                            hunter_output = f"{hunter_output}\n\nDebate Judge Resolution:\n{accepted}"
                    elif _has_concerns(hunter_feedback):
                        task_debate_record["nonblocking_concerns_accepted"] = True
                    debate_records.append(task_debate_record)

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
                            "debate_feedback": hunter_feedback,
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
                                "debate_feedback": hunter_feedback,
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
                    print(f"    [API ERROR] Attempt failed: {error_msg}")
                    last_feedback = f"Previous attempt failed before verification: {error_msg}"
                    time.sleep(60 if "429" in error_msg or "rate_limit" in error_msg.lower() else 5)

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

        print("\n[Analyst Debate] Starting deep incident analysis...")
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
        ttp_graph_prompt_context = ttp_graph.to_prompt_context(ttp_graph_context)

        deep_analysis = analyst.analyze_incident(
            results_str,
            analysis_context,
            entity_context=entity_context,
            ttp_relations_context=ttp_graph_prompt_context,
        )
        analyst_debate_started = time.time()
        analyst_feedback = _run_review(
            feedback_agent,
            stage="analyst_result",
            reviewer_role="Reporter",
            prior_role="Analyst",
            prior_output=deep_analysis,
            context=f"{results_str}\n\n{ttp_graph_prompt_context}",
            focus="Check chronology, unsupported conclusions, missing promoted TTP evidence, IOC/entity discipline, and report-readiness.",
        )
        analyst_debate_record = {
            "stage": "analyst_result",
            "feedback": analyst_feedback,
            "judge_result": None,
            "revision_applied": False,
        }
        if _should_revise(analyst_feedback, debate_strategy, analyst_debate_started):
            deep_analysis = analyst.analyze_incident(
                results_str,
                f"{analysis_context}\n\nDebate feedback to address:\n{_feedback_text(analyst_feedback)}",
                entity_context=entity_context,
                ttp_relations_context=ttp_graph_prompt_context,
            )
            analyst_debate_record["revision_applied"] = True
        elif _should_judge(analyst_feedback, debate_strategy, analyst_debate_started):
            analyst_debate_record["judge_result"] = _run_judge(
                judge_agent,
                stage="analyst_result",
                first_role="Analyst",
                second_role="Reporter",
                first_output=deep_analysis,
                second_output=json.dumps(analyst_feedback, ensure_ascii=False, indent=2),
                context=f"{results_str}\n\n{ttp_graph_prompt_context}",
            )
            accepted = analyst_debate_record["judge_result"].get("accepted_output")
            if accepted:
                deep_analysis = f"{deep_analysis}\n\nDebate Judge Resolution:\n{accepted}"
        elif _has_concerns(analyst_feedback):
            analyst_debate_record["nonblocking_concerns_accepted"] = True
        debate_records.append(analyst_debate_record)

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
            mitre_mapping = {"queries": [], "candidates": [], "error": str(error)}
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
            entity_context=curated_ioc_context,
        )
        report_str = "\n".join([str(x) for x in final_report]) if isinstance(final_report, list) else str(final_report)

        report_debate_started = time.time()
        report_feedback = _run_review(
            feedback_agent,
            stage="final_report",
            reviewer_role="Report Critic",
            prior_role="Reporter",
            prior_output=report_str,
            context=f"{deep_analysis}\n\n{curated_ioc_context}",
            focus="Check final report fidelity, unsupported new claims, missing promoted TTPs, and IOC table correctness.",
        )
        report_debate_record = {
            "stage": "final_report",
            "feedback": report_feedback,
            "judge_result": None,
            "revision_applied": False,
        }
        if _should_revise(report_feedback, debate_strategy, report_debate_started):
            revised_analysis = (
                f"{analysis_with_mitre}\n\n"
                "Reporter debate feedback to address:\n"
                f"{_feedback_text(report_feedback)}"
            )
            final_report = reporter.generate_final_report(
                revised_analysis,
                evidence_context=results_str,
                entity_context=curated_ioc_context,
            )
            report_str = "\n".join([str(x) for x in final_report]) if isinstance(final_report, list) else str(final_report)
            report_debate_record["revision_applied"] = True
        elif _should_judge(report_feedback, debate_strategy, report_debate_started):
            report_debate_record["judge_result"] = _run_judge(
                judge_agent,
                stage="final_report",
                first_role="Reporter",
                second_role="Report Critic",
                first_output=report_str,
                second_output=json.dumps(report_feedback, ensure_ascii=False, indent=2),
                context=f"{deep_analysis}\n\n{curated_ioc_context}",
            )
            accepted = report_debate_record["judge_result"].get("accepted_output")
            if accepted:
                report_str = str(accepted)
                report_debate_record["judge_report_applied"] = True
        elif _has_concerns(report_feedback):
            report_debate_record["nonblocking_concerns_accepted"] = True
        debate_records.append(report_debate_record)

        report_path = os.path.join(run_dir, "FINAL_REPORT_SOC.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_str)
        print(f"[Reporter] Final report saved to: {os.path.abspath(report_path)}")

        debate_path = os.path.join(run_dir, "debate_audit.json")
        with open(debate_path, "w", encoding="utf-8") as f:
            json.dump(debate_records, f, ensure_ascii=False, indent=2)

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
        "strategy": "debate_based",
        "metadata": {
            "test_date": timestamp,
            "latency_seconds": round(latency, 2),
            "llm_config": llm_config,
            "openai_metrics": {
                "input_tokens": total_input,
                "output_tokens": total_output,
                "total_cost_usd": round(total_cost, 6),
            },
            "debate_timeout_seconds": debate_timeout,
        },
        "layer_1_metrics": results_t1["layer_1_metrics"],
        "layer_2_audit": result_t2,
        "reasoning_audit": reasoning_audit,
        "ioc_scoring_policy": {
            "source": "curated_iocs",
            "fallback_applied": False,
            "curated_iocs_path": curated_iocs_path,
            "curated_ioc_counts": curated_iocs.get("counts", {}),
            "ioc_continuity_audit_path": ioc_continuity_path,
            "ioc_continuity_counts": ioc_continuity_audit.get("counts", {}),
            "policy": (
                "Debate strategy reorders agent communication only. IOC metrics use the same curated "
                "suspicious/malicious IOC set as hierarchical; TTP metrics use final report techniques. "
                "No deterministic scoring fallback is appended."
            ),
        },
        "ttp_seed_audit": ttp_seed_audit,
        "debate_audit_path": debate_path,
    }

    eval_file_path = os.path.join(run_dir, "eval_report.json")
    with open(eval_file_path, "w", encoding="utf-8") as f:
        json.dump(final_eval_data, f, indent=4, ensure_ascii=False)
    print(f"[Evaluator] Eval report saved to: {os.path.abspath(eval_file_path)}")

    print("\n" + "=" * 70)
    print(f"DEBATE BENCHMARK REPORT: SCENARIO [{scenario_id}]")
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
    print(f"    - Layer 2 Score (Weighted F1): {result_t2.get('enrichment_quality_score', 0)}/10")
    print(
        f"      + TTPs F1: {result_t2['f1_ttps']:.4f} "
        f"| IOCs F1: {result_t2['f1_iocs']:.4f}"
    )
    print(
        f"      + TTPs Jaccard: {result_t2['jaccard_ttps']:.4f} "
        f"| IOCs Jaccard: {result_t2['jaccard_iocs']:.4f}"
    )
    print("-" * 70)
    print("[4] DEBATE AUDIT")
    print(f"    - Debate Records:         {len(debate_records)}")
    print(f"    - Debate Audit Path:      {os.path.abspath(debate_path)}")
    print(f"    - Timeout Seconds:        {debate_timeout}")
    print("=" * 70 + "\n")

    return report_str


if __name__ == "__main__":
    if os.getenv("DEBATE_SOFT_TEST", "0").strip().lower() in {"1", "true", "yes"}:
        run_debate_soft_tests()
    else:
        log_file_path = os.getenv(
            "ARTIFACT_PATH",
            os.path.join("datasets", "CobaltStrike_Lockbit", "artifacts.json"),
        )
        try:
            with open(log_file_path, "r", encoding="utf-8") as f:
                log_payload = f.read()
            print(f"[*] Loaded log from: {log_file_path}")
            log_payload = json.dumps(json.loads(log_payload), indent=2)
            run_debate_cyber_defense_system(
                log_payload,
                scenario_name=os.getenv("SCENARIO_NAME", "CobaltStrike_LockBit_Debate"),
            )
        except FileNotFoundError:
            print(f"ERROR: File not found at {log_file_path}")
        except json.JSONDecodeError:
            print("ERROR: artifacts.json is not valid JSON.")
        except Exception as e:
            print(f"ERROR: Unexpected failure: {e}")
