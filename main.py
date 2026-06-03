import json
import os
import time
from datetime import datetime

from langchain_community.callbacks.manager import get_openai_callback

from agents.coordinator_agent import CoordinatorAgent
from agents.hunter_agent import HunterAgent
from agents.verifier_agent import VerifierAgent
from agents.analyst_agent import AnalystAgent
from agents.reporter_agent import ReporterAgent
from evaluation.evaluator import SOCEvaluator


def run_cyber_defense_system(log_data, scenario_name="UNTITLED"):
    start_time = time.time()

    coordinator = CoordinatorAgent()
    hunter = HunterAgent()
    verifier = VerifierAgent()
    analyst = AnalystAgent()
    reporter = ReporterAgent()
    evaluator = SOCEvaluator()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scenario_id = f"{scenario_name}_{timestamp}"
    run_dir = os.path.join("runs", scenario_id)
    os.makedirs(run_dir, exist_ok=True)

    final_results = []

    with get_openai_callback() as cb:
        print("\n[Evaluator] Extracting baseline entities from raw log...")
        pre_entities = evaluator._extract_entities(log_data, source_type="log")
        entity_context = json.dumps(pre_entities, indent=2, ensure_ascii=False)

        cyber_plan = coordinator.plan(log_data)
        print(f"\n[Main] Plan ready with {len(cyber_plan)} task(s).")

        task_counter = 0

        for task in cyber_plan:
            task_counter += 1
            success = False
            retries = 0
            max_retries = 2
            last_feedback = None

            while not success and retries <= max_retries:
                print(
                    f"\n[+] Processing: {task['id']} - {task['name']} "
                    f"(attempt {retries + 1})"
                )

                try:
                    task_history = hunter.run(
                        log_data,
                        assigned_tasks=[task],
                        verifier_feedback=last_feedback,
                    )
                    hunter_output = task_history[-1].content if task_history else ""

                    time.sleep(2)

                    check_result = verifier.verify(task["name"], hunter_output, log_data)
                    check_str = str(check_result).strip()

                    if check_str.upper() == "OK":
                        print(f"    [VERIFIED] Task {task['id']} passed.")
                        final_results.append({
                            "task_id": task["id"],
                            "status": "Verified",
                            "result": hunter_output,
                        })
                        success = True
                    else:
                        retries += 1
                        last_feedback = check_result
                        print(f"    [FAILED] Verifier feedback: {check_result}")

                        if retries <= max_retries:
                            print("    [RETRY] Hunter re-working with verifier feedback...")
                            time.sleep(2)
                        else:
                            print("    [SKIP] Verification failed after max retries.")
                            final_results.append({
                                "task_id": task["id"],
                                "status": "Failed_Verification",
                                "result": hunter_output,
                                "reason": check_result,
                            })

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
                        final_results.append({
                            "task_id": task["id"],
                            "status": "Error",
                            "result": "",
                            "reason": error_msg,
                        })

            if task_counter % 2 == 0:
                print(
                    f"\n[zZz] Finished {task_counter} tasks. "
                    "Sleeping 40s to reduce TPM pressure..."
                )
                time.sleep(10)

        hunt_results_path = os.path.join(run_dir, "soc_hunt_results.json")
        with open(hunt_results_path, "w", encoding="utf-8") as f:
            json.dump(final_results, f, ensure_ascii=False, indent=4)

        print("\n[Analyst] Starting deep incident analysis...")
        lean_results = [
            {"task": item["task_id"], "findings": item["result"]}
            for item in final_results
            if item["status"] == "Verified"
        ]
        results_str = json.dumps(lean_results, indent=2, ensure_ascii=False)

        deep_analysis = analyst.analyze_incident(
            results_str,
            log_data,
            entity_context=entity_context
        )

        final_report = reporter.generate_final_report(
            deep_analysis,
            evidence_context=results_str,
            entity_context=entity_context
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
        post_entities = evaluator._extract_entities(report_str, source_type="report")

        results_t1 = evaluator.compare_entities(pre_entities, post_entities)

        ground_truth_path = os.path.join(
            "datasets",
            "CobaltStrike_Lockbit",
            "ground_truth.json",
        )
        with open(ground_truth_path, "r", encoding="utf-8") as f:
            ground_truth_data = json.load(f)
        result_t2 = evaluator.calculate_layer_2_jaccard(
            ground_truth_data,
            post_entities,
            w_i=0.7,
            w_j=0.3,
        )

    latency = time.time() - start_time
    total_input = cb.prompt_tokens
    total_output = cb.completion_tokens
    total_cost = cb.total_cost

    final_eval_data = {
        "scenario_id": scenario_id,
        "metadata": {
            "test_date": timestamp,
            "latency_seconds": round(latency, 2),
            "openai_metrics": {
                "input_tokens": total_input,
                "output_tokens": total_output,
                "total_cost_usd": round(total_cost, 6),
            },
        },
        "layer_1_metrics": results_t1["layer_1_metrics"],
        "layer_2_audit": result_t2,
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
    print("=" * 70 + "\n")

    return final_report


if __name__ == "__main__":
    log_file_path = os.path.join("datasets", "CobaltStrike_Lockbit", "artifacts.json")

    try:
        with open(log_file_path, "r", encoding="utf-8") as f:
            log_payload = f.read()

        print(f"[*] Loaded log from: {log_file_path}")
        log_payload = json.dumps(json.loads(log_payload), indent=2)
        run_cyber_defense_system(log_payload, scenario_name="CobaltStrike_LockBit_Clean")

    except FileNotFoundError:
        print(f"ERROR: File not found at {log_file_path}")
    except json.JSONDecodeError:
        print("ERROR: artifacts.json is not valid JSON.")
    except Exception as e:
        print(f"ERROR: Unexpected failure: {e}")
