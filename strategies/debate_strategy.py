class DebateStrategy:
    """Scaffold for a future debate-based multi-agent collaboration strategy.

    This module is deliberately not imported by main.py. It prepares the source
    structure for a future pipeline where multiple hunters or analysts can argue
    competing interpretations before a judge/verifier consolidates findings.
    """

    name = "debate_based"

    def build_debate_roles(self):
        return {
            "proposer": "Construct the strongest evidence-backed interpretation of the incident.",
            "challenger": "Challenge unsupported claims, missing IOCs, weak MITRE mappings, and task drift.",
            "judge": "Resolve disagreements using only raw artifacts, tool outputs, and verified evidence.",
        }

    def build_round_contract(self):
        return {
            "round_input": [
                "task",
                "raw_log_or_slice",
                "tool_outputs",
                "previous_arguments",
                "verifier_feedback",
            ],
            "round_output": [
                "claim",
                "supporting_evidence",
                "challenged_points",
                "required_fixes",
                "confidence",
            ],
        }

    def describe(self):
        return (
            "Debate-based collaboration lets multiple role-specialized agents produce, challenge, "
            "and judge SOC findings before the final analyst/reporter stages consume them."
        )
