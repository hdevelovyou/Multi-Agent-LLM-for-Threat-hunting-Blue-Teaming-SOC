# Prompting Layer

This folder centralizes prompt construction for the five main SOC agents without
changing the current hierarchical pipeline in `main.py`.

## Structure

```text
prompts/
  agent_prompts.py
  techniques/
    role_based_zero_shot/
      coordinator.md
      hunter.md
      verifier.md
      analyst.md
      reporter.md
    chain_of_thought/
      coordinator.md
      hunter.md
      verifier.md
      analyst.md
      reporter.md
    example_based_fewshot/
      coordinator.md
      hunter.md
      verifier.md
      analyst.md
      reporter.md
```

Every prompt file contains:

```text
## System Prompt
...

## Human Prompt
...
```

`agent_prompts.py` selects the active technique, loads the matching agent prompt
file, extracts the system/human sections, and passes them into the existing
agent code.

## Supported Techniques

- `role_based_zero_shot`
- `chain_of_thought`
- `example_based_fewshot`

## Selection

Use a global technique:

```powershell
$env:PROMPT_TECHNIQUE="chain_of_thought"
python main.py
```

Or override one agent:

```powershell
$env:HUNTER_PROMPT_TECHNIQUE="example_based_fewshot"
python main.py
```

Agent-specific variables:

- `COORDINATOR_PROMPT_TECHNIQUE`
- `HUNTER_PROMPT_TECHNIQUE`
- `VERIFIER_PROMPT_TECHNIQUE`
- `ANALYST_PROMPT_TECHNIQUE`
- `REPORTER_PROMPT_TECHNIQUE`

Agent-specific variables override `PROMPT_TECHNIQUE`. Unknown values fall back
to `role_based_zero_shot`.

The current `main.py` collaboration flow remains hierarchical. Debate-based
collaboration is scaffolded under `strategies/debate_strategy.py` but is not
wired into runtime execution yet.
