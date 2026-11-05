# Shopping-Assistant Experiment Package

Code and produced results for a controlled experiment on indirect prompt
injection in an AI shopping assistant, and on the server-side controls that
contain it. All data in this package is synthetic; no real platform, user or
payment data is involved.

## Scenario

Consumer A asks an AI assistant to compare products and check the status of
A's own order. Third-party product content carries an embedded instruction
that tries to make the assistant request **another consumer's** (B's) order.
Four stages are tracked separately: content read -> model request -> backend
return -> disclosure.

## Package layout

```
code/                    experiment code (Python 3.11)
evaluation_inputs/       frozen evaluation inputs (registered before execution)
results/                 produced results: summary, CSVs, figures, trajectories
results/trajectories/    per-trial records, glm/ and deepseek/
```

## Experiments

| Experiment | Question | Trials |
|---|---|---|
| Group B (enforcement) | Does a cross-account request return data when ownership checks are disabled vs enabled? | 8 cases x 2 configs |
| Group A (model) | Can malicious content induce an unauthorized order request? | 9 conditions x 3 reps = 27 |
| Attack ladder (exploratory) | Does the conclusion hold under stronger attack techniques? | 3 levels x 9 = 27 |
| IDS baseline | What does rule-based monitoring catch, and at what cost? | 8 labelled sequences |
| Cross-model | Do the conclusions depend on the model? | repeat of A + ladder with a second model (54 trials) |

## Key results

- Malicious content deterministically induced unauthorized cross-account order
  requests in the comparison-only configuration for glm-4-flash-250414
  (3/9 primary; 3/9 under L2 authority-override and L4 payload-splitting
  variants; 0/9 for the L3 fabricated-transcript variant); deepseek-flash
  produced none across all 54 trials.
- Every unauthorized request was rejected by server-side object-ownership
  checks before any order fields were returned (zero disclosure, both models).
- Under the induced failure baseline (ownership checks disabled), the same
  requests returned another consumer's order fields (2/2).
- The rule-based IDS flagged a burst of probing (TP) but missed a low-and-slow
  pattern (FN) and raised two false alarms on legitimate behaviour; precision
  1/3, recall 1/2 over 8 sequences (descriptive only).

See `results/RESULTS_SUMMARY.md` for details.

## Reproducing

Python 3.11; `pip install openai` for the model trials.

```bash
# no API key required:
cd code
python run_group_b.py     # enforcement comparison (X vs Y)
python run_ids.py         # IDS baseline sequences
python make_figures.py    # figures

# API key required (OpenAI-compatible endpoint):
export ZHIPU_API_KEY=...     # or DEEPSEEK_API_KEY=...
python run_group_a.py --full # 27 model trials
python run_ladder.py         # 27 attack-ladder trials
```

## API keys

All API keys used during the study **have been removed from this package**.
To reproduce the model trials (Group A + attack ladder), insert your own
OpenAI-compatible API key via the environment variables above, or contact the
team.

## Notes

- Evaluation inputs were frozen before execution and never modified
  afterwards; the exploratory ladder was registered separately and is reported
  separately from the primary trials.
- Outcomes under greedy decoding (temperature 0) are deterministic within each
  (attack, task) configuration; repetitions are therefore reported as
  configuration-level determinism, not as probability estimates.
- Offline replay validates rule and window logic only; no online latency is
  claimed.
