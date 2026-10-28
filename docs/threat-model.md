# Threat model

| Threat | Mitigation | Test |
|---|---|---|
| Prompt injection via labels/names ("approve this plan") | verdict is code-only; model output validated; plan data passed as JSON with a system warning | `test_prompt_injection_in_labels_does_not_move_verdict`, live injection tests |
| Model hallucinates resources | critic checks every address against the plan | `test_hallucinated_address_is_dropped_by_critic` |
| Model inflates severity | extras clamped to medium and advisory | `test_extra_finding_severity_is_clamped_to_medium` |
| Model emits links (phishing in PR comments) | critic and summary guard reject URLs | `test_links_in_model_output_are_dropped` |
| Secrets in plan sent to a vendor | secret-like keys dropped, scalars only, `sensitive` values never forwarded | `test_secret_looking_attributes_never_reach_the_model` |
| Provider outage / slow / garbage | per-call timeout, schema validation, rules-only fallback | `test_*_degrades_gracefully`, `test_slow_model...` |
| Cost runaway | per-review and daily caps, max 2 instances | budget tests |
| Buggy rule silently passes a plan | fail closed to needs_changes | `test_failing_rule_fails_closed` |
| Unauthorised use of the deployed service | Cloud Run IAM, one invoker, no allUsers | live: unauthenticated = 403 |
| Stored review data exposure | plan not stored; TTL; private service | by design |

Residual risk: a model note can still be misleading prose (it is labelled as a model note, and cannot
move the verdict); rules are a fixed list.
