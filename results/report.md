# Evaluation report

Generated 2026-11-07T16:55:09+00:00 from commit `659cfb9709af+dirty`. Every number below is read from `metrics.json`.

Dataset: AIT Log Data Set V2.0, scenario russellmitchell, intranet_server Apache access log (CC-BY-NC-SA-4.0). Split: train 2014 / validation 817 / test 8299 lines (7695 attack, prevalence 0.927).
Threshold: 99% quantile of benign validation scores. Mean over seeds [0, 1, 2, 3, 4] (std in parentheses; rule baseline is deterministic). PR-AUC of a random scorer equals the prevalence (0.927).

## Variant `all_features` (pre-registered, held-out)

| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR (test benign) | FPR (other hosts) |
|---|---|---|---|---|---|---|---|
| rule_requests_per_60s | 1.000 (0.000) | 0.998 (0.000) | 0.999 (0.000) | 1.000 (0.000) | 0.999 (0.000) | 0.000 (0.000) | 0.5572 (0.0000) |
| isolation_forest | 0.999 (0.000) | 0.999 (0.001) | 0.999 (0.000) | 1.000 (0.000) | 1.000 (0.001) | 0.016 (0.006) | 0.0002 (0.0003) |
| combined_rule_or_isolation_forest | 0.999 (0.000) | 0.999 (0.000) | 0.999 (0.000) | 1.000 (0.000) | 0.998 (0.002) | 0.016 (0.006) | 0.5572 (0.0001) |
| ensemble_legacy_weights_0.5_0.3_0.2 | 0.999 (0.000) | 0.999 (0.001) | 0.999 (0.000) | 1.000 (0.000) | 1.000 (0.001) | 0.016 (0.006) | 0.0002 (0.0003) |
| component_dbscan_only | 0.000 (0.000) | 0.000 (0.000) | 0.000 (0.000) | 0.927 (0.000) | 0.500 (0.000) | 0.000 (0.000) | 0.0000 (0.0000) |
| component_gmm_only | 0.000 (0.000) | 0.000 (0.000) | 0.000 (0.000) | 0.927 (0.000) | 0.500 (0.000) | 0.000 (0.000) | 0.0000 (0.0000) |

Recall by attack type (n in header):

| Model | service_scan (n=12) | dirb (n=4462) | wpscan (n=3186) | webshell_upload (n=3) | webshell_cmd (n=32) | escalate (n=4) |
|---|---|---|---|---|---|---|
| rule_requests_per_60s | 0.000 | 0.998 | 1.000 | 1.000 | 1.000 | 1.000 |
| isolation_forest | 0.717 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| combined_rule_or_isolation_forest | 0.717 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| ensemble_legacy_weights_0.5_0.3_0.2 | 0.717 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| component_dbscan_only | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| component_gmm_only | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |

Attacks invisible to the volume rule (per-IP requests in 60 s within the benign validation range; n=19):

| Model | Recall |
|---|---|
| rule_requests_per_60s | 0.000 (0.000), Wilson 95% [0.00, 0.17] |
| isolation_forest | 0.779 (0.164), Wilson 95% [0.57, 0.91] |
| combined_rule_or_isolation_forest | 0.768 (0.184), Wilson 95% [0.57, 0.91] |
| ensemble_legacy_weights_0.5_0.3_0.2 | 0.779 (0.164), Wilson 95% [0.57, 0.91] |
| component_dbscan_only | 0.000 (0.000), Wilson 95% [0.00, 0.17] |
| component_gmm_only | 0.000 (0.000), Wilson 95% [0.00, 0.17] |

## Variant `no_calendar_features` (POST-HOC, in-sample design decision)

Dropped features: day_of_week, is_weekend.

| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR (test benign) | FPR (other hosts) |
|---|---|---|---|---|---|---|---|
| rule_requests_per_60s | 1.000 (0.000) | 0.998 (0.000) | 0.999 (0.000) | 1.000 (0.000) | 0.999 (0.000) | 0.000 (0.000) | 0.5572 (0.0000) |
| isolation_forest | 0.999 (0.000) | 1.000 (0.000) | 0.999 (0.000) | 1.000 (0.000) | 1.000 (0.000) | 0.016 (0.004) | 0.0001 (0.0001) |
| combined_rule_or_isolation_forest | 0.999 (0.000) | 1.000 (0.000) | 0.999 (0.000) | 1.000 (0.000) | 1.000 (0.000) | 0.015 (0.004) | 0.5573 (0.0001) |
| ensemble_legacy_weights_0.5_0.3_0.2 | 0.999 (0.000) | 1.000 (0.000) | 0.999 (0.000) | 1.000 (0.000) | 1.000 (0.000) | 0.018 (0.002) | 0.5796 (0.0250) |
| component_dbscan_only | 0.000 (0.000) | 0.000 (0.000) | 0.000 (0.000) | 0.970 (0.000) | 0.805 (0.000) | 0.000 (0.000) | 0.0000 (0.0000) |
| component_gmm_only | 0.999 (0.000) | 1.000 (0.000) | 0.999 (0.000) | 1.000 (0.000) | 0.998 (0.001) | 0.013 (0.001) | 0.8608 (0.0146) |

Recall by attack type (n in header):

| Model | service_scan (n=12) | dirb (n=4462) | wpscan (n=3186) | webshell_upload (n=3) | webshell_cmd (n=32) | escalate (n=4) |
|---|---|---|---|---|---|---|
| rule_requests_per_60s | 0.000 | 0.998 | 1.000 | 1.000 | 1.000 | 1.000 |
| isolation_forest | 0.850 | 1.000 | 1.000 | 1.000 | 0.994 | 0.950 |
| combined_rule_or_isolation_forest | 0.850 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| ensemble_legacy_weights_0.5_0.3_0.2 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| component_dbscan_only | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| component_gmm_only | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |

Attacks invisible to the volume rule (per-IP requests in 60 s within the benign validation range; n=19):

| Model | Recall |
|---|---|
| rule_requests_per_60s | 0.000 (0.000), Wilson 95% [0.00, 0.17] |
| isolation_forest | 0.905 (0.039), Wilson 95% [0.69, 0.97] |
| combined_rule_or_isolation_forest | 0.905 (0.039), Wilson 95% [0.69, 0.97] |
| ensemble_legacy_weights_0.5_0.3_0.2 | 1.000 (0.000), Wilson 95% [0.83, 1.00] |
| component_dbscan_only | 0.000 (0.000), Wilson 95% [0.00, 0.17] |
| component_gmm_only | 1.000 (0.000), Wilson 95% [0.83, 1.00] |

Types with a handful of lines (e.g. `escalate`, `webshell_upload`) have no statistical power; treat their recall as anecdotal.
