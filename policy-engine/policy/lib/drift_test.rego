# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.drift_test

import data.agt.drift
import rego.v1

test_score_reads_annotation if {
	drift.score == 0.7 with input as {"annotations": {"drift_score": 0.7}}
}

test_missing_score_does_not_match if {
	not drift.warn_if_drift(0.5) with input as {"annotations": {}}
	not drift.warn_if_drift(0.5) with input as {}
}

test_score_below_threshold_does_not_warn if {
	not drift.warn_if_drift(0.5) with input as {"annotations": {"drift_score": 0.2}}
}

test_score_at_threshold_warns if {
	verdict := drift.warn_if_drift(0.5) with input as {"annotations": {"drift_score": 0.5}}
	verdict.decision == "warn"
	verdict.reason == "drift_detected"
}

test_score_above_threshold_warns if {
	verdict := drift.warn_if_drift(0.4) with input as {"annotations": {"drift_score": 0.9}}
	verdict.decision == "warn"
	verdict.reason == "drift_detected"
}

test_non_numeric_score_does_not_warn if {
	not drift.warn_if_drift(0.5) with input as {"annotations": {"drift_score": "high"}}
}
