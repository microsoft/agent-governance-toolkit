# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.confidence_test

import data.agt.confidence
import rego.v1

test_score_reads_annotation if {
	confidence.score == 0.92 with input as {"annotations": {"confidence": {"score": 0.92}}}
}

test_missing_annotation_does_not_deny if {
	not confidence.deny_if_low_confidence(0.5) with input as {"annotations": {}}
	not confidence.deny_if_low_confidence(0.5) with input as {}
}

test_score_above_threshold_does_not_deny if {
	not confidence.deny_if_low_confidence(0.5) with input as {"annotations": {"confidence": {"score": 0.9}}}
}

test_score_at_threshold_does_not_deny if {
	not confidence.deny_if_low_confidence(0.5) with input as {"annotations": {"confidence": {"score": 0.5}}}
}

test_score_below_threshold_denies if {
	verdict := confidence.deny_if_low_confidence(0.5) with input as {"annotations": {"confidence": {"score": 0.2}}}
	verdict.decision == "deny"
	verdict.reason == "confidence_below_threshold"
}

test_non_numeric_score_does_not_deny if {
	not confidence.deny_if_low_confidence(0.5) with input as {"annotations": {"confidence": {"score": "high"}}}
}
