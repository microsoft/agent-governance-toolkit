# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for native AGT information-flow-control primitives."""

from agent_os.policies.context_envelope import ContextEnvelope
from agent_os.policies.data_classification import DataClassification as DC
from agent_os.policies.information_flow import (
    InformationFlowRevealPolicy,
    InformationFlowLabel,
    InformationFlowSinkPolicy,
    InformationFlowViolation,
    IntegrityLabel,
    QuarantinedInformationFlowStore,
    acs_information_flow_annotation,
    declassify_label,
    default_unlabeled_source_label,
    endorse_label,
    enforce_sink,
    fold_information_flow_label,
    join_labels,
    label_from_payload,
    normalize_fides_additional_properties,
)


def _env(**kw) -> ContextEnvelope:
    base = dict(envelope_id="env1", workflow_id="wf1")
    base.update(kw)
    return ContextEnvelope(**base)


def test_parses_fides_compatible_additional_properties_label():
    label = label_from_payload(
        {
            "additional_properties": {
                "fides": {
                    "integrity": "untrusted",
                    "confidentiality": "user_identity",
                    "categories": ["pii"],
                    "source": "mail",
                }
            }
        }
    )

    assert label.integrity == "untrusted"
    assert label.confidentiality == DC.RESTRICTED
    assert label.categories == frozenset({"pii"})
    assert label.source == "mail"


def test_join_labels_keeps_untrusted_and_most_restrictive_confidentiality():
    joined = join_labels(
        [
            InformationFlowLabel(confidentiality=DC.INTERNAL, categories=frozenset({"internal"})),
            InformationFlowLabel(
                integrity="untrusted",
                confidentiality=DC.CONFIDENTIAL,
                categories=frozenset({"pii"}),
            ),
        ]
    )

    assert joined.integrity == "untrusted"
    assert joined.confidentiality == DC.CONFIDENTIAL
    assert joined.categories == frozenset({"internal", "pii"})


def test_fold_keeps_untrusted_integrity_sticky():
    env = _env(integrity="untrusted")

    folded = fold_information_flow_label(
        env,
        InformationFlowLabel(integrity="trusted", confidentiality=DC.PUBLIC),
    )

    assert folded.integrity == "untrusted"


def test_confidentiality_sink_denial():
    decision = enforce_sink(
        _env(aggregate_sensitivity=DC.CONFIDENTIAL),
        InformationFlowSinkPolicy(
            accepts_untrusted=True,
            max_allowed_confidentiality=DC.INTERNAL,
            name="public_export",
        ),
    )

    assert decision.allowed is False
    assert decision.violation is InformationFlowViolation.CONFIDENTIALITY_EXCEEDED


def test_strict_unlabeled_payload_defaults_to_untrusted_top_secret():
    label = label_from_payload({"content": "no metadata"})

    assert label == default_unlabeled_source_label()
    assert label.integrity == IntegrityLabel.UNTRUSTED
    assert label.confidentiality == DC.TOP_SECRET


def test_normalizes_agent_framework_fides_additional_properties():
    metadata = normalize_fides_additional_properties(
        {
            "additional_properties": {
                "content_label": {
                    "integrity": "untrusted",
                    "confidentiality": "private",
                    "labels": ["pii"],
                    "source": "agent_framework_tool",
                }
            }
        }
    )

    assert metadata == {
        "integrity": "untrusted",
        "confidentiality": "confidential",
        "categories": ["pii"],
        "source": "agent_framework_tool",
    }


def test_parses_security_label_and_source_integrity_aliases():
    label = label_from_payload(
        {
            "additional_properties": {
                "security_label": {
                    "source_integrity": "untrusted",
                    "confidentiality": "private",
                    "labels": ["pii"],
                }
            }
        }
    )

    assert label.integrity == IntegrityLabel.UNTRUSTED
    assert label.confidentiality == DC.CONFIDENTIAL
    assert label.categories == frozenset({"pii"})


def test_malformed_integrity_label_fails_closed():
    try:
        label_from_payload({"information_flow": {"integrity": "garbage"}})
    except ValueError as exc:
        assert "integrity" in str(exc)
    else:
        raise AssertionError("malformed integrity metadata should fail closed")


def test_quarantined_store_reveals_only_bounded_requested_fields():
    store = QuarantinedInformationFlowStore()
    label = InformationFlowLabel(
        integrity=IntegrityLabel.UNTRUSTED,
        confidentiality=DC.CONFIDENTIAL,
        categories=frozenset({"pii"}),
        source="mail",
    )
    handle = store.put(
        "mail-1",
        {"ticket_id": "T-123", "customer_email": "person@example.test"},
        label,
    )

    decision = store.reveal(
        handle,
        InformationFlowRevealPolicy(
            allowed_fields=frozenset({"ticket_id"}),
            requested_fields=frozenset({"ticket_id"}),
            max_output_chars=25,
            target_confidentiality=DC.PUBLIC,
            authority="support-policy",
            reason="ticket identifier is non-sensitive",
            authorization_reference="approval://support-policy/123",
            authorizer=lambda _label: True,
        ),
    )

    assert handle == "ifcvar://mail-1"
    assert store.get_label(handle) == label
    assert decision.allowed is True
    assert decision.value == {"ticket_id": "T-123"}
    assert decision.label.confidentiality == DC.PUBLIC
    assert decision.label.integrity == IntegrityLabel.UNTRUSTED
    assert decision.audit_event is not None
    assert decision.audit_event["operation"] == "reveal"


def test_reveal_preserves_source_label_without_explicit_target_label():
    store = QuarantinedInformationFlowStore()
    label = InformationFlowLabel(
        integrity=IntegrityLabel.UNTRUSTED,
        confidentiality=DC.CONFIDENTIAL,
    )
    store.put("mail-1", {"ticket_id": "T-123"}, label)

    decision = store.reveal(
        "mail-1",
        InformationFlowRevealPolicy(
            allowed_fields=frozenset({"ticket_id"}),
            requested_fields=frozenset({"ticket_id"}),
            authority="support-policy",
            reason="ticket identifier is safe to inspect",
            authorization_reference="approval://support-policy/123",
            authorizer=lambda _label: True,
        ),
    )

    assert decision.allowed is True
    assert decision.label.integrity == IntegrityLabel.UNTRUSTED
    assert decision.label.confidentiality == DC.CONFIDENTIAL


def test_quarantined_store_denies_unapproved_field_reveal():
    store = QuarantinedInformationFlowStore()
    store.put(
        "mail-1",
        {"ticket_id": "T-123", "customer_email": "person@example.test"},
        InformationFlowLabel(integrity="untrusted", confidentiality=DC.CONFIDENTIAL),
    )

    decision = store.reveal(
        "mail-1",
        InformationFlowRevealPolicy(
            allowed_fields=frozenset({"ticket_id"}),
            requested_fields=frozenset({"customer_email"}),
            max_output_chars=100,
            target_confidentiality=DC.PUBLIC,
            authority="support-policy",
            reason="attempt to reveal customer email",
            authorization_reference="approval://support-policy/123",
            authorizer=lambda _label: True,
        ),
    )

    assert decision.allowed is False
    assert decision.violation is InformationFlowViolation.REVEAL_FIELD_DENIED


def test_quarantined_store_denies_reveal_over_capacity():
    store = QuarantinedInformationFlowStore()
    store.put("mail-1", "long customer provided text", InformationFlowLabel())

    decision = store.reveal(
        "mail-1",
        InformationFlowRevealPolicy(
            max_output_chars=5,
            authority="support-policy",
            reason="bounded preview",
            authorization_reference="approval://support-policy/123",
            authorizer=lambda _label: True,
        ),
    )

    assert decision.allowed is False
    assert decision.violation is InformationFlowViolation.REVEAL_EXCEEDED


def test_declassification_requires_explicit_authorizer_approval():
    label = InformationFlowLabel(confidentiality=DC.CONFIDENTIAL)

    denied = declassify_label(label, DC.PUBLIC, authority="", reason="approved summary")
    denied_reference_only = declassify_label(
        label,
        DC.PUBLIC,
        authority="privacy-review",
        reason="approved aggregate summary",
        authorization_reference="approval://privacy-review/1",
    )
    allowed = declassify_label(
        label,
        DC.PUBLIC,
        authority="privacy-review",
        reason="approved aggregate summary",
        authorization_reference="approval://privacy-review/1",
        authorizer=lambda _label: True,
    )

    assert denied.allowed is False
    assert denied.violation is InformationFlowViolation.DECLASSIFICATION_DENIED
    assert denied_reference_only.allowed is False
    assert denied_reference_only.violation is InformationFlowViolation.DECLASSIFICATION_DENIED
    assert allowed.allowed is True
    assert allowed.label.confidentiality == DC.PUBLIC
    assert allowed.audit_event is not None
    assert allowed.audit_event["operation"] == "declassify"


def test_endorsement_requires_explicit_authorizer_approval():
    label = InformationFlowLabel(integrity=IntegrityLabel.UNTRUSTED)

    denied = endorse_label(label, authority="moderation", reason="")
    denied_reference_only = endorse_label(
        label,
        authority="moderation",
        reason="validated structured ticket id",
        authorization_reference="approval://moderation/1",
    )
    allowed = endorse_label(
        label,
        authority="moderation",
        reason="validated structured ticket id",
        authorization_reference="approval://moderation/1",
        authorizer=lambda _label: True,
    )

    assert denied.allowed is False
    assert denied.violation is InformationFlowViolation.ENDORSEMENT_DENIED
    assert denied_reference_only.allowed is False
    assert denied_reference_only.violation is InformationFlowViolation.ENDORSEMENT_DENIED
    assert allowed.allowed is True
    assert allowed.label.integrity == IntegrityLabel.TRUSTED
    assert allowed.audit_event is not None
    assert allowed.audit_event["operation"] == "endorse"


def test_builds_acs_information_flow_annotation_profile():
    annotation = acs_information_flow_annotation(
        label=InformationFlowLabel(
            integrity=IntegrityLabel.UNTRUSTED,
            confidentiality=DC.CONFIDENTIAL,
            categories=frozenset({"pii"}),
            source="email",
        ),
        envelope=_env(
            aggregate_sensitivity=DC.CONFIDENTIAL,
            integrity="untrusted",
            labels=frozenset({"pii"}),
            version=2,
        ),
        sink_policy=InformationFlowSinkPolicy(
            accepts_untrusted=False,
            max_allowed_confidentiality=DC.INTERNAL,
            name="send_email",
        ),
    )

    assert annotation["schema"] == "agt.ifc.annotation.v1"
    assert annotation["label"]["integrity"] == "untrusted"
    assert annotation["context"]["aggregate_sensitivity"] == "confidential"
    assert annotation["context"]["label_count"] == 1
    assert annotation["sink"]["max_allowed_confidentiality"] == "internal"
