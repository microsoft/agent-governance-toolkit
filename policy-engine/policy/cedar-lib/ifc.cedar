// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// AGT stock IFC label flow library, Cedar mirror of
// `policy/lib/agt_ifc.rego`. The Rego library implements the AGT no
// write down rule against `input.snapshot.input.ifc.source_labels` at
// the `input` intervention point and against
// `input.snapshot.response.ifc.result_labels` at the `output`
// intervention point per AGT-SNAPSHOT-1.0.md sections 2.2 and 2.7.
//
// In the Cedar mirror the lattice closure is precomputed by the host
// and supplied as the resource entity attribute
// `clearance_dominated_labels`, a set of strings naming every label
// the sink clearance dominates. The Cedar set operator `.containsAll`
// then expresses the IFC rule cleanly. The forbid fires when the
// resource clearance does not dominate every source label on the
// snapshot.
//
// Cedar limit. Cedar cannot iterate over a set to compute lattice
// closures inside policy evaluation. Authors who want Cedar to pick
// the lattice at evaluation time precompute the closure into the
// resource entity attribute and reload entities when the lattice
// changes. Authors who need lattice agility stay on the Rego library
// `data.agt.ifc` which exposes `dominates_with_lattice` and
// `verdict_with_lattice` that take the lattice document at call
// time.
//
// Resource entity. The host loads the resource entity via the policy
// `entities_path` (D3.1). The entity matches the resource UID built
// by D3.2 (`PolicyTarget::"<kind>"` for the input and output
// intervention points). The set `clearance_dominated_labels` MUST
// include the sink clearance label itself when the lattice is
// reflexive, which the default AGT lattice in
// `policy/lib/agt_ifc.rego` is.

@id("ifc_clearance_violation_input")
forbid (
  principal,
  action == Action::"input",
  resource
) when {
  resource has clearance_dominated_labels &&
  context has input &&
  context.input has ifc &&
  context.input.ifc has source_labels &&
  !(resource.clearance_dominated_labels.containsAll(context.input.ifc.source_labels))
};

@id("ifc_clearance_violation_output")
forbid (
  principal,
  action == Action::"output",
  resource
) when {
  resource has clearance_dominated_labels &&
  context has response &&
  context.response has ifc &&
  context.response.ifc has result_labels &&
  !(resource.clearance_dominated_labels.containsAll(context.response.ifc.result_labels))
};

@id("ifc_clearance_violation_empty_input")
forbid (
  principal,
  action == Action::"input",
  resource
) when {
  resource has clearance_dominated_labels &&
  context has input &&
  context.input has ifc &&
  context.input.ifc has source_labels &&
  context.input.ifc.source_labels.isEmpty()
};

@id("ifc_clearance_violation_empty_output")
forbid (
  principal,
  action == Action::"output",
  resource
) when {
  resource has clearance_dominated_labels &&
  context has response &&
  context.response has ifc &&
  context.response.ifc has result_labels &&
  context.response.ifc.result_labels.isEmpty()
};
