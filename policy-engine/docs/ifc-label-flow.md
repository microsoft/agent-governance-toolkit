# IFC label flow

ACS implements information flow control as a stateless label flow policy model. The core evaluates the configured policy at intervention points and does not store labels, propagate taint, or perform a built in IFC check.

The host owns provenance tracking. The host attaches labels to data as it moves through prompts, model calls, tool results, memory, and output preparation. At each sink the host calls ACS and supplies the labels for the data entering that sink in `input.snapshot.ifc.source_labels`.

The default snapshot field is `ifc.source_labels`. The value is an array of label strings. Missing labels, empty labels, unknown labels, and incomparable labels fail closed in the reference Rego library.

Tool clearance is manifest metadata. A tool can declare `clearance` as the maximum label it can receive. A tool can also declare `security_labels` to describe sink attributes or capabilities. The runtime projects both fields into `input.tool` without core changes.

The library package `agent_control_specification.lib.ifc` provides the default lattice `public < internal < confidential < secret`. It also provides dominance, maximum sensitivity, allow verdict, and denial helpers. Integrators can pass their own lattice data object to support additional labels and partial orders.

Policies enforce no write down at the sink. The sink may receive data only when its clearance dominates the maximum sensitivity of every incoming source label. Otherwise the policy returns a deny verdict with reason `ifc_clearance_violation`.

The runtime returns propagated labels to the host. A policy MAY include `result_labels` in its output, an array of label strings describing the data the sink produced. The core returns this array verbatim in `verdict.result_labels` and does nothing else with it. It stores no labels and propagates no taint. The host persists the returned labels with the produced data, such as a tool result or a model output, and supplies them as `ifc.source_labels` on later evaluations whose policy target derives from that data. This carries label flow across turns while the runtime stays stateless. The library helpers `verdict_propagating` and `verdict_propagating_with_lattice` return an allow verdict whose `result_labels` is the join (maximum sensitivity) of the incoming source labels. These helpers assume a total-order sensitivity lattice and collapse the result to the single dominating label, which is the right default for ordered chains such as `public < internal < confidential < secret`. A policy over a richer lattice with independent compartments or categories (for example `pii` and `pci`) where no single input label dominates should emit `result_labels` directly rather than use these helpers, returning either the full set of source labels or an explicit joined label so no provenance is lost.

The model depends on complete host instrumentation. Uninstrumented paths, host side label loss, and sinks that do not call ACS are outside the ACS guarantee.
