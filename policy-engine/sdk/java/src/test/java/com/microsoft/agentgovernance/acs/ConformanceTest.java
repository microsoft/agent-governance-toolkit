// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.condition.EnabledIf;
import org.opentest4j.TestAbortedException;

/**
 * Runs the shared conformance corpus ({@code tests/conformance/cases}) through the Java binding, the way the Python runner
 * ({@code tests/conformance/run_python.py}) does: the policy and annotator answers come from the case, the engine does the rest.
 * A case that does not name {@code java} in {@code sdk_support} is treated as the {@code dotnet} entry says (the other SDK over the same
 * C ABI); {@code skip} skips it.
 */
@EnabledIf("com.microsoft.agentgovernance.acs.NativeAvailability#available")
class ConformanceTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** case id -> {status, detail}; written to {@code ACS_CONFORMANCE_RESULTS} (if set) in the format of {@code tests/conformance/run_parity.py}. */
    private static final Map<String, String[]> RESULTS = new ConcurrentHashMap<>();

    @TestFactory
    Stream<DynamicTest> everyCaseOfTheSharedCorpus() throws IOException {
        Path dir = NativeAvailability.policyEngineDir().resolve("tests/conformance/cases");
        assertTrue(Files.isDirectory(dir), "the conformance corpus is at " + dir);
        List<Path> files;
        try (Stream<Path> list = Files.list(dir)) {
            files = list.filter(p -> p.getFileName().toString().endsWith(".json")).sorted().toList();
        }
        assertTrue(files.size() >= 20, "the corpus has cases: " + files.size());
        List<DynamicTest> tests = new ArrayList<>();
        for (Path file : files) {
            JsonNode testCase = JSON.readTree(file.toFile());
            tests.add(DynamicTest.dynamicTest(testCase.path("id").asText(file.getFileName().toString()), () -> record(testCase.path("id").asText(), testCase)));
        }
        return tests.stream();
    }

    private static void record(String id, JsonNode testCase) throws Exception {
        try {
            run(testCase);
            RESULTS.put(id, new String[] {"pass", ""});
        } catch (TestAbortedException e) {
            RESULTS.put(id, new String[] {"skip", String.valueOf(e.getMessage())});
            throw e;
        } catch (Throwable e) {
            RESULTS.put(id, new String[] {"fail", String.valueOf(e.getMessage())});
            throw e;
        }
    }

    @AfterAll
    static void writeResults() throws IOException {
        String target = System.getenv("ACS_CONFORMANCE_RESULTS");
        if (target == null || target.isBlank()) {
            return;
        }
        var report = JSON.createObjectNode();
        report.put("sdk", "java");
        report.put("timestamp", java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString());
        var results = report.putArray("results");
        RESULTS.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(e -> {
            var item = results.addObject();
            item.put("case", e.getKey());
            item.put("status", e.getValue()[0]);
            item.put("detail", e.getValue()[1]);
        });
        Path out = Path.of(target);
        if (out.getParent() != null) {
            Files.createDirectories(out.getParent());
        }
        Files.writeString(out, JSON.writerWithDefaultPrettyPrinter().writeValueAsString(report) + "\n");
    }

    private static void run(JsonNode testCase) throws Exception {
        // a case that does not name java is treated as it is for dotnet, the other SDK that binds the same C ABI
        JsonNode support = testCase.path("sdk_support");
        String mine = support.has("java") ? support.path("java").asText() : support.path("dotnet").asText("optional");
        Assumptions.assumeFalse("skip".equals(mine), "the case excludes this SDK");
        String operation = testCase.path("operation").asText();
        switch (operation) {
            case "evaluate" -> runEvaluate(testCase);
            case "approval_action_mismatch" -> runApprovalMismatch(testCase);
            default -> Assumptions.abort("unsupported operation " + operation);
        }
    }

    private static void runEvaluate(JsonNode testCase) throws Exception {
        List<String> seenAnnotators = new ArrayList<>();
        JsonNode expected = testCase.path("expected");
        InterventionPointResult result;
        try (NativeRuntime runtime = NativeRuntime.builder().manifestYaml(testCase.path("manifest_yaml").asText())
                .annotatorDispatcher((name, config, preliminary) -> {
                    seenAnnotators.add(name);
                    JsonNode outputs = testCase.path("annotator_outputs").get(name);
                    return outputs != null ? outputs : JSON.readTree("{\"ok\":true}");
                })
                .policyDispatcher(invocation -> {
                    if ("error".equals(testCase.path("policy_behavior").asText())) {
                        throw new IllegalStateException("policy failed");
                    }
                    return testCase.path("policy_response");
                })
                .build()) {
            EnforcementMode mode = "evaluate_only".equals(testCase.path("mode").asText("enforce")) ? EnforcementMode.EVALUATE_ONLY : EnforcementMode.ENFORCE;
            result = runtime.evaluate(new InterventionPointRequest(InterventionPoint.fromWireName(testCase.path("intervention_point").asText()),
                    testCase.path("snapshot"), mode));
        } catch (AcsException e) {
            // an engine failure that is the expected deny (the Python runner accepts the reserved reason in the message)
            Matcher reason = Pattern.compile("runtime_error:[a-z_]+").matcher(e.getMessage());
            if ("deny".equals(expected.path("decision").asText()) && reason.find() && reason.group().equals(expected.path("reason").asText())) {
                return;
            }
            throw e;
        }

        assertEquals(expected.path("decision").asText(), result.verdict().decision().wireName(), "decision");
        if (expected.has("reason")) {
            assertEquals(expected.path("reason").asText(), result.verdict().reason(), "reason");
        }
        if (expected.has("transformed_policy_target")) {
            JsonNode target = expected.get("transformed_policy_target");
            assertEquals(target.isNull() ? null : target, result.transformedPolicyTarget(), "transformed policy target");
        }
        if (expected.has("policy_target")) {
            assertEquals(expected.get("policy_target"), result.policyInput().path("policy_target").path("value"), "policy target");
        }
        if (expected.has("annotations")) {
            assertEquals(expected.get("annotations"), result.policyInput().path("annotations"), "annotations");
        }
        if (expected.has("annotator_order")) {
            List<String> order = new ArrayList<>();
            expected.get("annotator_order").forEach(n -> order.add(n.asText()));
            assertEquals(order, seenAnnotators, "annotator order");
        }
        if ("present".equals(expected.path("action_identity").asText())) {
            assertNotNull(result.actionIdentity(), "an action identity is reported");
            assertTrue(result.actionIdentity().startsWith("sha256:"), result.actionIdentity());
        }
    }

    /**
     * An approval that names another action than the one the engine reported must block with {@code host_error:approval_identity_mismatch}.
     * (The Python runner provokes it by changing the result in place; a Java resolver gets a copy, so it names a different identity.)
     */
    private static void runApprovalMismatch(JsonNode testCase) throws IOException {
        JsonNode policyInput = JSON.readTree("{\"intervention_point\":\"input\",\"snapshot\":{\"input\":\"hi\"}}");
        AgentControlRuntime runtime = request -> new InterventionPointResult(
                new Verdict(Decision.DENY, "human_review", null, null, null, null, null, JSON.createObjectNode()),
                null, policyInput, "sha256:aaaa", false, "sha256:aaaa", "sha256:aaaa");
        AgentControl control = new AgentControl(runtime, (point, result) -> {
            result.policyInput().deepCopy(); // whatever the resolver does to what it was given...
            return ApprovalResolution.allow("sha256:bbbb"); // ...it consents to some other action
        });

        AgentControlBlockedException blocked = org.junit.jupiter.api.Assertions.assertThrows(AgentControlBlockedException.class,
                () -> control.run(JSON.getNodeFactory().textNode("hi"), value -> value));

        assertEquals(testCase.path("expected").path("reason").asText(), blocked.result().verdict().reason());
    }
}
