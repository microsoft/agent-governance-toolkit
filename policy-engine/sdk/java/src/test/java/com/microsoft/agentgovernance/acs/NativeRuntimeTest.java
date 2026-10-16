// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

/** The binding against the real Rust engine: build, evaluate through host callbacks, close, fail closed. */
@EnabledIf("com.microsoft.agentgovernance.acs.NativeAvailability#available")
class NativeRuntimeTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** A manifest that sends `input` to a policy dispatcher; the dispatcher (here: Java) answers. */
    static final String MANIFEST = """
            agent_control_specification_version: 0.4.0-alpha.1
            policies:
              p:
                type: rego
                query: data.acs.verdict
            intervention_points:
              input:
                policy:
                  id: p
                policy_target: $snap.input
            """;

    private static JsonNode json(String text) {
        try {
            return JSON.readTree(text);
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static NativeRuntime runtime(PolicyDispatcher policy) {
        return NativeRuntime.builder().manifestYaml(MANIFEST).policyDispatcher(policy).annotatorDispatcher((n, c, p) -> json("{}")).build();
    }

    @Test
    void aHostPolicyAllowsAndTheEngineReportsTheTargetAndAnIdentity() {
        List<JsonNode> seen = new ArrayList<>();
        try (NativeRuntime runtime = runtime(invocation -> {
            seen.add(invocation);
            return json("{\"decision\":\"allow\"}");
        })) {
            InterventionPointResult result = runtime.evaluate(new InterventionPointRequest(InterventionPoint.INPUT, json("{\"input\":{\"text\":\"hello\"}}")));

            assertEquals(Decision.ALLOW, result.verdict().decision());
            assertEquals("hello", result.policyInput().path("policy_target").path("value").path("text").asText());
            assertNotNull(result.enforcedIdentity());
            assertTrue(result.enforcedIdentity().startsWith("sha256:"), result.enforcedIdentity());
            assertEquals(1, seen.size(), "the policy was asked once");
        }
    }

    @Test
    void aHostPolicyThatDeniesIsADenyWithItsReason() {
        try (NativeRuntime runtime = runtime(invocation -> json("{\"decision\":\"deny\",\"reason\":\"blocked_by_test\"}"))) {
            InterventionPointResult result = runtime.evaluate(new InterventionPointRequest(InterventionPoint.INPUT, json("{\"input\":\"x\"}")));

            assertEquals(Decision.DENY, result.verdict().decision());
            assertEquals("blocked_by_test", result.verdict().reason());
        }
    }

    @Test
    void aHostPolicyThatThrowsFailsClosedAndTheJvmSurvives() {
        for (Throwable failure : new Throwable[] {new RuntimeException("boom"), new IllegalStateException("bad"), new StackOverflowError(), new AssertionError("no")}) {
            try (NativeRuntime runtime = runtime(invocation -> {
                if (failure instanceof Error error) {
                    throw error;
                }
                throw (RuntimeException) failure;
            })) {
                InterventionPointResult result = runtime.evaluate(new InterventionPointRequest(InterventionPoint.INPUT, json("{\"input\":\"x\"}")));

                assertEquals(Decision.DENY, result.verdict().decision(), failure.toString());
                assertTrue(result.verdict().reason().startsWith("runtime_error:"), result.verdict().reason());
            }
        }
    }

    @Test
    void aHostPolicyThatAnswersWithSomethingElseIsADeny() {
        try (NativeRuntime runtime = runtime(invocation -> json("[1,2,3]"))) {
            InterventionPointResult result = runtime.evaluate(new InterventionPointRequest(InterventionPoint.INPUT, json("{\"input\":\"x\"}")));

            assertEquals(Decision.DENY, result.verdict().decision());
        }
    }

    @Test
    void textWithNonAsciiCharactersSurvivesTheTripToTheEngineAndBack() {
        List<String> seen = new ArrayList<>();
        try (NativeRuntime runtime = runtime(invocation -> {
            seen.add(invocation.path("input").path("snapshot").path("input").asText());
            return json("{\"decision\":\"allow\"}");
        })) {
            String text = "café 日本語 😀 \"quoted\" \\ back\nline";
            InterventionPointResult result = runtime.evaluate(new InterventionPointRequest(InterventionPoint.INPUT,
                    JSON.createObjectNode().put("input", text)));

            assertEquals(Decision.ALLOW, result.verdict().decision());
            assertEquals(List.of(text), seen);
            assertEquals(text, result.policyInput().path("snapshot").path("input").asText());
        }
    }

    @Test
    void aNulInTheSnapshotTravelsEscapedAndANulInAManifestIsRefused() {
        List<String> seen = new ArrayList<>();
        try (NativeRuntime runtime = runtime(invocation -> {
            seen.add(invocation.path("input").path("snapshot").path("input").asText());
            return json("{\"decision\":\"allow\"}");
        })) {
            // JSON escapes the NUL (NUL), so the C string is not cut short and the policy sees all of it
            runtime.evaluate(new InterventionPointRequest(InterventionPoint.INPUT, JSON.createObjectNode().put("input", "a\0b")));

            assertEquals(List.of("a\0b"), seen);
        }
        // a manifest is passed as a C string as it is: a NUL would cut it, so it is refused
        assertThrows(IllegalArgumentException.class, () -> NativeRuntime.builder().manifestYaml("a\0b").build());
        assertThrows(IllegalArgumentException.class, () -> NativeRuntime.builder().manifestPath("a\0b").build());
    }

    @Test
    void aManifestThatDoesNotLoadIsAnExceptionWithTheEnginesReason() {
        AcsException missing = assertThrows(AcsException.class, () -> NativeRuntime.builder().manifestPath("no/such/manifest.yaml").build());
        assertTrue(missing.getMessage().contains("manifest"), missing.getMessage());

        AcsException broken = assertThrows(AcsException.class, () -> NativeRuntime.builder().manifestYaml("this: [is not\n").build());
        assertFalse(broken.getMessage().isBlank());
    }

    @Test
    void anUnknownInterventionPointInThePolicyIsADenyNotACrash() {
        try (NativeRuntime runtime = runtime(invocation -> json("{\"decision\":\"allow\"}"))) {
            // `output` is not configured in the manifest: the engine refuses it
            InterventionPointResult result = runtime.evaluate(new InterventionPointRequest(InterventionPoint.OUTPUT, json("{\"output\":\"x\"}")));

            assertEquals(Decision.DENY, result.verdict().decision());
        }
    }

    @Test
    void aClosedRuntimeRefusesToEvaluateAndClosingTwiceIsHarmless() {
        NativeRuntime runtime = runtime(invocation -> json("{\"decision\":\"allow\"}"));
        runtime.close();
        runtime.close();

        assertThrows(IllegalStateException.class, () -> runtime.evaluate(new InterventionPointRequest(InterventionPoint.INPUT, json("{\"input\":1}"))));
        assertThrows(IllegalStateException.class, runtime::policyLabels);
    }

    @Test
    void manyThreadsEvaluateAtOnceAndEveryCallbackAnswersItsOwnCaller() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        try (NativeRuntime runtime = runtime(invocation -> {
            calls.incrementAndGet();
            String value = invocation.path("input").path("snapshot").path("input").asText();
            return json("{\"decision\":\"" + (value.endsWith("deny") ? "deny" : "allow") + "\",\"reason\":\"" + value + "\"}");
        })) {
            ExecutorService pool = Executors.newFixedThreadPool(8);
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < 400; i++) {
                int n = i;
                results.add(pool.submit(() -> {
                    String value = n + (n % 3 == 0 ? "-deny" : "-allow");
                    InterventionPointResult result = runtime.evaluate(new InterventionPointRequest(InterventionPoint.INPUT,
                            JSON.createObjectNode().put("input", value)));
                    return value.equals(result.verdict().reason())
                            && result.verdict().decision() == (n % 3 == 0 ? Decision.DENY : Decision.ALLOW);
                }));
            }
            for (Future<Boolean> r : results) {
                assertTrue(r.get(60, TimeUnit.SECONDS));
            }
            pool.shutdown();
            assertEquals(400, calls.get());
        }
    }

    @Test
    void closingWaitsForEvaluationsInProgress() throws Exception {
        java.util.concurrent.CountDownLatch inside = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        NativeRuntime runtime = runtime(invocation -> {
            inside.countDown();
            release.await(30, TimeUnit.SECONDS);
            return json("{\"decision\":\"allow\"}");
        });
        ExecutorService pool = Executors.newFixedThreadPool(2);
        Future<InterventionPointResult> evaluation = pool.submit(() -> runtime.evaluate(new InterventionPointRequest(InterventionPoint.INPUT, json("{\"input\":1}"))));
        assertTrue(inside.await(30, TimeUnit.SECONDS));
        Future<?> closing = pool.submit(runtime::close);

        Thread.sleep(300);
        assertFalse(closing.isDone(), "close() must wait: the engine is in use");
        release.countDown();
        assertEquals(Decision.ALLOW, evaluation.get(30, TimeUnit.SECONDS).verdict().decision());
        closing.get(30, TimeUnit.SECONDS);
        pool.shutdown();
    }

    @Test
    void thePolicyLabelsNameThePolicyOfEveryConfiguredPoint() {
        try (NativeRuntime runtime = runtime(invocation -> json("{\"decision\":\"allow\"}"))) {
            JsonNode labels = runtime.policyLabels();

            assertTrue(labels.toString().contains("\"p\""), labels.toString());
        }
    }

    @Test
    void aManifestChainMergesAndTheLaterOneRefinesTheEarlier() {
        String base = MANIFEST;
        String refinement = "agent_control_specification_version: 0.4.0-alpha.1\nintervention_points:\n  output:\n    policy:\n      id: p\n    policy_target: $snap.output\n";
        try (NativeRuntime runtime = NativeRuntime.builder().manifestChain(List.of(base, refinement))
                .policyDispatcher(invocation -> json("{\"decision\":\"allow\"}")).annotatorDispatcher((n, c, p) -> json("{}")).build()) {

            assertEquals(Decision.ALLOW, runtime.evaluate(new InterventionPointRequest(InterventionPoint.INPUT, json("{\"input\":1}"))).verdict().decision());
            assertEquals(Decision.ALLOW, runtime.evaluate(new InterventionPointRequest(InterventionPoint.OUTPUT, json("{\"output\":1}"))).verdict().decision());
        }
    }

    @Test
    void evaluateOnlyReportsTheDecisionWithoutApplyingIt() {
        try (NativeRuntime runtime = runtime(invocation -> json("{\"decision\":\"deny\",\"reason\":\"would_block\"}"))) {
            InterventionPointResult result = runtime.evaluate(new InterventionPointRequest(InterventionPoint.INPUT, json("{\"input\":\"x\"}"),
                    EnforcementMode.EVALUATE_ONLY));

            assertEquals("would_block", result.verdict().reason());
        }
    }
}
