// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/** What the host layer does with the engine's answers, against a scripted runtime: no native library involved. */
class AgentControlTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private static JsonNode json(String text) {
        try {
            return JSON.readTree(text);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static final String IDENTITY = "sha256:0123";

    private static InterventionPointResult result(Verdict verdict) {
        return new InterventionPointResult(verdict, null, json("{\"intervention_point\":\"input\",\"snapshot\":{}}"), IDENTITY, false, IDENTITY, IDENTITY);
    }

    private static InterventionPointResult allow() {
        return result(Verdict.of(Decision.ALLOW, null, null));
    }

    private static InterventionPointResult deny(String reason) {
        return result(Verdict.of(Decision.DENY, reason, null));
    }

    private static InterventionPointResult liftable() {
        return result(new Verdict(Decision.DENY, "human_review", null, null, null, null, null, json("{}")));
    }

    /** A runtime that answers per intervention point and remembers the requests. */
    private static final class Script implements AgentControlRuntime {
        final List<InterventionPointRequest> requests = new ArrayList<>();
        final Function<InterventionPointRequest, InterventionPointResult> answer;

        Script(Function<InterventionPointRequest, InterventionPointResult> answer) {
            this.answer = answer;
        }

        @Override
        public InterventionPointResult evaluate(InterventionPointRequest request) {
            requests.add(request);
            return answer.apply(request);
        }
    }

    private static Script always(InterventionPointResult result) {
        return new Script(request -> result);
    }

    // ------------------------------------------------------------------ run

    @Test
    void anAllowedTurnRunsTheActionBetweenTheInputAndTheOutputGuards() {
        Script script = always(allow());
        AgentControl control = new AgentControl(script);

        AgentControl.RunResult run = control.run(json("\"hello\""), in -> json("\"answer to " + in.asText() + "\""));

        assertEquals("answer to hello", run.value().asText());
        assertEquals(List.of(InterventionPoint.INPUT, InterventionPoint.OUTPUT), script.requests.stream().map(InterventionPointRequest::interventionPoint).toList());
        assertEquals("hello", script.requests.get(0).snapshot().path("input").asText());
        assertEquals("hello", script.requests.get(1).snapshot().path("input").asText());
        assertEquals("answer to hello", script.requests.get(1).snapshot().path("output").asText());
    }

    @Test
    void aDeniedInputStopsBeforeTheActionRuns() {
        AtomicBoolean ran = new AtomicBoolean();
        AgentControl control = new AgentControl(always(deny("policy_violation")));

        AgentControlBlockedException blocked = assertThrows(AgentControlBlockedException.class, () -> control.run(json("\"x\""), in -> {
            ran.set(true);
            return in;
        }));

        assertFalse(ran.get());
        assertEquals(InterventionPoint.INPUT, blocked.interventionPoint());
        assertEquals("policy_violation", blocked.result().verdict().reason());
        assertTrue(blocked.getMessage().contains("input") && blocked.getMessage().contains("policy_violation"), blocked.getMessage());
    }

    @Test
    void aDeniedOutputKeepsTheResultFromTheCaller() {
        Script script = new Script(request -> request.interventionPoint() == InterventionPoint.OUTPUT ? deny("leak") : allow());
        AgentControl control = new AgentControl(script);

        AgentControlBlockedException blocked = assertThrows(AgentControlBlockedException.class, () -> control.run(json("\"x\""), in -> json("\"secret\"")));

        assertEquals(InterventionPoint.OUTPUT, blocked.interventionPoint());
    }

    @Test
    void evaluateOnlyNeverBlocksAndNeverTransforms() {
        Script script = always(new InterventionPointResult(new Verdict(Decision.TRANSFORM, null, null, new Transform("$target", json("\"CHANGED\"")), null, null, null, null),
                json("\"CHANGED\""), json("{\"policy_target\":{\"path\":\"$snap.input\"}}"), IDENTITY, true, IDENTITY, IDENTITY));
        AgentControl control = new AgentControl(script);
        AgentControl.Options options = AgentControl.Options.defaults().withMode(EnforcementMode.EVALUATE_ONLY);

        assertEquals("original", control.run(json("\"original\""), in -> in, options).value().asText());
        assertEquals(EnforcementMode.EVALUATE_ONLY, script.requests.get(0).mode());

        AgentControl denying = new AgentControl(always(deny("would_block")));
        assertEquals("x", denying.run(json("\"x\""), in -> in, options).value().asText(), "reported, not enforced");
    }

    @Test
    void aWarnStillPermitsTheAction() {
        AgentControl control = new AgentControl(always(result(Verdict.of(Decision.WARN, "careful", null))));

        assertEquals("x", control.run(json("\"x\""), in -> in).value().asText());
    }

    // ------------------------------------------------------------------ transforms

    @Test
    void aTransformOfTheWholeValueReplacesIt() {
        Script script = new Script(request -> request.interventionPoint() == InterventionPoint.INPUT
                ? new InterventionPointResult(new Verdict(Decision.TRANSFORM, null, null, null, null, null, null, null), json("\"redacted\""),
                        json("{\"policy_target\":{\"path\":\"$snap.input\"}}"), IDENTITY, true, IDENTITY, IDENTITY)
                : allow());
        AgentControl control = new AgentControl(script);
        List<String> seen = new ArrayList<>();

        control.run(json("\"my secret\""), in -> {
            seen.add(in.asText());
            return in;
        });

        assertEquals(List.of("redacted"), seen, "the action receives the transformed value");
        assertEquals("redacted", script.requests.get(1).snapshot().path("input").asText(), "and so does the output guard");
    }

    @Test
    void aTransformOfAPartIsSplicedIntoTheValueItCameFrom() {
        // the policy target was $snap.tool_call.args.query: only that member is replaced
        Script script = new Script(request -> request.interventionPoint() == InterventionPoint.PRE_TOOL_CALL
                ? new InterventionPointResult(new Verdict(Decision.TRANSFORM, null, null, null, null, null, null, null), json("\"clean query\""),
                        json("{\"policy_target\":{\"path\":\"$snap.tool_call.args.query\"}}"), IDENTITY, true, IDENTITY, IDENTITY)
                : allow());
        AgentControl control = new AgentControl(script);
        List<JsonNode> seen = new ArrayList<>();

        control.runTool("search", json("{\"query\":\"dirty\",\"limit\":5}"), args -> {
            seen.add(args);
            return json("[]");
        });

        assertEquals(json("{\"query\":\"clean query\",\"limit\":5}"), seen.get(0));
        assertEquals(json("{\"query\":\"clean query\",\"limit\":5}"), script.requests.get(1).snapshot().path("tool_call").path("args"));
    }

    @Test
    void aTransformThatTargetsSomethingOutsideTheValueBlocksTheActionInsteadOfRunningOnAWrongValue() {
        // the policy replaced the tool NAME, but the tool is run with its arguments: there is nothing sound to hand over
        Script script = new Script(request -> request.interventionPoint() == InterventionPoint.PRE_TOOL_CALL
                ? new InterventionPointResult(new Verdict(Decision.TRANSFORM, null, null, null, null, null, null, null), json("\"other_tool\""),
                        json("{\"policy_target\":{\"path\":\"$snap.tool_call.name\"}}"), IDENTITY, true, IDENTITY, IDENTITY)
                : allow());
        AtomicBoolean ran = new AtomicBoolean();

        AgentControlBlockedException blocked = assertThrows(AgentControlBlockedException.class,
                () -> new AgentControl(script).runTool("search", json("{\"q\":1}"), args -> {
                    ran.set(true);
                    return args;
                }));

        assertEquals("host_error:transform_target_unsupported", blocked.result().verdict().reason());
        assertFalse(ran.get());
    }

    @Test
    void aTransformOfAMemberThatIsNotThereBlocksToo() {
        InterventionPointResult transform = new InterventionPointResult(new Verdict(Decision.TRANSFORM, null, null, null, null, null, null, null),
                json("\"x\""), json("{\"policy_target\":{\"path\":\"$snap.input.missing.deep\"}}"), IDENTITY, true, IDENTITY, IDENTITY);

        assertThrows(AgentControlBlockedException.class,
                () -> AgentControl.transformedOr(InterventionPoint.INPUT, transform, json("{\"y\":2}"), EnforcementMode.ENFORCE, "input"));
    }

    @Test
    void aTransformOfAnArrayElementIsSplicedByIndex() {
        InterventionPointResult transform = new InterventionPointResult(new Verdict(Decision.TRANSFORM, null, null, null, null, null, null, null),
                json("\"[removed]\""), json("{\"policy_target\":{\"path\":\"$.model_request.messages[1].content\"}}"), IDENTITY, true, IDENTITY, IDENTITY);

        JsonNode spliced = AgentControl.transformedOr(InterventionPoint.PRE_MODEL_CALL, transform,
                json("{\"messages\":[{\"content\":\"a\"},{\"content\":\"secret\"}]}"), EnforcementMode.ENFORCE, "model_request");

        assertEquals(json("{\"messages\":[{\"content\":\"a\"},{\"content\":\"[removed]\"}]}"), spliced);
    }

    @Test
    void snapshotPathsAcceptBothSpellingsAndNothingElse() {
        assertEquals("tool_call.args.query", AgentControl.snapshotPath("$snap.tool_call.args.query"));
        assertEquals("input", AgentControl.snapshotPath("$.input"));
        assertNull(AgentControl.snapshotPath("input.text"));
        assertNull(AgentControl.snapshotPath(null));
    }

    // ------------------------------------------------------------------ approval

    @Test
    void aDenyThatCarriesApprovalCanBeLiftedByAResolverThatNamesTheSameAction() {
        AtomicBoolean ran = new AtomicBoolean();
        AgentControl control = new AgentControl(always(liftable()), (point, r) -> ApprovalResolution.allow(r.actionIdentity()));

        control.run(json("\"x\""), in -> {
            ran.set(true);
            return in;
        });

        assertTrue(ran.get());
    }

    @Test
    void anApprovalOfAnotherActionIsBlocked() {
        AgentControl control = new AgentControl(always(liftable()), (point, r) -> ApprovalResolution.allow("sha256:other"));

        AgentControlBlockedException blocked = assertThrows(AgentControlBlockedException.class, () -> control.run(json("\"x\""), in -> in));

        assertEquals("host_error:approval_identity_mismatch", blocked.result().verdict().reason());
    }

    @Test
    void anApprovalWithoutAnIdentityIsBlocked() {
        AgentControl control = new AgentControl(always(liftable()), (point, r) -> ApprovalResolution.allow(null));

        assertEquals("host_error:approval_identity_mismatch",
                assertThrows(AgentControlBlockedException.class, () -> control.run(json("\"x\""), in -> in)).result().verdict().reason());
    }

    @Test
    void aResolverThatDeniesBlocksWithTheEnginesVerdict() {
        AgentControl control = new AgentControl(always(liftable()), (point, r) -> ApprovalResolution.deny());

        AgentControlBlockedException blocked = assertThrows(AgentControlBlockedException.class, () -> control.run(json("\"x\""), in -> in));

        assertEquals("human_review", blocked.result().verdict().reason());
    }

    @Test
    void aResolverMaySuspendAndTheHandleComesBackToTheCaller() {
        JsonNode handle = json("{\"ticket\":\"T-42\"}");
        AgentControl control = new AgentControl(always(liftable()), (point, r) -> ApprovalResolution.suspend(handle, r.actionIdentity()));

        AgentControlSuspendedException suspended = assertThrows(AgentControlSuspendedException.class, () -> control.run(json("\"x\""), in -> in));

        assertSame(handle, suspended.handle());
        assertEquals(InterventionPoint.INPUT, suspended.interventionPoint());
        assertTrue(suspended.getMessage().contains("pending approval"), suspended.getMessage());
    }

    @Test
    void aResolverThatThrowsOrReturnsNothingFailsClosed() {
        AgentControl throwing = new AgentControl(always(liftable()), (point, r) -> {
            throw new IllegalStateException("approval service down");
        });
        AgentControlBlockedException blocked = assertThrows(AgentControlBlockedException.class, () -> throwing.run(json("\"x\""), in -> in));
        assertEquals("host_error:approval_resolver_failed", blocked.result().verdict().reason());
        assertInstanceOf(IllegalStateException.class, blocked.getCause());

        AgentControl nothing = new AgentControl(always(liftable()), (point, r) -> null);
        assertEquals("host_error:approval_resolver_failed",
                assertThrows(AgentControlBlockedException.class, () -> nothing.run(json("\"x\""), in -> in)).result().verdict().reason());
    }

    @Test
    void withoutAResolverALiftableDenyStands() {
        AgentControl control = new AgentControl(always(liftable()));

        assertEquals("host_error:approval_unresolved",
                assertThrows(AgentControlBlockedException.class, () -> control.run(json("\"x\""), in -> in)).result().verdict().reason());
    }

    @Test
    void aFinalDenyNeverAsksTheResolver() {
        AtomicBoolean asked = new AtomicBoolean();
        AgentControl control = new AgentControl(always(deny("final")), (point, r) -> {
            asked.set(true);
            return ApprovalResolution.allow(r.actionIdentity());
        });

        assertThrows(AgentControlBlockedException.class, () -> control.run(json("\"x\""), in -> in));

        assertFalse(asked.get());
    }

    @Test
    void theResolverOfACallOverridesTheOneOfTheControl() {
        AgentControl control = new AgentControl(always(liftable()), (point, r) -> ApprovalResolution.deny());

        AgentControl.RunResult run = control.run(json("\"x\""), in -> in,
                AgentControl.Options.defaults().withApprovalResolver((point, r) -> ApprovalResolution.allow(r.actionIdentity())));

        assertEquals("x", run.value().asText());
    }

    @Test
    void whateverTheResolverDoesToTheResultItWasGivenDoesNotChangeWhatIsEnforced() {
        Script script = always(liftable());
        AgentControl control = new AgentControl(script, (point, r) -> {
            ((ObjectNode) r.policyInput()).put("tampered", true);
            return ApprovalResolution.allow(r.actionIdentity());
        });

        AgentControl.RunResult run = control.run(json("\"x\""), in -> in);

        assertFalse(run.inputResult().policyInput().has("tampered"));
    }

    // ------------------------------------------------------------------ tools and models

    @Test
    void aToolCallIsGuardedOnBothSidesWithTheSameCallId() {
        Script script = always(allow());
        AgentControl control = new AgentControl(script);

        AgentControl.ToolRunResult run = control.runTool("search", json("{\"q\":\"x\"}"), args -> json("{\"hits\":3}"),
                AgentControl.Options.defaults().withToolCallId("call-1"));

        assertEquals(3, run.value().path("hits").asInt());
        JsonNode pre = script.requests.get(0).snapshot().path("tool_call");
        JsonNode post = script.requests.get(1).snapshot().path("tool_call");
        assertEquals(InterventionPoint.PRE_TOOL_CALL, script.requests.get(0).interventionPoint());
        assertEquals(InterventionPoint.POST_TOOL_CALL, script.requests.get(1).interventionPoint());
        assertEquals("search", pre.path("name").asText());
        assertEquals("call-1", pre.path("id").asText());
        assertEquals(pre, post);
        assertEquals(3, script.requests.get(1).snapshot().path("tool_result").path("hits").asInt());
    }

    @Test
    void aDeniedToolCallDoesNotRunTheTool() {
        AtomicBoolean ran = new AtomicBoolean();
        AgentControl control = new AgentControl(always(deny("tool_not_allowed")));

        assertThrows(AgentControlBlockedException.class, () -> control.runTool("rm", json("{}"), args -> {
            ran.set(true);
            return json("{}");
        }));

        assertFalse(ran.get());
    }

    @Test
    void aToolNameAndACallIdMustBeUsable() {
        AgentControl control = new AgentControl(always(allow()));

        assertThrows(IllegalArgumentException.class, () -> control.runTool(" ", json("{}"), args -> args));
        assertThrows(IllegalArgumentException.class, () -> AgentControl.Options.defaults().withToolCallId(""));
        assertThrows(NullPointerException.class, () -> control.runTool("t", json("{}"), null));
    }

    @Test
    void aStreamingModelRequestIsRefusedBeforeAnythingIsAsked() {
        Script script = always(allow());
        AgentControl control = new AgentControl(script);
        AtomicBoolean ran = new AtomicBoolean();

        AgentControlBlockedException blocked = assertThrows(AgentControlBlockedException.class, () -> control.runModel(json("{\"stream\":true}"), r -> {
            ran.set(true);
            return r;
        }, AgentControl.Options.defaults()));

        assertEquals("host_error:streaming_unsupported", blocked.result().verdict().reason());
        assertFalse(ran.get());
        assertTrue(script.requests.isEmpty());
    }

    @Test
    void aModelCallIsGuardedOnBothSides() {
        Script script = always(allow());
        AgentControl control = new AgentControl(script);

        AgentControl.ModelRunResult run = control.runModel(json("{\"prompt\":\"hi\"}"), request -> json("{\"text\":\"hello\"}"), AgentControl.Options.defaults());

        assertEquals("hello", run.value().path("text").asText());
        assertEquals("hi", script.requests.get(1).snapshot().path("model_request").path("prompt").asText());
        assertEquals("hello", script.requests.get(1).snapshot().path("model_response").path("text").asText());
    }

    @Test
    void ambientMembersOfTheSnapshotAreAddedToEveryRequest() {
        Script script = always(allow());
        AgentControl control = new AgentControl(script);

        control.run(json("\"x\""), in -> in, AgentControl.Options.defaults().withSnapshot(Map.of("user", json("{\"id\":\"u1\"}"))));

        assertEquals("u1", script.requests.get(0).snapshot().path("user").path("id").asText());
        assertEquals("u1", script.requests.get(1).snapshot().path("user").path("id").asText());
    }

    // ------------------------------------------------------------------ the guarded action

    @Test
    void aCheckedFailureInTheActionIsWrappedAndARuntimeFailureIsNot() {
        AgentControl control = new AgentControl(always(allow()));

        AgentControl.ActionExecutionException wrapped = assertThrows(AgentControl.ActionExecutionException.class,
                () -> control.run(json("\"x\""), in -> {
                    throw new IOException("disk full");
                }));
        assertInstanceOf(IOException.class, wrapped.getCause());
        assertThrows(IllegalStateException.class, () -> control.run(json("\"x\""), in -> {
            throw new IllegalStateException("bug");
        }));
    }

    @Test
    void theOutputIsNotJudgedWhenTheActionFails() {
        Script script = always(allow());
        AgentControl control = new AgentControl(script);

        assertThrows(RuntimeException.class, () -> control.run(json("\"x\""), in -> {
            throw new RuntimeException("failed");
        }));

        assertEquals(1, script.requests.size());
    }

    @Test
    void closingTheControlClosesARuntimeThatIsCloseable() {
        AtomicBoolean closed = new AtomicBoolean();
        class Closeable implements AgentControlRuntime, AutoCloseable {
            @Override
            public InterventionPointResult evaluate(InterventionPointRequest request) {
                return allow();
            }

            @Override
            public void close() {
                closed.set(true);
            }
        }
        new AgentControl(new Closeable()).close();
        new AgentControl(request -> allow()).close(); // a runtime that is not closeable is left alone

        assertTrue(closed.get());
    }

    @Test
    void theWireNamesRoundTrip() {
        for (InterventionPoint point : InterventionPoint.values()) {
            assertEquals(point, InterventionPoint.fromWireName(point.wireName()));
        }
        for (Decision decision : Decision.values()) {
            assertEquals(decision, Decision.fromWireName(decision.wireName()));
        }
        assertThrows(IllegalArgumentException.class, () -> InterventionPoint.fromWireName("pre_everything"));
        assertThrows(IllegalArgumentException.class, () -> Decision.fromWireName("maybe"));
        assertTrue(Decision.ALLOW.permits() && Decision.TRANSFORM.permits() && Decision.WARN.permits());
        assertFalse(Decision.DENY.permits() || Decision.ESCALATE.permits());
        assertTrue(InterventionPoint.PRE_TOOL_CALL.isToolInterventionPoint() && !InterventionPoint.INPUT.isToolInterventionPoint());
    }
}
