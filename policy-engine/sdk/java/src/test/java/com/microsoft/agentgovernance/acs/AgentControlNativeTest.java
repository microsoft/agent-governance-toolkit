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
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

/** A tool call guarded end to end by the real engine: the identity an approval is bound to comes from the engine, not from a fake. */
@EnabledIf("com.microsoft.agentgovernance.acs.NativeAvailability#available")
class AgentControlNativeTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final String MANIFEST = """
            agent_control_specification_version: 0.4.0-alpha.1
            policies:
              p:
                type: rego
                query: data.acs.verdict
            intervention_points:
              pre_tool_call:
                tool_name_from: $snap.tool_call.name
                policy:
                  id: p
                policy_target: $snap.tool_call.args
              post_tool_call:
                tool_name_from: $snap.tool_call.name
                policy:
                  id: p
                policy_target: $snap.tool_result
            tools:
              search:
                type: Tool
              export:
                type: Tool
              drop:
                type: Tool
            """;

    private static JsonNode json(String text) {
        try {
            return JSON.readTree(text);
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /** The "policy": search is allowed, a query with "secret" in it is rewritten, export needs a person, drop is refused. */
    private static JsonNode decide(JsonNode invocation) {
        JsonNode input = invocation.path("input");
        if (!"pre_tool_call".equals(input.path("intervention_point").asText())) {
            return json("{\"decision\":\"allow\"}");
        }
        String tool = input.path("snapshot").path("tool_call").path("name").asText();
        JsonNode args = input.path("snapshot").path("tool_call").path("args");
        return switch (tool) {
            case "drop" -> json("{\"decision\":\"deny\",\"reason\":\"policy_denied\"}");
            case "export" -> json("{\"decision\":\"escalate\"}");
            default -> args.path("query").asText().contains("secret")
                    ? json("{\"decision\":\"transform\",\"transform\":{\"path\":\"$target.query\",\"value\":\"[redacted]\"}}")
                    : json("{\"decision\":\"allow\"}");
        };
    }

    private static AgentControl control(List<JsonNode> asked, ApprovalResolver resolver) {
        return AgentControl.builder().manifestYaml(MANIFEST)
                .annotatorDispatcher((name, config, preliminary) -> json("{}"))
                .policyDispatcher(invocation -> {
                    asked.add(invocation);
                    return decide(invocation);
                })
                .approvalResolver(resolver)
                .build();
    }

    @Test
    void anAllowedToolRunsAndBothSidesAreGuarded() {
        List<JsonNode> asked = new ArrayList<>();
        try (AgentControl control = control(asked, null)) {
            AgentControl.ToolRunResult run = control.runTool("search", json("{\"query\":\"cats\"}"), args -> json("{\"hits\":2}"),
                    AgentControl.Options.defaults().withToolCallId("call-7"));

            assertEquals(2, run.value().path("hits").asInt());
            assertEquals(2, asked.size(), "pre_tool_call and post_tool_call");
            assertEquals("call-7", asked.get(0).path("input").path("snapshot").path("tool_call").path("id").asText());
            assertEquals(2, asked.get(1).path("input").path("snapshot").path("tool_result").path("hits").asInt());
            assertNotNull(run.preToolCallResult().enforcedIdentity());
        }
    }

    @Test
    void aTransformOfOneArgumentReachesTheToolAndTheOtherArgumentsSurvive() {
        List<JsonNode> seen = new ArrayList<>();
        try (AgentControl control = control(new ArrayList<>(), null)) {
            AgentControl.ToolRunResult run = control.runTool("search", json("{\"query\":\"the secret plan\",\"limit\":5}"), args -> {
                seen.add(args);
                return json("{}");
            });

            assertEquals(Decision.TRANSFORM, run.preToolCallResult().verdict().decision());
            assertEquals(json("{\"query\":\"[redacted]\",\"limit\":5}"), seen.get(0), "the tool never saw the original query");
        }
    }

    @Test
    void aDeniedToolNeverRuns() {
        AtomicBoolean ran = new AtomicBoolean();
        try (AgentControl control = control(new ArrayList<>(), null)) {
            AgentControlBlockedException blocked = assertThrows(AgentControlBlockedException.class, () -> control.runTool("drop", json("{}"), args -> {
                ran.set(true);
                return json("{}");
            }));

            assertEquals("policy_denied", blocked.result().verdict().reason());
            assertFalse(ran.get());
        }
    }

    @Test
    void aToolTheManifestDoesNotKnowIsDeniedByTheEngineBeforeThePolicyIsAsked() {
        List<JsonNode> asked = new ArrayList<>();
        try (AgentControl control = control(asked, null)) {
            AgentControlBlockedException blocked = assertThrows(AgentControlBlockedException.class,
                    () -> control.runTool("rm_rf", json("{}"), args -> json("{}")));

            assertEquals("runtime_error:tool_unknown", blocked.result().verdict().reason());
            assertTrue(asked.isEmpty());
        }
    }

    @Test
    void anEscalationWithoutAResolverStandsAsADeny() {
        try (AgentControl control = control(new ArrayList<>(), null)) {
            AgentControlBlockedException blocked = assertThrows(AgentControlBlockedException.class,
                    () -> control.runTool("export", json("{\"table\":\"users\"}"), args -> json("{}")));

            assertEquals("host_error:approval_unresolved", blocked.result().verdict().reason());
        }
    }

    @Test
    void anApproverThatNamesTheEnginesIdentityLetsTheToolRun() {
        List<String> approved = new ArrayList<>();
        try (AgentControl control = control(new ArrayList<>(), (point, result) -> {
            assertEquals(InterventionPoint.PRE_TOOL_CALL, point);
            assertNotNull(result.verdict().approval(), "the deny carries an approval block");
            approved.add(result.actionIdentity());
            return ApprovalResolution.allow(result.actionIdentity());
        })) {
            AgentControl.ToolRunResult run = control.runTool("export", json("{\"table\":\"users\"}"), args -> json("{\"rows\":10}"));

            assertEquals(10, run.value().path("rows").asInt());
            assertEquals(1, approved.size());
            assertTrue(approved.get(0).startsWith("sha256:"), approved.get(0));
        }
    }

    @Test
    void anApprovalOfAnotherActionIsRefusedAndASuspensionHandsBackItsHandle() {
        AtomicBoolean ran = new AtomicBoolean();
        try (AgentControl wrong = control(new ArrayList<>(), (point, result) -> ApprovalResolution.allow("sha256:not-this-action"))) {
            AgentControlBlockedException blocked = assertThrows(AgentControlBlockedException.class, () -> wrong.runTool("export", json("{}"), args -> {
                ran.set(true);
                return json("{}");
            }));
            assertEquals("host_error:approval_identity_mismatch", blocked.result().verdict().reason());
            assertFalse(ran.get());
        }
        try (AgentControl suspending = control(new ArrayList<>(), (point, result) -> ApprovalResolution.suspend(json("{\"ticket\":\"T-1\"}"), result.actionIdentity()))) {
            AgentControlSuspendedException suspended = assertThrows(AgentControlSuspendedException.class,
                    () -> suspending.runTool("export", json("{}"), args -> json("{}")));
            assertEquals("T-1", suspended.handle().path("ticket").asText());
        }
    }

    @Test
    void theSameCallHasTheSameIdentityAndADifferentCallDoesNot() {
        try (AgentControl control = control(new ArrayList<>(), null)) {
            String first = control.evaluatePreToolCall("search", json("{\"query\":\"a\"}"), AgentControl.Options.defaults()).enforcedIdentity();
            String again = control.evaluatePreToolCall("search", json("{\"query\":\"a\"}"), AgentControl.Options.defaults()).enforcedIdentity();
            String other = control.evaluatePreToolCall("search", json("{\"query\":\"b\"}"), AgentControl.Options.defaults()).enforcedIdentity();

            assertEquals(first, again);
            assertFalse(first.equals(other));
        }
    }
}
