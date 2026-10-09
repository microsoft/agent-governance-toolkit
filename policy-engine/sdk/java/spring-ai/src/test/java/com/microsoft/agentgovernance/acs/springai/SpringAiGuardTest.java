// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs.springai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.agentgovernance.acs.AgentControl;
import com.microsoft.agentgovernance.acs.AgentControlBlockedException;
import com.microsoft.agentgovernance.acs.AgentControlRuntime;
import com.microsoft.agentgovernance.acs.Decision;
import com.microsoft.agentgovernance.acs.InterventionPoint;
import com.microsoft.agentgovernance.acs.InterventionPointResult;
import com.microsoft.agentgovernance.acs.Verdict;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.ai.chat.client.advisor.api.CallAdvisorChain;
import org.springframework.ai.chat.client.advisor.api.StreamAdvisorChain;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.definition.ToolDefinition;
import reactor.core.publisher.Flux;

class SpringAiGuardTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** An engine that answers per intervention point and remembers what it was asked. */
    private static AgentControl control(List<InterventionPoint> asked, Function<InterventionPoint, Decision> decide) {
        AgentControlRuntime runtime = request -> {
            asked.add(request.interventionPoint());
            Decision decision = decide.apply(request.interventionPoint());
            return InterventionPointResult.of(Verdict.of(decision, decision == Decision.ALLOW ? null : "policy_" + decision.wireName(), null));
        };
        return new AgentControl(runtime);
    }

    private static ToolCallback tool(String name, List<String> received, String answer) {
        ToolDefinition definition = ToolDefinition.builder().name(name).description(name).inputSchema("{}").build();
        return new ToolCallback() {
            @Override
            public ToolDefinition getToolDefinition() {
                return definition;
            }

            @Override
            public String call(String toolInput) {
                received.add(toolInput);
                return answer;
            }
        };
    }

    @Test
    void anAllowedToolRunsAndBothSidesAreAsked() {
        List<InterventionPoint> asked = new ArrayList<>();
        List<String> received = new ArrayList<>();
        ToolCallback guarded = new GuardedToolCallback(control(asked, p -> Decision.ALLOW), tool("search", received, "{\"hits\":2}"));

        String answer = guarded.call("{\"q\":\"cats\"}");

        assertEquals(List.of("{\"q\":\"cats\"}"), received);
        assertEquals("{\"hits\":2}", answer);
        assertEquals(List.of(InterventionPoint.PRE_TOOL_CALL, InterventionPoint.POST_TOOL_CALL), asked);
        assertEquals("search", guarded.getToolDefinition().name());
    }

    @Test
    void aDeniedToolDoesNotRunAndTheModelIsToldWhy() {
        List<String> received = new ArrayList<>();
        ToolCallback guarded = new GuardedToolCallback(control(new ArrayList<>(), p -> Decision.DENY), tool("drop", received, "x"));

        String answer = guarded.call("{}");

        assertTrue(received.isEmpty());
        assertTrue(answer.startsWith("NOT EXECUTED"), answer);
        assertTrue(answer.contains("policy_deny"), answer);
    }

    @Test
    void aResultTheEngineDeniesIsNotHandedToTheModel() {
        List<String> received = new ArrayList<>();
        ToolCallback guarded = new GuardedToolCallback(control(new ArrayList<>(), p -> p == InterventionPoint.POST_TOOL_CALL ? Decision.DENY : Decision.ALLOW),
                tool("lookup", received, "secret rows"));

        String answer = guarded.call("{}");

        assertEquals(1, received.size(), "the tool ran, its result was refused");
        assertFalse(answer.contains("secret rows"));
        assertTrue(answer.startsWith("NOT EXECUTED"), answer);
    }

    @Test
    void argumentsThatAreNotJsonAreRefusedBeforeAnythingRuns() {
        List<InterventionPoint> asked = new ArrayList<>();
        List<String> received = new ArrayList<>();
        ToolCallback guarded = new GuardedToolCallback(control(asked, p -> Decision.ALLOW), tool("search", received, "x"));

        assertThrows(IllegalArgumentException.class, () -> guarded.call("not json"));

        assertTrue(asked.isEmpty());
        assertTrue(received.isEmpty());
    }

    @Test
    void theProviderGuardsEveryToolItOffers_theMcpAdapter() {
        List<InterventionPoint> asked = new ArrayList<>();
        List<String> received = new ArrayList<>();
        ToolCallbackProvider mcp = ToolCallbackProvider.from(tool("a", received, "1"), tool("b", received, "2"));

        ToolCallback[] guarded = new GuardedToolCallbackProvider(control(asked, p -> Decision.DENY), mcp).getToolCallbacks();

        assertEquals(2, guarded.length);
        for (ToolCallback callback : guarded) {
            assertTrue(callback.call("{}").startsWith("NOT EXECUTED"));
        }
        assertTrue(received.isEmpty());
    }

    // ------------------------------------------------------------------ advisor

    private static CallAdvisorChain chain(AtomicReference<ChatClientRequest> seen, String answer) {
        return (CallAdvisorChain) Proxy.newProxyInstance(CallAdvisorChain.class.getClassLoader(), new Class<?>[] {CallAdvisorChain.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("nextCall")) {
                        seen.set((ChatClientRequest) args[0]);
                        return ChatClientResponse.builder().chatResponse(new ChatResponse(List.of(new Generation(new AssistantMessage(answer))))).build();
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    @Test
    void theAdvisorAsksBeforeAndAfterTheModelAndLetsAnAllowThrough() {
        List<InterventionPoint> asked = new ArrayList<>();
        AtomicReference<ChatClientRequest> seen = new AtomicReference<>();
        AgentControlAdvisor advisor = new AgentControlAdvisor(control(asked, p -> Decision.ALLOW));

        ChatClientResponse response = advisor.adviseCall(ChatClientRequest.builder().prompt(new Prompt("hello")).build(), chain(seen, "hi there"));

        assertEquals("hi there", response.chatResponse().getResult().getOutput().getText());
        assertEquals(List.of(InterventionPoint.PRE_MODEL_CALL, InterventionPoint.POST_MODEL_CALL), asked);
    }

    @Test
    void aDeniedRequestNeverReachesTheModel() {
        AtomicReference<ChatClientRequest> seen = new AtomicReference<>();
        AgentControlAdvisor advisor = new AgentControlAdvisor(control(new ArrayList<>(), p -> Decision.DENY));

        assertThrows(AgentControlBlockedException.class,
                () -> advisor.adviseCall(ChatClientRequest.builder().prompt(new Prompt("hello")).build(), chain(seen, "x")));

        assertEquals(null, seen.get());
    }

    @Test
    void aTransformIsRefusedBecauseItCannotBeAppliedFaithfully() {
        AgentControlAdvisor advisor = new AgentControlAdvisor(control(new ArrayList<>(), p -> Decision.TRANSFORM));

        assertThrows(AgentControlBlockedException.class,
                () -> advisor.adviseCall(ChatClientRequest.builder().prompt(new Prompt("hello")).build(), chain(new AtomicReference<>(), "x")));
    }

    @Test
    void anAnswerTheEngineDeniesIsNotReturned() {
        AgentControlAdvisor advisor = new AgentControlAdvisor(control(new ArrayList<>(), p -> p == InterventionPoint.POST_MODEL_CALL ? Decision.DENY : Decision.ALLOW));

        assertThrows(AgentControlBlockedException.class,
                () -> advisor.adviseCall(ChatClientRequest.builder().prompt(new Prompt("hello")).build(), chain(new AtomicReference<>(), "leak")));
    }

    private static StreamAdvisorChain streamChain(List<String> chunks) {
        return (StreamAdvisorChain) Proxy.newProxyInstance(StreamAdvisorChain.class.getClassLoader(), new Class<?>[] {StreamAdvisorChain.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("nextStream")) {
                        return Flux.fromIterable(chunks).map(text -> ChatClientResponse.builder()
                                .chatResponse(new ChatResponse(List.of(new Generation(new AssistantMessage(text))))).build());
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    @Test
    void aStreamIsBufferedCheckedAsOneAnswerAndThenEmitted() {
        List<InterventionPoint> asked = new ArrayList<>();
        AgentControlAdvisor advisor = new AgentControlAdvisor(control(asked, p -> Decision.ALLOW));

        List<ChatClientResponse> out = advisor.adviseStream(ChatClientRequest.builder().prompt(new Prompt("hello")).build(),
                streamChain(List.of("a", "b", "c"))).collectList().block();

        assertEquals(3, out.size());
        assertEquals(List.of(InterventionPoint.PRE_MODEL_CALL, InterventionPoint.POST_MODEL_CALL), asked);
    }

    @Test
    void aStreamWhoseAnswerIsDeniedEmitsNothing() {
        AgentControlAdvisor advisor = new AgentControlAdvisor(control(new ArrayList<>(), p -> p == InterventionPoint.POST_MODEL_CALL ? Decision.DENY : Decision.ALLOW));
        List<ChatClientResponse> seen = new ArrayList<>();

        assertThrows(AgentControlBlockedException.class, () -> advisor.adviseStream(ChatClientRequest.builder().prompt(new Prompt("hello")).build(),
                streamChain(List.of("leak", "age"))).doOnNext(seen::add).collectList().block());

        assertTrue(seen.isEmpty(), "no chunk reached the caller");
    }

    @Test
    void theRequestIsShownToThePolicyAsMessages() throws Exception {
        JsonNode json = AgentControlAdvisor.requestJson(ChatClientRequest.builder().prompt(new Prompt("hello")).build());

        assertEquals(JSON.readTree("{\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}"), json);
    }
}
