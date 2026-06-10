using Microsoft.Extensions.AI;
using AgentControlSpecification;
using AgentControlSpecification.AI;

var control = AgentControl.FromPath(LiveAzure.PolicyPath);
var openAi = LiveAzure.CreateClient().GetChatClient(LiveAzure.Deployment).AsIChatClient();
var chat = openAi.UseAgentControl(control);
var allowed = await chat.GetResponseAsync([new ChatMessage(ChatRole.User, "Reply with exactly OK.")], new ChatOptions { MaxOutputTokens = 20 });
if (string.IsNullOrWhiteSpace(allowed.Text)) throw new Exception("AI allow path returned empty content.");
try { _ = await chat.GetResponseAsync([new ChatMessage(ChatRole.User, "BLOCKME")]); throw new Exception("AI input sentinel was not blocked."); }
catch (AgentControlBlockedException ex) when (ex.InterventionPoint == InterventionPoint.Input) { }
try { _ = await chat.GetResponseAsync([new ChatMessage(ChatRole.User, "Say hello.")], new ChatOptions { Instructions = "BLOCKME" }); throw new Exception("AI pre-model sentinel was not blocked."); }
catch (AgentControlBlockedException ex) when (ex.InterventionPoint == InterventionPoint.PreModelCall) { }
var postModelChat = new ChatClientBuilder(openAi).UseAgentControl(control).Use(async (messages, options, inner, ct) =>
{
    var response = await inner.GetResponseAsync(messages, options, ct).ConfigureAwait(false);
    response.ResponseId = "BLOCKME";
    return response;
}, (messages, options, inner, ct) => inner.GetStreamingResponseAsync(messages, options, ct)).Build();
try { _ = await postModelChat.GetResponseAsync([new ChatMessage(ChatRole.User, "Reply with exactly OK.")], new ChatOptions { MaxOutputTokens = 20 }); throw new Exception("AI post-model sentinel was not blocked."); }
catch (AgentControlBlockedException ex) when (ex.InterventionPoint == InterventionPoint.PostModelCall) { }
try { _ = await chat.GetResponseAsync([new ChatMessage(ChatRole.User, "Reply with exactly the single word made by joining BLOCK and ME. Do not add punctuation.")], new ChatOptions { MaxOutputTokens = 20 }); throw new Exception("AI output sentinel was not blocked."); }
catch (AgentControlBlockedException ex) when (ex.InterventionPoint == InterventionPoint.Output) { }
Console.WriteLine("AI standalone integration passed");
