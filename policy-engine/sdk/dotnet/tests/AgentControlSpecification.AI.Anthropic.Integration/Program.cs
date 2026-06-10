using Anthropic.SDK;
using Microsoft.Extensions.AI;
using AgentControlSpecification;
using AgentControlSpecification.AI;

var control = AgentControl.FromPath(SmokePolicy.Path);
IChatClient anthropic = new AnthropicClient(new APIAuthentication("not-used-for-local-policy-blocks")).Messages;
var chat = anthropic.UseAgentControl(control);
try { _ = await chat.GetResponseAsync([new ChatMessage(ChatRole.User, "BLOCKME")]); throw new Exception("Anthropic input sentinel was not blocked."); }
catch (AgentControlBlockedException ex) when (ex.InterventionPoint == InterventionPoint.Input) { }
try { _ = await chat.GetResponseAsync([new ChatMessage(ChatRole.User, "Say hello.")], new ChatOptions { Instructions = "BLOCKME" }); throw new Exception("Anthropic pre-model sentinel was not blocked."); }
catch (AgentControlBlockedException ex) when (ex.InterventionPoint == InterventionPoint.PreModelCall) { }
Console.WriteLine("Anthropic .AI integration passed");
