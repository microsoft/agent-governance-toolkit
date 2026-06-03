using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using AgentControlSpecification;
using AgentControlSpecification.AgentFramework;

var control = AgentControl.FromPath(LiveAzure.PolicyPath);
var agent = new ChatClientAgent(LiveAzure.CreateClient().GetChatClient(LiveAzure.Deployment).AsIChatClient(), new ChatClientAgentOptions { Name = "acs-agentframework", UseProvidedChatClientAsIs = true }).UseAgentControl(control);
var allowed = await agent.RunAsync("Reply with exactly OK.");
if (string.IsNullOrWhiteSpace(allowed.Text)) throw new Exception("Agent Framework allow path returned empty content.");
try { _ = await agent.RunAsync("BLOCKME"); throw new Exception("Agent Framework input sentinel was not blocked."); }
catch (AgentControlBlockedException ex) when (ex.InterventionPoint == InterventionPoint.Input) { }
try { _ = await agent.RunAsync("Reply with exactly the single word made by joining BLOCK and ME. Do not add punctuation."); throw new Exception("Agent Framework output sentinel was not blocked."); }
catch (AgentControlBlockedException ex) when (ex.InterventionPoint is InterventionPoint.PostModelCall or InterventionPoint.Output) { }
Console.WriteLine("AgentFramework standalone integration passed");
