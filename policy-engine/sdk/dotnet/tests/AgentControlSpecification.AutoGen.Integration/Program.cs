using AutoGen.Core;
using AutoGen.OpenAI;
using AutoGen.OpenAI.Extension;
using AgentControlSpecification;
using AgentControlSpecification.AutoGen;

var control = AgentControl.FromPath(LiveAzure.PolicyPath);
var agent = new OpenAIChatAgent(LiveAzure.CreateClient().GetChatClient(LiveAzure.Deployment), "acs-autogen", "Reply briefly.").RegisterMessageConnector().UseAgentControl(control);
var allowed = await agent.GenerateReplyAsync([new TextMessage(Role.User, "Reply with exactly OK.")]);
if (string.IsNullOrWhiteSpace(allowed.GetContent())) throw new Exception("AutoGen allow path returned empty content.");
try { _ = await agent.GenerateReplyAsync([new TextMessage(Role.User, "BLOCKME")]); throw new Exception("AutoGen input sentinel was not blocked."); }
catch (AgentControlBlockedException ex) when (ex.InterventionPoint == InterventionPoint.Input) { }
try { _ = await agent.GenerateReplyAsync([new TextMessage(Role.User, "Reply with exactly the single word made by joining BLOCK and ME. Do not add punctuation.")]); throw new Exception("AutoGen output sentinel was not blocked."); }
catch (AgentControlBlockedException ex) when (ex.InterventionPoint == InterventionPoint.Output) { }
try { _ = await agent.GenerateReplyAsync([new ToolCallMessage([new ToolCall("danger_tool", "{}") { ToolCallId = "call1" }], "assistant")]); throw new Exception("AutoGen tool sentinel was not blocked."); }
catch (AgentControlBlockedException ex) when (ex.InterventionPoint == InterventionPoint.PreToolCall) { }
Console.WriteLine("AutoGen standalone integration passed");
