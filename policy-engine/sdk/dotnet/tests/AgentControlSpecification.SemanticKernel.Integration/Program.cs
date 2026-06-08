using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.ChatCompletion;
using AgentControlSpecification;
using AgentControlSpecification.SemanticKernel;

var control = AgentControl.FromPath(LiveAzure.PolicyPath);
var builder = Kernel.CreateBuilder().AddAzureOpenAIChatCompletion(LiveAzure.Deployment, Environment.GetEnvironmentVariable("AZURE_OPENAI_ENDPOINT")!, Environment.GetEnvironmentVariable("AZURE_OPENAI_API_KEY")!).UseAgentControl(control);
var kernel = builder.Build();
var chat = kernel.GetRequiredService<IChatCompletionService>();
var allowed = await chat.GetChatMessageContentAsync("Reply with exactly OK.", kernel: kernel);
if (string.IsNullOrWhiteSpace(allowed.Content)) throw new Exception("Semantic Kernel allow path returned empty content.");
try { _ = await chat.GetChatMessageContentAsync("BLOCKME", kernel: kernel); throw new Exception("Semantic Kernel input sentinel was not blocked."); }
catch (AgentControlBlockedException ex) when (ex.InterventionPoint == InterventionPoint.Input) { }
try { _ = await chat.GetChatMessageContentAsync("Reply with exactly the single word made by joining BLOCK and ME. Do not add punctuation.", kernel: kernel); throw new Exception("Semantic Kernel post-model sentinel was not blocked."); }
catch (AgentControlBlockedException ex) when (ex.InterventionPoint == InterventionPoint.PostModelCall) { }

var toolFilter = new AgentControlFilter(control);
var dangerFunction = KernelFunctionFactory.CreateFromMethod(() => "ok", "danger_tool");
var toolContext = new AutoFunctionInvocationContext(kernel, dangerFunction, new FunctionResult(dangerFunction), [], new Microsoft.SemanticKernel.ChatMessageContent()) { Arguments = [], ToolCallId = "sk-danger" };
try { await toolFilter.OnAutoFunctionInvocationAsync(toolContext, _ => Task.CompletedTask); throw new Exception("Semantic Kernel tool sentinel was not blocked."); }
catch (AgentControlBlockedException ex) when (ex.InterventionPoint == InterventionPoint.PreToolCall) { }
Console.WriteLine("SemanticKernel standalone integration passed");
