using System.Runtime.InteropServices;

namespace AgentControlSpecification.Interop;

internal static partial class NativeMethods
{
    internal const string NativeLibraryName = "agent_control_specification_core";

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate IntPtr AcsAnnotatorCallback(
        IntPtr annotatorName,
        IntPtr annotatorJson,
        IntPtr preliminaryPolicyInputJson,
        IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate IntPtr AcsPolicyCallback(
        IntPtr preparedInvocationJson,
        IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void AcsFreeResultCallback(IntPtr ptr, IntPtr userData);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_builder_from_path")]
    internal static extern IntPtr AcsBuilderFromPath(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        out IntPtr err);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_builder_from_yaml_chain")]
    internal static extern IntPtr AcsBuilderFromYamlChain(
        IntPtr yamls,
        nuint count,
        out IntPtr err);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_builder_from_yaml")]
    internal static extern IntPtr AcsBuilderFromYaml(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string yaml,
        out IntPtr err);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_builder_from_json")]
    internal static extern IntPtr AcsBuilderFromJson(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string json,
        out IntPtr err);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_builder_register_annotator_dispatcher")]
    internal static extern int AcsBuilderRegisterAnnotatorDispatcher(
        IntPtr builder,
        AcsAnnotatorCallback callback,
        AcsFreeResultCallback freeResult,
        IntPtr userData,
        out IntPtr err);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_builder_register_policy_dispatcher")]
    internal static extern int AcsBuilderRegisterPolicyDispatcher(
        IntPtr builder,
        AcsPolicyCallback callback,
        AcsFreeResultCallback freeResult,
        IntPtr userData,
        out IntPtr err);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_builder_enable_default_annotator_dispatcher")]
    internal static extern int AcsBuilderEnableDefaultAnnotatorDispatcher(
        IntPtr builder,
        out IntPtr err);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_builder_enable_default_policy_dispatcher")]
    internal static extern int AcsBuilderEnableDefaultPolicyDispatcher(
        IntPtr builder,
        out IntPtr err);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_builder_set_perf_telemetry")]
    internal static extern int AcsBuilderSetPerfTelemetry(
        IntPtr builder,
        int level,
        out IntPtr err);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_builder_build")]
    internal static extern IntPtr AcsBuilderBuild(IntPtr builder, out IntPtr err);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_builder_free")]
    internal static extern void AcsBuilderFree(IntPtr builder);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_runtime_evaluate")]
    internal static extern IntPtr AcsRuntimeEvaluate(
        IntPtr runtime,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson,
        out IntPtr err);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_runtime_policy_labels")]
    internal static extern IntPtr AcsRuntimePolicyLabels(
        IntPtr runtime,
        out IntPtr err);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_runtime_free")]
    internal static extern void AcsRuntimeFree(IntPtr runtime);

    [LibraryImport(
        NativeLibraryName,
        EntryPoint = "acs_validate_artifacts",
        StringMarshalling = StringMarshalling.Utf8)]
    [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    internal static partial IntPtr AcsValidateArtifacts(
        string manifestYaml,
        string regoModulesJson,
        string? opaPath,
        out IntPtr err);

    [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "acs_free_string")]
    internal static extern void AcsFreeString(IntPtr value);
}
