using System.Runtime.InteropServices;

namespace AgentControlSpecification.Interop;

internal static class NativeEnvironment
{
    internal static void SyncOpaEnvironment()
    {
        SyncVariable("ACS_OPA_PATH");
        SyncVariable("PATH");
    }

    private static void SyncVariable(string name)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        var value = Environment.GetEnvironmentVariable(name);
        var result = value is null
            ? UnsetEnv(name)
            : SetEnv(name, value, 1);
        if (result != 0)
        {
            throw new InvalidOperationException(
                $"Failed to synchronize {name} with native environment.");
        }
    }

    [DllImport("libc", EntryPoint = "setenv", CallingConvention = CallingConvention.Cdecl)]
    private static extern int SetEnv(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string value,
        int overwrite);

    [DllImport("libc", EntryPoint = "unsetenv", CallingConvention = CallingConvention.Cdecl)]
    private static extern int UnsetEnv([MarshalAs(UnmanagedType.LPUTF8Str)] string name);
}
