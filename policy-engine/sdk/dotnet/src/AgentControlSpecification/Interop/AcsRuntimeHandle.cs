using System.Runtime.InteropServices;

namespace AgentControlSpecification.Interop;

internal sealed class AcsRuntimeHandle : SafeHandle
{
    private readonly NativeMethods.AcsAnnotatorCallback? annotatorCallback;
    private readonly NativeMethods.AcsPolicyCallback? policyCallback;
    private readonly NativeMethods.AcsFreeResultCallback freeResultCallback;

    private AcsRuntimeHandle(
        IntPtr existing,
        NativeMethods.AcsAnnotatorCallback? annotatorCallback,
        NativeMethods.AcsPolicyCallback? policyCallback,
        NativeMethods.AcsFreeResultCallback freeResultCallback)
        : base(IntPtr.Zero, ownsHandle: true)
    {
        this.annotatorCallback = annotatorCallback;
        this.policyCallback = policyCallback;
        this.freeResultCallback = freeResultCallback;
        SetHandle(existing);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    public IntPtr DangerousGetPointer() => handle;

    public static AcsRuntimeHandle FromExisting(
        IntPtr existing,
        NativeMethods.AcsAnnotatorCallback? annotatorCallback,
        NativeMethods.AcsPolicyCallback? policyCallback,
        NativeMethods.AcsFreeResultCallback freeResultCallback)
    {
        if (existing == IntPtr.Zero)
        {
            throw new ArgumentException("Cannot wrap a null ACS runtime handle.", nameof(existing));
        }

        return new AcsRuntimeHandle(existing, annotatorCallback, policyCallback, freeResultCallback);
    }

    protected override bool ReleaseHandle()
    {
        if (handle != IntPtr.Zero)
        {
            NativeMethods.AcsRuntimeFree(handle);
            SetHandle(IntPtr.Zero);
        }

        GC.KeepAlive(annotatorCallback);
        GC.KeepAlive(policyCallback);
        GC.KeepAlive(freeResultCallback);
        return true;
    }
}
