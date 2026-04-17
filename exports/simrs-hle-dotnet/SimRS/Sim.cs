using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;

namespace SimRS;

/// <summary>
/// SimRS smart card simulator -- C#/.NET bindings via P/Invoke.
///
/// Thread-safe by default: all native calls are dispatched to a dedicated
/// thread to satisfy the C library's thread-local storage requirement.
/// Pass <c>threadSafe: false</c> for pinned mode (caller manages threading).
/// </summary>
public sealed class Sim : IDisposable
{
    private readonly bool _threadSafe;
    private readonly Thread? _workerThread;
    private readonly BlockingCollection<(Action action, ManualResetEventSlim done)>? _queue;
    private readonly int _ownerThreadId;
    private bool _disposed;

    /// <summary>
    /// Initialize the SIM with Milenage authentication credentials.
    /// </summary>
    /// <param name="ki">16-byte GSM subscriber key</param>
    /// <param name="k">16-byte Milenage subscriber key</param>
    /// <param name="opc">16-byte Milenage operator variant OPc</param>
    /// <param name="threadSafe">If true (default), uses a dedicated worker thread</param>
    public Sim(byte[] ki, byte[] k, byte[] opc, bool threadSafe = true)
    {
        if (ki.Length != 16) throw new ArgumentException("ki must be 16 bytes");
        if (k.Length != 16) throw new ArgumentException("k must be 16 bytes");
        if (opc.Length != 16) throw new ArgumentException("opc must be 16 bytes");

        _threadSafe = threadSafe;
        _ownerThreadId = Environment.CurrentManagedThreadId;

        if (threadSafe)
        {
            _queue = new BlockingCollection<(Action, ManualResetEventSlim)>();
            _workerThread = new Thread(WorkerLoop) { IsBackground = true, Name = "simrs-worker" };
            _workerThread.Start();
        }

        Dispatch(() => NativeInit(ki, k, opc));
    }

    /// <summary>Power-on reset. Returns the ATR bytes.</summary>
    public byte[] Reset()
    {
        byte[]? result = null;
        Dispatch(() =>
        {
            var buf = new byte[64];
            var len = NativeReset(buf, (uint)buf.Length);
            if (len == 0) throw new InvalidOperationException("Reset failed");
            result = new byte[len];
            Array.Copy(buf, result, len);
        });
        return result!;
    }

    /// <summary>Send an APDU command and receive the response.</summary>
    public byte[] Apdu(byte[] command)
    {
        if (command.Length < 4) throw new ArgumentException("APDU must be at least 4 bytes");
        byte[]? result = null;
        Dispatch(() =>
        {
            var rsp = new byte[258];
            var len = NativeApdu(command, (uint)command.Length, rsp, (uint)rsp.Length);
            if (len == 0) throw new InvalidOperationException("APDU failed");
            result = new byte[len];
            Array.Copy(rsp, result, len);
        });
        return result!;
    }

    /// <summary>Save the current SIM state.</summary>
    public byte[] Snapshot()
    {
        byte[]? result = null;
        Dispatch(() =>
        {
            var size = NativeSnapshotSize();
            var buf = new byte[size];
            var written = NativeSnapshotSave(buf, size);
            if (written == 0) throw new InvalidOperationException("Snapshot failed");
            result = new byte[written];
            Array.Copy(buf, result, written);
        });
        return result!;
    }

    /// <summary>Restore SIM state from a previous snapshot.</summary>
    public void Restore(byte[] snapshot)
    {
        Dispatch(() =>
        {
            if (NativeSnapshotRestore(snapshot, (uint)snapshot.Length) == 0)
                throw new InvalidOperationException("Snapshot restore failed");
        });
    }

    /// <summary>FNV-1a hash of the current SIM state.</summary>
    public ulong StateHash()
    {
        ulong result = 0;
        Dispatch(() => { result = NativeStateHash(); });
        return result;
    }

    private void Dispatch(Action action)
    {
        if (!_threadSafe)
        {
            if (Environment.CurrentManagedThreadId != _ownerThreadId)
                throw new InvalidOperationException(
                    "Sim accessed from a different thread. Use threadSafe: true for cross-thread access.");
            action();
            return;
        }

        using var done = new ManualResetEventSlim(false);
        Exception? caught = null;
        _queue!.Add((() =>
        {
            try { action(); }
            catch (Exception ex) { caught = ex; }
            finally { done.Set(); }
        }, done));
        done.Wait();
        if (caught != null) throw caught;
    }

    private void WorkerLoop()
    {
        foreach (var (action, _) in _queue!.GetConsumingEnumerable())
        {
            action();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _queue?.CompleteAdding();
        _workerThread?.Join(TimeSpan.FromSeconds(5));
        _queue?.Dispose();
    }

    // --- P/Invoke declarations ---

    [DllImport("simrs_hle_capi", EntryPoint = "simrs_init")]
    private static extern void NativeInit(byte[] ki, byte[] k, byte[] opc);

    [DllImport("simrs_hle_capi", EntryPoint = "simrs_init_profile")]
    private static extern uint NativeInitProfile(byte[] der, uint derLen);

    [DllImport("simrs_hle_capi", EntryPoint = "simrs_reset")]
    private static extern uint NativeReset(byte[] atrBuf, uint atrBufLen);

    [DllImport("simrs_hle_capi", EntryPoint = "simrs_apdu")]
    private static extern uint NativeApdu(byte[] cmd, uint cmdLen, byte[] rspBuf, uint rspBufLen);

    [DllImport("simrs_hle_capi", EntryPoint = "simrs_snapshot_save")]
    private static extern uint NativeSnapshotSave(byte[] buf, uint bufLen);

    [DllImport("simrs_hle_capi", EntryPoint = "simrs_init_from_snapshot")]
    private static extern uint NativeSnapshotRestore(byte[] buf, uint bufLen);

    [DllImport("simrs_hle_capi", EntryPoint = "simrs_snapshot_size")]
    private static extern uint NativeSnapshotSize();

    [DllImport("simrs_hle_capi", EntryPoint = "simrs_state_hash")]
    private static extern ulong NativeStateHash();
}
