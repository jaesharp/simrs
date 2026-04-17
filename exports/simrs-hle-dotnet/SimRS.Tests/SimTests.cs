using SimRS;
using Xunit;

namespace SimRS.Tests;

public class SimTests : IDisposable
{
    private Sim MakeSim() => new(new byte[16], new byte[16], new byte[16]);

    [Fact]
    public void InitRequires16ByteKeys()
    {
        Assert.Throws<ArgumentException>(() => new Sim(new byte[8], new byte[16], new byte[16]));
        Assert.Throws<ArgumentException>(() => new Sim(new byte[16], new byte[8], new byte[16]));
        Assert.Throws<ArgumentException>(() => new Sim(new byte[16], new byte[16], new byte[8]));
    }

    [Fact]
    public void ResetReturnsATR()
    {
        using var sim = MakeSim();
        var atr = sim.Reset();
        Assert.NotEmpty(atr);
        Assert.Equal(0x3B, atr[0]);
    }

    [Fact]
    public void SelectMF()
    {
        using var sim = MakeSim();
        sim.Reset();
        var rsp = sim.Apdu(new byte[] { 0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00 });
        Assert.True(rsp.Length >= 2);
        Assert.Equal(0x61, rsp[^2]);
    }

    [Fact]
    public void ApduTooShortThrows()
    {
        using var sim = MakeSim();
        sim.Reset();
        Assert.Throws<ArgumentException>(() => sim.Apdu(new byte[] { 0x00, 0xA4 }));
    }

    [Fact]
    public void SnapshotRoundtrip()
    {
        using var sim = MakeSim();
        sim.Reset();
        sim.Apdu(new byte[] { 0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00 });

        var snap = sim.Snapshot();
        Assert.NotEmpty(snap);

        var h1 = sim.StateHash();

        using var sim2 = MakeSim();
        sim2.Reset();
        sim2.Restore(snap);
        Assert.Equal(h1, sim2.StateHash());
    }

    [Fact]
    public void StateHashChanges()
    {
        using var sim = MakeSim();
        sim.Reset();
        var h1 = sim.StateHash();
        sim.Apdu(new byte[] { 0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00 });
        var h2 = sim.StateHash();
        Assert.NotEqual(h1, h2);
    }

    [Fact]
    public void BadSnapshotThrows()
    {
        using var sim = MakeSim();
        sim.Reset();
        Assert.Throws<InvalidOperationException>(() =>
            sim.Restore(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }));
    }

    public void Dispose() { }
}
