import XCTest
@testable import SimRS

final class SimTests: XCTestCase {

    func makeSim() -> Sim {
        return Sim(ki: [UInt8](repeating: 0, count: 16),
                   k: [UInt8](repeating: 0, count: 16),
                   opc: [UInt8](repeating: 0, count: 16))
    }

    func testResetReturnsATR() {
        let sim = makeSim()
        let atr = sim.reset()
        XCTAssertFalse(atr.isEmpty)
        XCTAssertEqual(atr[0], 0x3B)
    }

    func testSelectMF() {
        let sim = makeSim()
        _ = sim.reset()
        let rsp = sim.apdu([0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00])
        XCTAssertGreaterThanOrEqual(rsp.count, 2)
        XCTAssertEqual(rsp[rsp.count - 2], 0x61)
    }

    func testSnapshotRoundtrip() {
        let sim = makeSim()
        _ = sim.reset()
        _ = sim.apdu([0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00])

        let snap = sim.snapshot()
        XCTAssertFalse(snap.isEmpty)

        let h1 = sim.stateHash()

        let sim2 = makeSim()
        _ = sim2.reset()
        XCTAssertTrue(sim2.restore(snap))
        XCTAssertEqual(sim2.stateHash(), h1)
    }

    func testStateHashChanges() {
        let sim = makeSim()
        _ = sim.reset()
        let h1 = sim.stateHash()
        _ = sim.apdu([0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00])
        let h2 = sim.stateHash()
        XCTAssertNotEqual(h1, h2)
    }

    func testBadSnapshotFails() {
        let sim = makeSim()
        _ = sim.reset()
        XCTAssertFalse(sim.restore([0xFF, 0xFF, 0xFF, 0xFF]))
    }
}
