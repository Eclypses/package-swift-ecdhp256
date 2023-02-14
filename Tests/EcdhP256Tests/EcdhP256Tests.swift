import XCTest
@testable import EcdhLib
@testable import EcdhP256

final class EcdhP256Tests: XCTestCase, EcdhEntropyCallback {
    
    var localPublicKey: [UInt8]!
    var remotePublicKey: [UInt8]!
    
    var localSharedSecret: [UInt8]!
    var remoteSharedSecret: [UInt8]!
    
    var ecdhP256Local: EcdhP256!
    var ecdhP256Remote: EcdhP256!
    
    func copySecRndBytes(_ entropyInput: inout [UInt8],
                         _ eiBytes: Int) -> Int32 {
        debugPrint("Using the Ca;;back Random Byte Generator within the EcdhP256Tests project")
        let status = SecRandomCopyBytes(
            kSecRandomDefault,
            eiBytes,
            &entropyInput
        )
        if status != errSecSuccess {
            debugPrint("Error getting secure random bytes. Error Code: \(status)")
            return ECDH_P256_RANDOM_FAIL
        }
        return ECDH_P256_SUCCESS
    }
    
    private func getLocalPublicKey() {
        do {
            localPublicKey = try ecdhP256Local.getLocalPublicKey()
        } catch {
            print("Error getting local public key. Error: \(error.localizedDescription)")
        }
    }
    
    private func getRemotePublicKey() {
        do {
            remotePublicKey = try ecdhP256Remote.getLocalPublicKey()
        } catch {
            print("Error getting remote public key. Error: \(error.localizedDescription)")
        }
    }
    
    private func createLocalSharedSecret() {
        do {
            localSharedSecret = [UInt8]()
            try ecdhP256Local.createSharedSecret(remotePublicKeyBytes: remotePublicKey, entropyBuffer: &localSharedSecret)
        } catch {
            print("Error creating local shared secret. Error: \(error.localizedDescription)")
        }
    }
    
    private func createRemoteSharedSecret() {
        do {
            remoteSharedSecret = [UInt8]()
            try ecdhP256Remote.createSharedSecret(remotePublicKeyBytes: localPublicKey, entropyBuffer: &remoteSharedSecret)
        } catch {
            print("Error creating remote shared secret. Error: \(error.localizedDescription)")
        }
    }
    
    override func setUpWithError() throws {
        print("\n\nBeginning ECDH Test Sequence")
        do {
            ecdhP256Local = try EcdhP256(name: "Local")
//            ecdhP256Local.setEntropyCallback(self) // Commented out to demonstrate retrieving Random Bytes from EcdhP256
            ecdhP256Remote = try EcdhP256(name: "Remote")
            ecdhP256Remote.setEntropyCallback(self)
        } catch {
            print("EcdhP256 init failed. Error: \(error.localizedDescription)")
        }
    }
    
    func testEcdhP256() throws {
        defer {
            ecdhP256Local = nil
            ecdhP256Remote = nil
        }
        getLocalPublicKey()
        getRemotePublicKey()
        createLocalSharedSecret()
        createRemoteSharedSecret()
        XCTAssertEqual(remoteSharedSecret, localSharedSecret)
    }
}
