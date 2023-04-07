// The MIT License (MIT)
//
// Copyright (c) Eclypses, Inc.
//
// All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
    
    func getRandom(_ entropyInput: inout [UInt8],
                         _ eiBytes: Int) -> Int32 {
        print("Using \(#function) in \(type(of: self))")
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
        var result: (status:Int , publicKey:[UInt8]?)
        result = ecdhP256Local.createKeyPair()
        if result.status != EcdhP256.ResultCodes.success {
            print("Error getting local public key. Status: \(result.status)")
            return
        }
        localPublicKey = result.publicKey
    }
    
    private func getRemotePublicKey() {
        var result: (status:Int, publicKey:[UInt8]?)
        result = ecdhP256Remote.createKeyPair()
        if result.status != EcdhP256.ResultCodes.success {
            print("Error getting remote public key. Status: \(result.status)")
            return
        }
        remotePublicKey = result.publicKey
    }
    
    private func createLocalSharedSecret() {
        localSharedSecret = [UInt8]()
        let status = ecdhP256Local.getSharedSecret(remotePublicKeyBytes: remotePublicKey, entropyBuffer: &localSharedSecret)
        if status != EcdhP256.ResultCodes.success {
            print("Error getting local Shared Secret. Status: \(status)")
            return
        }
    }
    
    private func createRemoteSharedSecret() {
        remoteSharedSecret = [UInt8]()
        let status = ecdhP256Remote.getSharedSecret(remotePublicKeyBytes: localPublicKey, entropyBuffer: &remoteSharedSecret)
        if status != EcdhP256.ResultCodes.success {
            print("Error getting remote Shared Secret. Status: \(status)")
            return
        }
    }
    
    override func setUpWithError() throws {
        print("\n\nBeginning ECDH Test Sequence")
        ecdhP256Local = EcdhP256(name: "Local")
//            ecdhP256Local.setEntropyCallback(self) // Commented out to demonstrate retrieving Random Bytes from EcdhP256
        ecdhP256Remote = EcdhP256(name: "Remote")
        ecdhP256Remote.setEntropyCallback(self)
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
