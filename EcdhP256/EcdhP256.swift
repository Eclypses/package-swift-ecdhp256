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


import Foundation
import EcdhLib

public class EcdhP256 {
    
    // MARK: Class properties
    
    var name: String!
    private var localPrivateKey: byte_array!
    private var localPublicKey: byte_array!
    private var remotePublicKey: byte_array!
    private var sharedSecret: byte_array!
    var ecdhEntropyCallback: EcdhEntropyCallback!
    private var keysCreated = false
    
    
    // MARK: Class init and deinit
    public init(name: String) {
        
        self.name = name

        localPrivateKey = byte_array(size: Constants.privateKeySize,
                                     data: UnsafeMutablePointer<UInt8>.allocate(capacity: Constants.privateKeySize))
        localPublicKey = byte_array(size: Constants.publicKeySize,
                                    data: UnsafeMutablePointer<UInt8>.allocate(capacity: Constants.publicKeySize))
        remotePublicKey = byte_array(size: Constants.publicKeySize,
                                     data: UnsafeMutablePointer<UInt8>.allocate(capacity: Constants.publicKeySize))
        sharedSecret = byte_array(size: Constants.secretDataSize,
                                  data: UnsafeMutablePointer<UInt8>.allocate(capacity: Constants.secretDataSize))
        debugPrint("EcdhP256 for \(name) initialized and ready for use.")
    }
    
    deinit {
        localPrivateKey.data.deinitialize(count: Constants.privateKeySize)
        localPrivateKey.data.deallocate()
        localPublicKey.data.deinitialize(count: Constants.publicKeySize)
        localPublicKey.data.deallocate()
        remotePublicKey.data.deinitialize(count: Constants.publicKeySize)
        remotePublicKey.data.deallocate()
        sharedSecret.data.deinitialize(count: Constants.secretDataSize)
        sharedSecret.data.deallocate()
        debugPrint("EcdhP256 for \(name!) cleaned up and class destroyed.")
    }
    
    // MARK: Public functions
    public func createKeyPair() -> (Int, [UInt8]?) {
        var status: Int32 = 0
        if !keysCreated {
            let ptr = Unmanaged.passUnretained(self).toOpaque()
            status = ecdh_p256_create_keypair(&localPrivateKey, &localPublicKey, EcdhP256.entropyCallback, ptr)
            if status != EcdhP256.ResultCodes.success {
                return (Int(status), nil)
            }
            keysCreated = true
        }
        var localPublicKeyBytes = [UInt8]()
        for byte in UnsafeBufferPointer(start: localPublicKey.data, count: localPublicKey.size) {
            localPublicKeyBytes.append(byte)
        }
        return (Int(status), localPublicKeyBytes)
    }
    
    public func getSharedSecret(remotePublicKeyBytes: [UInt8], entropyBuffer: inout [UInt8]) -> Int {
        remotePublicKey.data.initialize(from: remotePublicKeyBytes, count: remotePublicKeyBytes.count)
        let status = ecdh_p256_create_secret(localPrivateKey, remotePublicKey, &sharedSecret)
        if status != EcdhP256.ResultCodes.success {
            return Int(status)
        }
        var sharedSecretBytes = [UInt8]()
        for byte in UnsafeBufferPointer(start: sharedSecret.data, count: sharedSecret.size) {
            sharedSecretBytes.append(byte)
        }
        entropyBuffer = sharedSecretBytes
        EcdhP256.zeroize(&sharedSecretBytes)
        keysCreated = false
        return Int(status)
    }
    
    // MARK: Callback Functions
    
    private var myEntropyCb: EcdhEntropyCallback? = nil
    private var myEntropy: [UInt8]? = nil
    
    public func setEntropy(_ entropyInput: [UInt8]) -> Int {
        if entropyInput.count != EcdhP256.Constants.privateKeySize {
            return EcdhP256.ResultCodes.memoryFail
        }
        myEntropy = entropyInput
        return EcdhP256.ResultCodes.success
    }
    
    public func setEntropyCallback(_ cb: EcdhEntropyCallback?) {
        myEntropyCb = cb;
    }
    
    // Internal Entropy Callback
    internal func entropyCallback(_ entropyInput: inout [UInt8], _ eiBytes: Int) -> Int32 {
        if myEntropyCb != nil {
            return myEntropyCb!.getRandom(&entropyInput, eiBytes)
        }
        if myEntropy != nil {
            entropyInput = myEntropy!
            myEntropy!.resetBytes(in: 0..<myEntropy!.count)
            return Int32(ResultCodes.success)
        }
        return EcdhP256.getRandom(&entropyInput, eiBytes)
    }
    
    static let entropyCallback: Optional<@convention(c)
                                            (UnsafeMutableRawPointer?,
                                             byte_array) -> Int32> = {
                                                (context, entropyInput) ->
                                                Int32 in
                                                let c = Unmanaged<EcdhP256>.fromOpaque(context!).takeUnretainedValue()
                                                var eib = entropyInput.size
                                                var eiByteArray = [UInt8](repeating: 0, count: eib)
                                                let status = c.entropyCallback(&eiByteArray, eib)
                                                if status != EcdhP256.ResultCodes.success {
                                                    return Int32(EcdhP256.ResultCodes.randomFail)
                                                }
                                                entropyInput.data.assign(from: eiByteArray, count: Int(eib))
                                                eiByteArray.resetBytes(in: 0..<eiByteArray.count)                                                
                                                return status
                                            }
    
    public static func getRandom(_ entropyInput: inout [UInt8],
                                  _ eiBytes: Int) -> Int32 {
        debugPrint("Using \(#function) in \(type(of: self))")
        let status = SecRandomCopyBytes(
            kSecRandomDefault,
            eiBytes,
            &entropyInput
        )
        if status != errSecSuccess {            
            debugPrint("Error using \(#function) in \(type(of: self)). Error Code: \(status)")
        }
        return status
    }
    
    public static func zeroize(_ data: inout [UInt8]) {
        data.withUnsafeMutableBytes { buf in
            ecdh_p256_zeroize(buf.baseAddress, buf.count)
        }
    }
    
    public enum ResultCodes {
        public static var success: Int = Int(ECDH_P256_SUCCESS)
        public static var randomFail: Int = Int(ECDH_P256_RANDOM_FAIL)
        public static var invalidPubKey: Int = Int(ECDH_P256_INVALID_PUBKEY)
        public static var invalidPrivKey: Int = Int(ECDH_P256_INVALID_PRIVKEY)
        public static var memoryFail: Int = Int(ECDH_P256_MEMORY_FAIL)
    }
    
    public enum Constants {
        public static var publicKeySize: Int = Int(SZ_ECDH_P256_PUBLIC_KEY)
        public static var privateKeySize: Int = Int(SZ_ECDH_P256_PRIVATE_KEY)
        public static var secretDataSize: Int = Int(SZ_ECDH_P256_SECRET_DATA)
    }

}

// MARK: Protocol for Entropy Input Callback
public protocol EcdhEntropyCallback {
    func getRandom(_ entropyInput: inout [UInt8], _ eiBytes: Int) -> Int32
}

