//
// ******************************************************
// Copyright © 2023 Eclypses Inc. All rights reserved.
// ******************************************************


import Foundation
import EcdhLib

public class EcdhP256 {
    
    // MARK: Class properties
    
    var name: String!
    var localPrivateKey: byte_array!
    var localPublicKey: byte_array!
    var remotePublicKey: byte_array!
    var sharedSecret: byte_array!
    var ecdhEntropyCallback: EcdhEntropyCallback!
    
    
    // MARK: Class init and deinit
    public init(name: String) throws {
        
        self.name = name
        localPrivateKey = byte_array(size: Int(SZ_ECDH_P256_PRIVATE_KEY),
                                     data: UnsafeMutablePointer<UInt8>.allocate(capacity: Int(SZ_ECDH_P256_PRIVATE_KEY)))
        localPublicKey = byte_array(size: Int(SZ_ECDH_P256_PUBLIC_KEY),
                                    data: UnsafeMutablePointer<UInt8>.allocate(capacity: Int(SZ_ECDH_P256_PUBLIC_KEY)))
        remotePublicKey = byte_array(size: Int(SZ_ECDH_P256_PUBLIC_KEY),
                                     data: UnsafeMutablePointer<UInt8>.allocate(capacity: Int(SZ_ECDH_P256_PUBLIC_KEY)))
        sharedSecret = byte_array(size: Int(SZ_ECDH_P256_SECRET_DATA),
                                  data: UnsafeMutablePointer<UInt8>.allocate(capacity: Int(SZ_ECDH_P256_SECRET_DATA)))
        debugPrint("EcdhP256 for \(name) initialized and ready for use.")
    }
    
    deinit {
        localPrivateKey.data.deinitialize(count: Int(SZ_ECDH_P256_PRIVATE_KEY))
        localPrivateKey.data.deallocate()
        localPublicKey.data.deinitialize(count: Int(SZ_ECDH_P256_PUBLIC_KEY))
        localPublicKey.data.deallocate()
        remotePublicKey.data.deinitialize(count: Int(SZ_ECDH_P256_PUBLIC_KEY))
        remotePublicKey.data.deallocate()
        sharedSecret.data.deinitialize(count: Int(SZ_ECDH_P256_SECRET_DATA))
        sharedSecret.data.deallocate()
        debugPrint("EcdhP256 for \(name!) cleaned up and class destroyed.")
    }
    
    // MARK: Public functions
    public func getLocalPublicKey() throws -> [UInt8] {
        
        let ptr = Unmanaged.passUnretained(self).toOpaque()
        let createKeyPairResult = ecdh_p256_create_keypair(localPrivateKey, localPublicKey, EcdhP256.entropyCallback, ptr)
        if createKeyPairResult != ECDH_P256_SUCCESS {
            throw ECDHErrors.unableToCreateLocalPublicKey
        }
        var localPublicKeyBytes = [UInt8]()
        for byte in UnsafeBufferPointer(start: localPublicKey.data, count: localPublicKey.size) {
            localPublicKeyBytes.append(byte)
        }
        return localPublicKeyBytes
    }
    
    public func createSharedSecret(remotePublicKeyBytes: [UInt8], entropyBuffer: inout [UInt8]) throws {
        remotePublicKey.data.initialize(from: remotePublicKeyBytes, count: remotePublicKeyBytes.count)
        let createSharedSecretResult = ecdh_p256_create_secret(localPrivateKey, remotePublicKey, sharedSecret)
        if createSharedSecretResult != ECDH_P256_SUCCESS {
            throw ECDHErrors.unableToCreateSharedSecret
        }
        var sharedSecretBytes = [UInt8]()
        for byte in UnsafeBufferPointer(start: sharedSecret.data, count: sharedSecret.size) {
            sharedSecretBytes.append(byte)
        }
        entropyBuffer = sharedSecretBytes
        sharedSecretBytes.resetBytes(in: 0..<sharedSecretBytes.count)
    }
    
    // MARK: Callback Functions
    
    private var myEntropyCb: EcdhEntropyCallback? = nil
    
    public func setEntropyCallback(_ cb: EcdhEntropyCallback?) {
        myEntropyCb = cb;
    }
    
    // Internal Entropy Callback
    internal func entropyCallback(_ entropyInput: inout [UInt8], _ eiBytes: Int) -> Int32 {
        if myEntropyCb != nil {
            return myEntropyCb!.copySecRndBytes(&entropyInput, eiBytes)
        }
        return self.copySecRndBytes(&entropyInput, eiBytes)
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
                                                if status != ECDH_P256_SUCCESS {
                                                    return ECDH_P256_RANDOM_FAIL
                                                }
                                                entropyInput.data.assign(from: eiByteArray, count: Int(eib))
                                                eiByteArray.resetBytes(in: 0..<eiByteArray.count)
                                                
                                                return status
                                            }
    
    internal func copySecRndBytes(_ entropyInput: inout [UInt8],
                                  _ eiBytes: Int) -> Int32 {
        debugPrint("Using Random Byte Generator in EcdhP256")
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
}

// MARK: Interface for Entropy Input Callback
public protocol EcdhEntropyCallback {
    func copySecRndBytes(_ entropyInput: inout [UInt8], _ eiBytes: Int) -> Int32
}

// MARK: ErrorEnum
enum ECDHErrors: Error {
    case unableToInitializeEcdhP256
    case unableToCreateLocalPublicKey
    case unableToCreateSharedSecret
    case unableToCopyRandomBytes
    
    var resultCode: String {
        switch self {
        case .unableToInitializeEcdhP256:
            return "Unable to Initialize an Elliptic Curve Diffie-Hellman in this device. Unable to Continue."
        case .unableToCreateLocalPublicKey:
            return "Unable to Create an Elliptic Curve Diffie-Hellman Public Key for this Device. Unable to Continue."
        case .unableToCreateSharedSecret:
            return "Unable to Create a Elliptic Curve Diffie-Hellman Shared Secret. Unable to Continue."
        case .unableToCopyRandomBytes:
            return "Unable to Copy Secure random Bytes on this Device. Unable to Continue."
        }
    }
    
}
