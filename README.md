# package-swift-ecdhp256

This Swift Package combines the Ecdh P256 C language library with a Swift wrapper class (EcdhP256) to provide out-of-the-box integration. Unit testing is also included.

## Full Code and Documentation
In addition to the code and documentation provided here, the complete codebase, including wrapper classes for many other languages, and complete documentation can be found at https://github.com/Eclypses/package-mtesupport-ecdh.git.


## Implement Package
1. Create or open your host application
2. In the Project Navigator, select the project root, and then, select the project in the editor, rather than the Target, then the 'Package dependencies' tab.
3. Click the '+' symbol to add a new package.
4. In the Search box paste this URL https://github.com/Eclypses/package-swift-ecdhp256.git
5. Select the master branch and click 'Add Package'.
6. The package will show up within a 'Package Dependencies' section in the Project Navigator.
7. Select the root in the Project Navigator again, select your Target in the Editor, then the 'General' tab and scroll down to 'Frameworks, Libraries and Embedded Content'.
8. Add EcdhP256 if it's not already there.
9. In any class where you wish to use the publicly accessible properties and functions of EcdhP256, import it. 


## Local Implementation
This package can also be cloned and used locally.

1. Clone this package.
2. Create or open your host application
3. In the Project Navigator, select the project root, and then, select the project in the editor, rather than the Target, then the 'Package dependencies' tab.
4. Click the '+' symbol to add a new package.
5. Click 'Add Local...' at the bottom of the dialog window and navigate to this cloned Swift Package.
6. Select this package and click 'Add Package'.
7. The package will show up within a 'Packages' directory in the Project Navigator.
8. Select the root in the Project Navigator again, select your Target in the Editor, then the 'General' tab and scroll down to 'Frameworks, Libraries and Embedded Content'.
9. Add EcdhP256 if it's not already there.
10. In any class where you wish to use the publicly accessible properties and functions of EcdhP256, import it. 
12. Included here is example code testing two instantiations of EcdhP256 and comparing the resulting shared secrets. This provides good examples of using the EcdhP256 Swift Package.

```swift
import Foundation
import EcdhLib
import EcdhP256

class Manager: ObservableObject, EcdhEntropyCallback {
    
    func getRandom(_ entropyInput: inout [UInt8],
                         _ eiBytes: Int) -> Int32 {
        debugPrint("Using \(#function) in \(type(of: self))")
        let status = SecRandomCopyBytes(
            kSecRandomDefault,
            eiBytes,
            &entropyInput
        )
        if status != errSecSuccess {
            debugPrint("Error using \(#function) in \(type(of: self)). Error Code: \(status)")
            return ECDH_P256_RANDOM_FAIL
        }
        return ECDH_P256_SUCCESS
    }
    
    var localPublicKey: [UInt8]!
    var remotePublicKey: [UInt8]!
    
    var localSharedSecret: [UInt8]!
    var remoteSharedSecret: [UInt8]!
    
    var ecdhP256Local: EcdhP256!
    var ecdhP256Remote: EcdhP256!
    
    init() {
        initializeEcdh()
    }
    
    func initializeEcdh() {
        print("\n\nBeginning ECDH Test Sequence")
        do {
            ecdhP256Local = try EcdhP256(name: "Local")
//            ecdhHelperLocal.setEntropyCallback(self) // Commented out to demonstrate retrieving Random Bytes from EcdhHelper
            ecdhP256Remote = try EcdhP256(name: "Remote")
            ecdhP256Remote.setEntropyCallback(self)
        } catch {
            print("Error using \(#function) in \(type(of: self)). Error: \(error.localizedDescription)")
        }
    }
        
    func test() -> Bool {
        defer {
            ecdhP256Local = nil
            ecdhP256Remote = nil
        }
        
        getLocalPublicKey()
        getRemotePublicKey()
        createLocalSharedSecret()
        createRemoteSharedSecret()
        return compareSharedSecrets()
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
    
    func compareSharedSecrets() -> Bool {
        return remoteSharedSecret == localSharedSecret
    }
    
}

```
