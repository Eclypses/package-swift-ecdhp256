# package_swift_ecdh

This Swift Package combines the Ecdh P256 C library with a Swift wrapper class (EcdhP256) to provide out-of-the-box integration. Unit testing is also included.

## Local Implementation

We currently (Feb 2023) don't have a publicly-accessible package repo but this package can still be cloned and used locally.

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
11. You will likely also need to import EcdhLib to make use of its Enums and properties.
12. Here is example code testing two instantiations of EcdhP256 and comparing the resulting shared secrets. This provides good examples of using the EcdhP256 Swift Package.

```swift
import Foundation
import EcdhLib
import EcdhP256

class Manager: ObservableObject, EcdhEntropyCallback {
    
    func copySecRndBytes(_ entropyInput: inout [UInt8],
                         _ eiBytes: Int) -> Int32 {
        debugPrint("Using Random Byte Generator in EcdhHelper")
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
    
    var localPublicKey: [UInt8]!
    var remotePublicKey: [UInt8]!
    
    var localSharedSecret: [UInt8]!
    var remoteSharedSecret: [UInt8]!
    
    var ecdhHelperLocal: EcdhP256!
    var ecdhHelperRemote: EcdhP256!
    
    init() {
        initializeEcdhHelpers()
    }
    
    func initializeEcdhHelpers() {
        print("\n\nBeginning ECDH Test Sequence")
        do {
            ecdhHelperLocal = try EcdhP256(name: "Local")
//            ecdhHelperLocal.setEntropyCallback(self) // Commented out to demonstrate retrieving Random Bytes from EcdhHelper
            ecdhHelperRemote = try EcdhP256(name: "Remote")
            ecdhHelperRemote.setEntropyCallback(self)
        } catch {
            print("EcdhHelper init failed. Error: \(error.localizedDescription)")
        }
    }
    
    
    func test() -> Bool {
        defer {
            ecdhHelperLocal = nil
            ecdhHelperRemote = nil
        }
        
        getLocalPublicKey()
        getRemotePublicKey()
        createLocalSharedSecret()
        createRemoteSharedSecret()
        return compareSharedSecrets()
    }
    
        
    private func getLocalPublicKey() {
        do {
            localPublicKey = try ecdhHelperLocal.getLocalPublicKey()
        } catch {
            print("Error getting local public key. Error: \(error.localizedDescription)")
        }
    }
    
    
    private func getRemotePublicKey() {
        do {
            remotePublicKey = try ecdhHelperRemote.getLocalPublicKey()
        } catch {
            print("Error getting remote public key. Error: \(error.localizedDescription)")
        }
    }
    
    private func createLocalSharedSecret() {
        do {
            localSharedSecret = [UInt8]()
            try ecdhHelperLocal.createSharedSecret(remotePublicKeyBytes: remotePublicKey, entropyBuffer: &localSharedSecret)
        } catch {
            print("Error creating local shared secret. Error: \(error.localizedDescription)")
        }
    }
    
    private func createRemoteSharedSecret() {
        do {
            remoteSharedSecret = [UInt8]()
            try ecdhHelperRemote.createSharedSecret(remotePublicKeyBytes: localPublicKey, entropyBuffer: &remoteSharedSecret)
        } catch {
            print("Error creating remote shared secret. Error: \(error.localizedDescription)")
        }
    }
    
    func compareSharedSecrets() -> Bool {
        return remoteSharedSecret == localSharedSecret
    }
    
    
    
}

```
