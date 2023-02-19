struct BiometricsConstants {
    static let channel = "flutter_biometrics"
    
    struct MethodNames {
        static let availableBiometricTypes = "availableBiometricTypes"
        static let createKeys = "createKeys"
        static let sign = "sign"
        static let decrypt = "decrypt"
        static let deleteKeys = "deleteKeys"

    }
    
    struct BiometricsType {
        static let faceId = "faceId"
        static let fingerprint = "fingerprint"
        static let none = "none"
        static let undefined = "undefined"
    }
}
