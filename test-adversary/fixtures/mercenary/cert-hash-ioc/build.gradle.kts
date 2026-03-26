plugins { id("com.android.application") }
android {
    namespace = "com.androdr.fixture.certhash"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.androdr.fixture.certhash"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }
    signingConfigs {
        create("certHashTest") {
            storeFile = file("../cert-hash-ioc-keystore.jks")
            storePassword = "adversary-test"
            keyAlias = "cert-hash-test"
            keyPassword = "adversary-test"
        }
    }
    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("certHashTest")
        }
    }
}
