plugins { id("com.android.application") }
// Uses com.cerberus.rat, an invented package name removed from AndroDR's
// bundled IOC list on 2026-10-15. Installing it must produce only the
// sideloaded-app finding, never a known-malicious-package match.
android {
    namespace = "com.cerberus.rat"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.cerberus.rat"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }
}
