plugins { id("com.android.application") }
android {
    namespace = "com.android.providers.settings.backup"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.android.providers.settings.backup"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }
}
