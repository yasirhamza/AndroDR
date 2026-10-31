// Top-level build file where you can add configuration options common to all sub-projects/modules.
buildscript {
    dependencies {
        constraints {
            // AGP and the Kotlin/KSP/Hilt plugins pull guava 32.0.1-jre..33.6.0-jre onto the build
            // classpath (GHSA-xxph-c9ww-hj94, fixed in 33.7.2). Build tooling only; never in the APK.
            classpath(libs.guava) { version { require(libs.versions.guava.get()) } }
        }
    }
}

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.hilt) apply false
    alias(libs.plugins.ksp) apply false
    alias(libs.plugins.detekt) apply false
}

// OWASP dependency-check plugin removed -- replaced by Dependabot in
// .github/dependabot.yml. The plugin kept timing out on the NVD feed.
