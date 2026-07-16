buildscript {
    dependencies {
        constraints {
            // Build-classpath security constraints (the plugins{} block below
            // resolves into this project's buildscript classpath, so these
            // live HERE, not in the root build file). Policy: a fix exists ->
            // bump, never suppress. None of these artifacts ship in the APK.
            // If this repo ever goes multi-module, duplicate this block in
            // every module that applies these plugins (or hoist to a
            // convention plugin) — it is module-local.

            // CycloneDX plugin (SBOM) pulls jackson-databind 2.20.1, carrying
            // GHSA-j3rv-43j4-c7qm + GHSA-rmj7-2vxq-3g9f (high) and the residual
            // GHSA-5jmj-h7xm-6q6v (medium, <2.21.5). 2.21.5 clears all three.
            // This constraint reaches it because CycloneDX is applied in this
            // project's plugins{} block. Drop once the plugin ships a patched
            // jackson itself (still 3.3.0 as of 2026-07-16).
            classpath("com.fasterxml.jackson.core:jackson-databind:2.21.5")

            // NOTE: the bcprov-jdk18on 1.77 critical (GHSA-574f-3g2m-x479) is
            // NOT fixable here — it is a transitive of the Android Gradle
            // Plugin, resolved on the pluginManagement classpath that a
            // per-project buildscript constraint cannot reach (verified: the
            // constraint was a no-op). It clears with an AGP bump (8.7.3 ->
            // a release shipping BC >= 1.80.2), which also requires a Gradle
            // wrapper bump — tracked as a separate toolchain-upgrade PR.
            // It is build-classpath only and never ships in the APK/AAB.
        }
    }
}

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
    alias(libs.plugins.detekt)
    alias(libs.plugins.cyclonedx.bom)
}

android {
    namespace = "com.androdr"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.androdr"
        minSdk = 26
        targetSdk = 36

        // Version code is the commit count on origin/main, NOT on the
        // current HEAD. Building a feature branch used to produce a larger
        // versionCode than the release AAB (because feature branches have
        // extra commits), which surfaced as "wrong version in About" vs
        // the Play Store install. Pinning to origin/main keeps debug and
        // release versions consistent.
        //
        // Floor at 439 for Play Store acceptance — earlier uploads consumed
        // the 1..438 range. Once the commit count naturally overtakes 439
        // the floor becomes dead weight.
        val mainBuildNumber = providers.exec {
            isIgnoreExitValue = true
            commandLine("git", "rev-list", "--count", "origin/main")
        }.standardOutput.asText.get().trim().toIntOrNull()
            ?: providers.exec {
                commandLine("git", "rev-list", "--count", "HEAD")
            }.standardOutput.asText.get().trim().toIntOrNull() ?: 1
        versionCode = maxOf(mainBuildNumber, 439)
        versionName = "0.9.0.$versionCode"

        // Release note: use the HEAD commit's subject line — that's what was just
        // built. Earlier revisions used `git log --grep=^feat(` which walked HEAD
        // backward through all reachable history and returned the most recent
        // `feat:` commit *anywhere*. On a fix/chore release that produced a
        // subject from an unrelated feature months ago. See #150.
        val headSubjectRaw = runCatching {
            providers.exec {
                isIgnoreExitValue = true
                commandLine("git", "log", "-1", "--pretty=%s", "HEAD")
            }.standardOutput.asText.get().trim().takeIf { it.isNotBlank() }
        }.getOrNull() ?: "See CHANGELOG for details"

        // Strip the conventional-commit prefix and any trailing squash-merge PR
        // number so the About screen reads naturally. Quotes escaped for the
        // buildConfigField literal.
        val conventionalPrefix = Regex(
            """^(feat|fix|chore|docs|refactor|test|ci|build|perf|style)(\([^)]*\))?:\s*"""
        )
        // Squash-merge commits can carry multiple trailing issue/PR references
        // (e.g. "feat: X (#151) (#152)") — strip them all; release notes shown
        // in Settings shouldn't include issue numbers.
        val trailingPrNumber = Regex("""(\s*\(#\d+\))+\s*$""")
        val releaseNote = headSubjectRaw
            .replace(conventionalPrefix, "")
            .replace(trailingPrNumber, "")
            .replace("\"", "\\\"")

        buildConfigField("String", "RELEASE_NOTE", "\"$releaseNote\"")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        vectorDrawables {
            useSupportLibrary = true
        }
    }

    signingConfigs {
        create("release") {
            storeFile = file(providers.gradleProperty("RELEASE_KEYSTORE_PATH")
                .getOrElse("${rootProject.projectDir}/release-keystore.jks"))
            storePassword = providers.gradleProperty("RELEASE_STORE_PASSWORD").getOrElse("")
            keyAlias = providers.gradleProperty("RELEASE_KEY_ALIAS").getOrElse("androdr")
            keyPassword = providers.gradleProperty("RELEASE_KEY_PASSWORD").getOrElse("")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = signingConfigs.getByName("release")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            ndk { debugSymbolLevel = "FULL" }
        }
        debug {
            isMinifyEnabled = false
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    testOptions {
        unitTests {
            isReturnDefaultValues = true  // prevents android.util.Log stubs from throwing in JUnit tests
        }
    }

    sourceSets {
        getByName("androidTest") {
            assets.srcDirs("schemas")
        }
    }

    lint {
        warningsAsErrors = true
        abortOnError = true
        // GradleDependency / AndroidGradlePluginVersion: dependency version pinning is intentional;
        // we track upgrade decisions explicitly rather than via lint noise.
        // ObsoleteSdkInt: the mipmap-anydpi-v26 folder is the Android Studio scaffold default;
        // renaming it would require manifest + AAPT reference updates with no functional benefit
        // since the adaptive icon is only drawn on API 26+ devices anyway.
        disable += setOf("GradleDependency", "AndroidGradlePluginVersion", "ObsoleteSdkInt")
    }
}

// SBOM for release evidence (#252). release.yml invokes :app:cyclonedxBom
// (aggregate), which CONSUMES cyclonedxDirectBom's output (verified in the
// task graph and plugin bytecode) — so the includeConfigs restriction below
// is effective for the shipped bom.json even though only the aggregate task
// is invoked. Aggregate emits JSON only.
tasks.cyclonedxBom {
    jsonOutput.set(layout.buildDirectory.file("reports/cyclonedx/bom.json"))
    xmlOutput.unsetConvention()
}
tasks.cyclonedxDirectBom {
    includeConfigs.set(listOf("releaseRuntimeClasspath"))
}

// KSP source sets for Room schema export (optional but recommended)
ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
    arg("room.incremental", "true")
    arg("room.expandProjection", "true")
}

detekt {
    config.setFrom("$rootDir/config/detekt.yml")
    buildUponDefaultConfig = true
}

dependencies {
    // AndroidX Core
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)

    // Compose BOM — manages all Compose library versions
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)

    // Navigation
    implementation(libs.androidx.navigation.compose)

    // Hilt
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
    implementation(libs.androidx.hilt.navigation.compose)

    // Room
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)

    // Coroutines
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)

    // kotlinx.serialization
    implementation(libs.kotlinx.serialization.json)

    // YAML parsing (SIGMA rule engine)
    implementation(libs.snakeyaml.engine)

    // Debug tooling
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)

    // DataStore
    implementation(libs.androidx.datastore.preferences)

    // WorkManager
    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.androidx.hilt.work)
    ksp(libs.androidx.hilt.compiler)

    // Unit tests
    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.org.json) // provides org.json.JSONObject for JVM unit tests
    testImplementation(libs.json.schema.validator)

    // Instrumented tests
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.room.testing)
}
