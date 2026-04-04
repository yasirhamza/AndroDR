pluginManagement {
    repositories {
        google()
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "adversary-fixtures"
include(
    ":spyware-package-name",
    ":cert-hash-ioc",
    ":accessibility-abuse",
    ":device-admin-abuse",
    ":surveillance-permissions",
    ":system-name-disguise",
    ":impersonation-play-store",
    ":multi-abuse-combo",
    ":firmware-implant-sim",
    ":notification-listener-abuse"
)
