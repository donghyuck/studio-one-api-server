pluginManagement {
    val springBootVersion: String by settings
    val springDependencyManagementVersion: String by settings
    repositories {
        gradlePluginPortal()
        mavenCentral()
        mavenLocal()
    }
    plugins {
        id("org.springframework.boot") version springBootVersion
        id("io.spring.dependency-management") version springDependencyManagementVersion
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
        mavenLocal()
        maven { url = uri("https://maven.egovframe.go.kr/maven/") }
        val allowInsecure = providers.gradleProperty("nexus.allowInsecure").orNull?.toBoolean() ?: false
        providers.gradleProperty("nexus.releasesUrl").orNull?.let { url ->
            maven(url) {
                name = "podosoftware-nexus-releases"
                isAllowInsecureProtocol = allowInsecure
            }
        }
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.9.0"
}

rootProject.name = providers.gradleProperty("buildApplicationName").get()

val defaultStudioApiDir = file("/Users/donghyuck.son/git/studio-api")
val studioApiDir = providers.gradleProperty("studioApiDir")
    .orNull
    ?.takeIf { it.isNotBlank() }
    ?.let(::file)
    ?: defaultStudioApiDir
val useStudioApiComposite = providers.gradleProperty("useStudioApiComposite")
    .orNull
    ?.toBoolean()
    ?: studioApiDir.isDirectory

if (useStudioApiComposite) {
    logger.lifecycle("🧩 Including studio-api composite build from ${studioApiDir.absolutePath}")
    includeBuild(studioApiDir)
}
