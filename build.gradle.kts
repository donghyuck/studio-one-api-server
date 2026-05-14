plugins {
    id("org.springframework.boot")
    id("io.spring.dependency-management")
    war
    java
}

fun prop(vararg keys: String, default: String? = null): String {
    for (key in keys) {
        val value = findProperty(key)?.toString()?.trim()
        if (!value.isNullOrEmpty()) {
            return value
        }
    }
    return default ?: error("Missing Gradle property. Expected one of: ${keys.joinToString()}")
}

group = prop("buildGroup", "buildApplicationGroup")
version = prop("buildVersion", "buildApplicationVersion")
description = findProperty("buildApplicationName") as? String ?: project.name
val profile = project.findProperty("profile") as String? ?: "dev"
val isDev = profile == "dev"
val packaging = (findProperty("packaging") as String?) ?: "jar"   
val isWar = packaging.equals("war", ignoreCase = true)
logger.lifecycle("📦 [PROFILE] = $profile (isDev=$isDev)")
val javaVersion = prop("javaVersion", "sourceCompatibility", "targetCompatibility", default = "17")
val studioApiVersion = prop("studioOneVersion", default = "1.0.0")
val apachePdfBoxVersion = prop("apachePdfBoxVersion", default = "2.0.30")
val apachePoiVersion = prop("apachePoiVersion", default = "5.2.5")
val jsoupVersion = prop("jsoupVersion", default = "1.21.2")
val studioLocalCacheRoot = file("${System.getProperty("user.home")}/.gradle/caches/modules-2/files-2.1")
val studioLocalCacheArtifacts = setOf(
    "studio-platform",
    "studio-platform-autoconfigure",
    "studio-platform-data",
    "studio-platform-objecttype",
    "studio-platform-user",
    "studio-platform-user-default",
    "studio-platform-security",
    "studio-platform-security-acl",
    "studio-platform-realtime",
    "studio-platform-ai",
    "studio-platform-identity",
    "studio-platform-starter",
    "studio-platform-starter-jasypt",
    "studio-platform-starter-objecttype",
    "studio-platform-starter-user",
    "studio-platform-starter-security",
    "studio-platform-starter-security-acl",
    "studio-platform-starter-ai",
    "studio-platform-starter-realtime",
    "avatar-service",
    "attachment-service",
    "mail-service",
    "template-service",
    "content-embedding-pipeline",
    "studio-application-starter-avatar",
    "studio-application-starter-attachment",
    "studio-application-starter-mail",
    "studio-application-starter-template"
)
val useStudioLocalCache = (findProperty("useStudioLocalCache") as String?)?.toBooleanStrictOrNull()
    ?: false
val studioLocalCacheJars = if (useStudioLocalCache) {
    studioLocalCacheRoot
        .walkTopDown()
        .filter { it.isFile && it.extension == "jar" }
        .filter { it.invariantSeparatorsPath.contains("/studio.one") }
        .filter { it.invariantSeparatorsPath.contains("/$studioApiVersion/") }
        .filter { file ->
            studioLocalCacheArtifacts.any { artifact ->
                file.name == "$artifact-$studioApiVersion.jar" ||
                    file.name == "$artifact-$studioApiVersion-plain.jar"
            }
        }
        .groupBy { it.name }
        .map { (_, files) -> files.minByOrNull { it.absolutePath.length }!! }
} else {
    emptyList()
}
java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(javaVersion.toInt()))
    }
    sourceCompatibility = JavaVersion.toVersion(javaVersion)
    targetCompatibility = JavaVersion.toVersion(javaVersion)
    withSourcesJar()
    withJavadocJar()
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(javaVersion.toInt())
}

dependencies {
    if (isWar) {
        providedRuntime("org.springframework.boot:spring-boot-starter-tomcat")
    } else {
        implementation("org.springframework.boot:spring-boot-starter-tomcat")
    }
    if (useStudioLocalCache) {
        logger.lifecycle("📦 [DEPENDENCIES] Using local studio.one Gradle cache fallback: $studioLocalCacheRoot")
        implementation(files(studioLocalCacheJars))
    } else {
        // studio one platform starters
        implementation("studio.one.starter:studio-platform-starter:$studioApiVersion")
        implementation("studio.one.starter:studio-platform-starter-jasypt:$studioApiVersion")
        implementation("studio.one.starter:studio-platform-starter-objecttype:$studioApiVersion")
        implementation("studio.one.starter:studio-platform-starter-user:$studioApiVersion")
        implementation("studio.one.starter:studio-platform-starter-security:$studioApiVersion")
        implementation("studio.one.starter:studio-platform-starter-security-acl:$studioApiVersion")
        implementation("studio.one.starter:studio-platform-starter-objectstorage:$studioApiVersion")
        implementation("studio.one.starter:studio-platform-starter-objectstorage-aws:$studioApiVersion")
        implementation("studio.one.starter:studio-platform-starter-ai:$studioApiVersion")
        implementation("studio.one.starter:studio-platform-starter-ai-web:$studioApiVersion")
        implementation("studio.one.starter:studio-platform-starter-chunking:$studioApiVersion")
        implementation("studio.one.starter:studio-platform-starter-realtime:$studioApiVersion")
        implementation("studio.one.starter:studio-platform-starter-workspace:$studioApiVersion")
        implementation("studio.one.starter:studio-platform-thumbnail-starter:$studioApiVersion")
        // studio one platform applicaiton module & starters
        implementation("studio.one.starter:studio-application-starter-avatar:$studioApiVersion")
        implementation("studio.one.starter:studio-application-starter-attachment:$studioApiVersion")
        implementation("studio.one.starter:studio-application-starter-mail:$studioApiVersion")
        implementation("studio.one.starter:studio-application-starter-template:$studioApiVersion")
        implementation("studio.one.modules:content-embedding-pipeline:$studioApiVersion")
        implementation("studio.one.api:studio-platform-identity:$studioApiVersion")
        implementation("studio.one.api:studio-platform-user-default:$studioApiVersion")
    }
    // spring starters
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-aop")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.security:spring-security-acl")
    implementation("org.springframework.boot:spring-boot-starter-cache")
    implementation("com.github.ben-manes.caffeine:caffeine")
    implementation("org.springframework.boot:spring-boot-starter-mail")
    implementation("org.springframework.boot:spring-boot-starter-websocket")
    implementation("javax.servlet:javax.servlet-api:4.0.1")
    implementation("org.apache.commons:commons-lang3")

    // spring mamagement starter
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    // database driver
    runtimeOnly("org.postgresql:postgresql:${project.findProperty("postgresqlVersion")}")    
    implementation("org.bgee.log4jdbc-log4j2:log4jdbc-log4j2-jdbc4.1:${project.findProperty("log4jdbcLog4j2Version")}")
    implementation("org.flywaydb:flyway-core:${project.findProperty("flywayVersion")}")
    //test
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    //lombok
    val lombokVersion: String = project.findProperty("lombokVersion") as String? ?: "1.18.30"
    compileOnly("org.projectlombok:lombok:$lombokVersion")
    annotationProcessor("org.projectlombok:lombok:$lombokVersion")
    testCompileOnly("org.projectlombok:lombok:$lombokVersion")
    testAnnotationProcessor("org.projectlombok:lombok:$lombokVersion")
    //mapstruct 사용의 경우 의존성 추가.

    // implementation ("org.mapstruct:mapstruct:${project.findProperty("mapstructVersion")}")   
    // annotationProcessor ("org.mapstruct:mapstruct-processor:${project.findProperty("mapstructVersion")}")   
    // annotationProcessor ("org.projectlombok:lombok-mapstruct-binding:0.2.0")

    // Document processing dependencies shared by textract and thumbnail.
    // studio-platform-textract declares these as compileOnly; the application supplies runtime libraries.
    // studio-platform-thumbnail uses PDFBox for PDF rasterizing, POI for PPTX,
    // and textract output for DOCX/HWP/HWPX preview thumbnails.
    implementation("org.apache.pdfbox:pdfbox:$apachePdfBoxVersion")
    implementation("org.apache.poi:poi-ooxml:$apachePoiVersion")
    implementation("org.apache.poi:poi:$apachePoiVersion")
    implementation("org.jsoup:jsoup:$jsoupVersion")
    implementation("net.sourceforge.tess4j:tess4j:${property("tesseractVersion")}")

}
tasks.test { useJUnitPlatform() }
tasks.getByName<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
    enabled = !isWar
}
tasks.getByName<org.springframework.boot.gradle.tasks.bundling.BootWar>("bootWar") {
    enabled = isWar
}
tasks.jar {
    enabled = false
}
tasks.named<org.springframework.boot.gradle.tasks.run.BootRun>("bootRun") {
    systemProperty("spring.profiles.active", profile)
    logger.lifecycle("📦 [BOOT RUN] spring.profiles.active=$profile")
    if (isDev) {
        val pw = providers.gradleProperty("JASYPT_ENCRYPTOR_PASSWORD").orNull
            ?: providers.gradleProperty("jasypt.encryptor.password").orNull
        if (!pw.isNullOrBlank()) {
            systemProperty("JASYPT_ENCRYPTOR_PASSWORD", pw)
            logger.lifecycle("📦 [BOOT RUN] JASYPT_ENCRYPTOR_PASSWORD is set")
        }
        // null이면 아예 설정하지 않도록(불필요한 "null" 문자열 방지)
        providers.gradleProperty("mail.host").orNull?.let { systemProperty("MAIL_HOST", it) }
        providers.gradleProperty("mail.port").orNull?.let { systemProperty("MAIL_PORT", it) }
        providers.gradleProperty("mail.user").orNull?.let { systemProperty("MAIL_USER", it) }
        providers.gradleProperty("mail.password").orNull?.let { systemProperty("MAIL_PASSWORD", it) }
       // s3 관련 설정
        providers.gradleProperty("s3.accessKey").orNull?.let { systemProperty("S3_ACCESS_KEY", it) }
        providers.gradleProperty("s3.secretKey").orNull?.let { systemProperty("S3_SECRET_KEY", it) } 
        // ai 관련 설정
        providers.gradleProperty("gemini.api.key").orNull?.let {
            systemProperty("GEMINI_API_KEY", it)
        }
        providers.gradleProperty("openai.api.key").orNull?.let {
            systemProperty("OPENAI_API_KEY", it)
        }
        providers.gradleProperty("openai.provider.enabled").orNull?.let {
            systemProperty("OPENAI_PROVIDER_ENABLED", it)
        }
    }  
}
