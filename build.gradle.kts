plugins {
    id("org.springframework.boot") version "2.7.18"
    id("io.spring.dependency-management") version "1.1.7" 
    war
    java
}
group = project.findProperty("buildGroup") as String
version = project.findProperty("buildVersion") as String 
val profile = project.findProperty("profile") as String? ?: "dev"
val isDev = profile == "dev"
val packaging = (findProperty("packaging") as String?) ?: "jar"   
val isWar = packaging.equals("war", ignoreCase = true)
logger.lifecycle("📦 [PROFILE] = $profile (isDev=$isDev)")
java { 
    toolchain {
        languageVersion.set(JavaLanguageVersion.of((findProperty("javaVersion") as String).toInt()))
    } 
    withSourcesJar()
    withJavadocJar()
}  
dependencies {
    if (isWar) {
        providedRuntime("org.springframework.boot:spring-boot-starter-tomcat") 
    } else {
        implementation("org.springframework.boot:spring-boot-starter-tomcat")
    }
    // studio one platform starters
    implementation("studio.one.starter:studio-platform-starter:${property("studioOneVersion")}")
    implementation("studio.one.starter:studio-platform-starter-jasypt:${property("studioOneVersion")}")
    implementation("studio.one.starter:studio-platform-starter-objecttype:${property("studioOneVersion")}")
    implementation("studio.one.starter:studio-platform-starter-user:${property("studioOneVersion")}")
    implementation("studio.one.starter:studio-platform-starter-security:${property("studioOneVersion")}")
    implementation("studio.one.starter:studio-platform-starter-security-acl:${property("studioOneVersion")}")
    implementation("studio.one.starter:studio-platform-starter-objectstorage:${property("studioOneVersion")}")
    implementation("studio.one.starter:studio-platform-starter-objectstorage-aws:${property("studioOneVersion")}")
    implementation("studio.one.starter:studio-platform-starter-ai:${property("studioOneVersion")}")
    implementation("studio.one.starter:studio-platform-starter-realtime:${property("studioOneVersion")}")
    // studio one platform applicaiton module & starters
    implementation("studio.one.starter:studio-application-starter-avatar:${property("studioOneVersion")}")
    implementation("studio.one.starter:studio-application-starter-attachment:${property("studioOneVersion")}") 
    implementation("studio.one.starter:studio-application-starter-mail:${property("studioOneVersion")}") 
    implementation("studio.one.starter:studio-application-starter-template:${property("studioOneVersion")}")         
    implementation("studio.one.modules:content-embedding-pipeline:${property("studioOneVersion")}")
    implementation("studio.one.starter:studio-application-starter-pages:${property("studioOneVersion")}")   
    implementation("studio.one.starter:studio-application-starter-forums:${property("studioOneVersion")}")  
    implementation("studio.one.modules:content-embedding-pipeline:${property("studioOneVersion")}")
    implementation("studio.one.api:studio-platform-identity:${property("studioOneVersion")}")
    implementation("studio.one.api:studio-platform-user-default:${property("studioOneVersion")}")
    // srping starters 
    implementation("org.springframework.boot:spring-boot-starter-validation") 
    implementation("org.springframework.boot:spring-boot-starter-aop") 
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-security") 
    implementation("org.springframework.boot:spring-boot-starter-cache")
    implementation("com.github.ben-manes.caffeine:caffeine")
    implementation("org.springframework.boot:spring-boot-starter-mail")
    implementation("org.springframework.boot:spring-boot-starter-websocket")

    // spring mamagement starter
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    // database driver
    runtimeOnly("org.postgresql:postgresql:${project.findProperty("postgresqlVersion")}")    
    implementation("org.bgee.log4jdbc-log4j2:log4jdbc-log4j2-jdbc4.1:${project.findProperty("log4jdbcLog4j2Version")}")
    implementation("org.flywaydb:flyway-core")
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
    // AI TEXT Extraction
    implementation("org.apache.pdfbox:pdfbox:${property("apachePdfBoxVersion")}")
    implementation("org.apache.poi:poi-ooxml:${property("apachePoiVersion")}")
    implementation("org.apache.poi:poi:${property("apachePoiVersion")}")
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
        providers.gradleProperty("gemini.api.key").orNull?.let { systemProperty("GEMINI_API_KEY", it) }
    }  
}