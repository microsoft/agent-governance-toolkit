// Spring AI integration of the Agent Control Specification Java SDK: guarded tool callbacks (which covers MCP tools, as Spring AI
// exposes them as ToolCallbacks) and a chat client advisor for the model call.
plugins {
    `java-library`
}

group = "com.microsoft.agentgovernance"
base.archivesName.set("agent-control-specification-spring-ai")
version = rootProject.version

val jdk = providers.gradleProperty("acs.jdk").orNull?.toInt()

java {
    if (jdk != null) {
        toolchain.languageVersion.set(JavaLanguageVersion.of(jdk))
    }
}

repositories {
    mavenCentral()
}

dependencies {
    api(rootProject)
    api(platform("org.springframework.ai:spring-ai-bom:2.0.1"))
    api("org.springframework.ai:spring-ai-model")
    api("org.springframework.ai:spring-ai-client-chat")

    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(25)
    options.encoding = "UTF-8"
}

tasks.test {
    useJUnitPlatform()
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
