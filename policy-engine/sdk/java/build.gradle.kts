// Java SDK for the Agent Control Specification (ACS).
//
// It reaches the Rust engine through the C ABI of `policy-engine/sdk/rust` with the Foreign Function & Memory API
// (java.lang.foreign, final since Java 22), so there is no JNI glue and no native code in this project.
//
//   JDK 25 or later builds it (language level 25); run Gradle with JAVA_HOME on that JDK, or pass -Pacs.jdk=<n> to select
//   a toolchain.
//   The native library is built separately (see README.md) and found through -Dacs.native.library=<path>,
//   the ACS_NATIVE_LIBRARY environment variable, or the resource /native/<os>-<arch>/ in the jar.

plugins {
    `java-library`
    `maven-publish`
}

group = "com.microsoft.agentgovernance"
version = "0.1.0-SNAPSHOT"

val jdk = providers.gradleProperty("acs.jdk").orNull?.toInt()

java {
    if (jdk != null) {
        toolchain.languageVersion.set(JavaLanguageVersion.of(jdk))
    }
    withSourcesJar()
    withJavadocJar()
}

repositories {
    mavenCentral()
}

dependencies {
    // JSON on the wire: the engine speaks JSON, the JDK has no JSON API.
    api("com.fasterxml.jackson.core:jackson-databind:2.22.3")

    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(25)
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).addStringOption("Xdoclint:none", "-quiet")
}

// Native libraries inside the jar (NativeLibrary finds them at /native/<os>-<arch>/<file>):
//  - ./gradlew stageNativeLibrary -Pacs.native.library=<built cdylib> copies it to build/native/<os>-<arch>/;
//  - -Pacs.native.bundle=<dir> adds a directory that already holds <os>-<arch>/<file> subfolders (for example the merged artifacts of a CI matrix).
// A jar built without either has no native code, and the library is found through acs.native.library / ACS_NATIVE_LIBRARY / the OS loader.
val platformName: String = run {
    val os = System.getProperty("os.name").lowercase()
    val arch = System.getProperty("os.arch").lowercase()
    val osName = if (os.contains("win")) "windows" else if (os.contains("mac") || os.contains("darwin")) "macos" else "linux"
    val archName = if (arch == "amd64" || arch == "x86_64") "x86_64" else if (arch == "aarch64" || arch == "arm64") "aarch64" else arch
    "$osName-$archName"
}
val stagedNative = layout.buildDirectory.dir("native")
val bundledNative = providers.gradleProperty("acs.native.bundle")

val stageNativeLibrary by tasks.registering(Copy::class) {
    description = "Copies the built native library (-Pacs.native.library) to build/native/<os>-<arch>/ so that the jar carries it."
    val library = providers.gradleProperty("acs.native.library").orNull
    onlyIf { library != null }
    if (library != null) {
        from(file(library))
    }
    into(stagedNative.map { it.dir(platformName) })
}

tasks.jar {
    dependsOn(stageNativeLibrary)
    from(stagedNative) { into("native") }
    bundledNative.orNull?.let { dir -> from(file(dir)) { into("native") } }
    manifest {
        attributes(
            "Automatic-Module-Name" to "com.microsoft.agentgovernance.acs",
            "Enable-Native-Access" to "ALL-UNNAMED",
        )
    }
}

val nativeLibrary = providers.gradleProperty("acs.native.library").orElse(providers.environmentVariable("ACS_NATIVE_LIBRARY"))

tasks.test {
    useJUnitPlatform()
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    // the real-library tests are skipped when this is not set (see NativeAvailability in the tests)
    nativeLibrary.orNull?.let { systemProperty("acs.native.library", it) }
    // repository root of the policy engine, for the conformance corpus
    systemProperty("acs.policy.engine.dir", layout.projectDirectory.dir("../..").asFile.absolutePath)
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            pom {
                name.set("Agent Control Specification Java SDK")
                description.set("Java host API for the Agent Control Specification engine, over its Rust C ABI (Foreign Function & Memory API).")
                url.set("https://github.com/microsoft/agent-governance-toolkit")
                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
            }
        }
    }
}
