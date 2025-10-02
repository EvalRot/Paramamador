plugins {
    id("java")
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.8")
    implementation("com.google.code.gson:gson:2.10.1")
}

// Configure Java 21 for compilation and toolchain
java {
    // Ensure Gradle uses a Java 21 toolchain (no need to run Gradle with JDK 21)
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
    // Explicitly target Java 21 bytecode
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })
}
