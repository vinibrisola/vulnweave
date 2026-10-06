plugins {
    java
    id("org.jetbrains.intellij.platform") version "2.19.0"
}

group = "com.vulnweave"
version = "0.12.4"

repositories {
    mavenCentral()
    intellijPlatform { defaultRepositories() }
}

dependencies {
    intellijPlatform { intellijIdeaCommunity("2025.1.1") }
}

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(21)) }
}

sourceSets {
    main {
        java.srcDirs("src")
        resources.srcDirs("resources")
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release.set(21)
}

intellijPlatform {
    pluginConfiguration {
        ideaVersion {
            sinceBuild = "251"
        }
    }
}
