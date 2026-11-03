import java.io.File
import org.apache.tools.ant.taskdefs.condition.Os
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.logging.LogLevel
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.TaskAction
import javax.inject.Inject
import org.gradle.process.ExecOperations

abstract class BuildTask : DefaultTask() {
    @get:Inject
    abstract val execOperations: ExecOperations

    @Input
    var rootDirRel: String? = null
    @Input
    var projectDir: String? = null
    @Input
    var target: String? = null
    @Input
    var release: Boolean? = null

    @TaskAction
    fun assemble() {
        val executable = """npm""";
        var lastException: Exception? = null
        try {
            runTauriCli(executable)
            return
        } catch (e: Exception) {
            lastException = e
            if (Os.isFamily(Os.FAMILY_WINDOWS)) {
                val fallbacks = listOf(
                    "$executable.exe",
                    "$executable.cmd",
                    "$executable.bat",
                )

                for (fallback in fallbacks) {
                    try {
                        runTauriCli(fallback)
                        return
                    } catch (fallbackException: Exception) {
                        lastException = fallbackException
                    }
                }
            }
        }

        // Fallback: If Tauri CLI options server is not running (e.g. direct Gradle or Android Studio build),
        // build or copy libvult_lib.so for the current target
        val abi = when (target) {
            "aarch64" -> "arm64-v8a"
            "armv7" -> "armeabi-v7a"
            "i686" -> "x86"
            "x86_64" -> "x86_64"
            else -> target ?: "arm64-v8a"
        }
        val jniLib = File(projectDir, "src/main/jniLibs/$abi/libvult_lib.so")
        val rustTargetTriple = when (target) {
            "aarch64" -> "aarch64-linux-android"
            "armv7" -> "armv7-linux-androideabi"
            "i686" -> "i686-linux-android"
            "x86_64" -> "x86_64-linux-android"
            else -> "$target-linux-android"
        }
        val targetSo = File(projectDir, "../../../target/$rustTargetTriple/${if (release == true) "release" else "debug"}/libvult_lib.so")

        // If targetSo does not exist or jniLib is missing, invoke cargo build directly
        if (!targetSo.exists() || !jniLib.exists()) {
            val userCargo = File(System.getProperty("user.home"), ".cargo/bin/cargo" + if (Os.isFamily(Os.FAMILY_WINDOWS)) ".exe" else "")
            val cargoCmd = if (userCargo.exists()) userCargo.absolutePath else (if (Os.isFamily(Os.FAMILY_WINDOWS)) "cargo.exe" else "cargo")
            val cargoArgs = mutableListOf("build", "--target", rustTargetTriple)
            if (release == true) {
                cargoArgs.add("--release")
            }
            logger.lifecycle("[BuildTask] Running $cargoCmd ${cargoArgs.joinToString(" ")}...")
            try {
                execOperations.exec {
                    workingDir(File(projectDir, "../../../src-tauri"))
                    executable(cargoCmd)
                    args(cargoArgs)
                }.assertNormalExitValue()
            } catch (cargoErr: Exception) {
                logger.warn("[BuildTask] Direct cargo build failed: ${cargoErr.message}")
            }
        }

        if (targetSo.exists()) {
            if (!jniLib.exists() || targetSo.lastModified() > jniLib.lastModified()) {
                jniLib.parentFile.mkdirs()
                targetSo.copyTo(jniLib, overwrite = true)
                logger.lifecycle("[BuildTask] Copied $targetSo to $jniLib")
            } else {
                logger.lifecycle("[BuildTask] Using up-to-date library at $jniLib")
            }
            return
        }

        if (jniLib.exists()) {
            logger.lifecycle("[BuildTask] Using existing library at $jniLib")
            return
        }

        throw lastException ?: GradleException("Could not build or find libvult_lib.so for $target")
    }

    fun runTauriCli(executable: String) {
        val rootDirRel = rootDirRel ?: throw GradleException("rootDirRel cannot be null")
        val target = target ?: throw GradleException("target cannot be null")
        val release = release ?: throw GradleException("release cannot be null")
        val args = listOf("run", "--", "tauri", "android", "android-studio-script");

        execOperations.exec {
            workingDir(File(projectDir, rootDirRel))
            executable(executable)
            args(args)
            if (logger.isEnabled(LogLevel.DEBUG)) {
                args("-vv")
            } else if (logger.isEnabled(LogLevel.INFO)) {
                args("-v")
            }
            if (release) {
                args("--release")
            }
            args(listOf("--target", target))
        }.assertNormalExitValue()
    }
}