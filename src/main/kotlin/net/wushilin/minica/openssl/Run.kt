package net.wushilin.minica.openssl;

import org.slf4j.LoggerFactory
import java.io.BufferedReader
import java.io.File
import java.io.InputStream
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

public class Run {
    companion object {
        val log = LoggerFactory.getLogger(Run::class.java)
        fun ExecWait(workingDirectory: File, timeoutMs:Long, stdin: InputStream?=null, args: List<String>): ProcessResult {
            val pb = ProcessBuilder(args)
            pb.directory(workingDirectory)
            log.info("Starting process in $workingDirectory, timeout=$timeoutMs milliseconds, args $args")
            val startMs = System.currentTimeMillis()
            val process = pb.start()
            lateinit var stdout:ByteArray
            lateinit var stderr:ByteArray
            val stdoutThread = thread(name="stdout-reader") {
                process.inputStream.use {
                    stdout = it.readAllBytes()
                }
            }
            val stderrThread = thread(name="stderr-reader") {
                process.errorStream.use {
                    stderr = it.readAllBytes()
                }
            }

            var pipeThread: Thread? = null
            if(stdin != null) {
                pipeThread = thread(name = "input-writer") {
                    process.outputStream.use {
                        stdin.use { input ->
                            input.copyTo(process.outputStream)
                        }

                    }
                }
            }

            var realTimeoutMs = timeoutMs
            if(realTimeoutMs >= 1800000 || realTimeoutMs <= 0) {
                realTimeoutMs = 1800000
                log.info("Adjusted timeout: $realTimeoutMs milliseconds")
            }


            val waitResult = process.waitFor(realTimeoutMs, TimeUnit.MILLISECONDS)
            if(waitResult) {
                stdoutThread.join()
                stderrThread.join()
                pipeThread?.join()
            } else {
                process.destroyForcibly()
                stdoutThread.join()
                stderrThread.join()
                pipeThread?.join()
            }
            val exitCode = process.exitValue()
            val pid = process.pid()
            log.info("PID $pid, Exit code $exitCode, Duration ${System.currentTimeMillis() - startMs} milliseconds")
            return ProcessResult(pid, startMs, System.currentTimeMillis(), exitCode, stdout, stderr)
        }
    }
}
