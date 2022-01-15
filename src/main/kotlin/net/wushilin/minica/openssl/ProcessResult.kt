package net.wushilin.minica.openssl;

data class ProcessResult(val pid:Long, val startMs:Long, val endMs:Long, val exitCode:Int, val stdout:ByteArray, val stderr:ByteArray) {
    private val stdoutList = mutableListOf<String>()
    private val stderrList = mutableListOf<String>()
    private val stdoutString = String(stdout)
    private val stderrString = String(stderr)
    init {
        var split = stdoutString.split("\n")
        split.forEach {
            stdoutList.add(it)
        }

        split = stderrString.split("\n")
        split.forEach {
            stderrList.add(it)
        }
    }
    override fun toString():String {
        return "ProcessResult[#pid=$pid, code=$exitCode, stdout=>>>>>${stdoutString}<<<<<, stderr=>>>>>${stderrString}<<<<<, duration=${endMs-startMs}ms#]"
    }

    fun isSuccessful():Boolean {
        return exitCode == 0
    }

    fun error():String = stderrString

    fun stdout():String = stdoutString

    fun errors():List<String> {
        return stderrList
    }

    fun outputs():List<String> {
        return stdoutList
    }
}
