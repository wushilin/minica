package net.wushilin.minica

import java.io.File
import java.util.*

class IO {
    companion object {
        val random = Random(System.nanoTime())
        fun readFile(input:File):ByteArray {
            input.inputStream().use {
                return it.readAllBytes()
            }
        }

        fun readFileAsString(input:File):String {
            return String(readFile(input))
        }

        fun readClassPath(input:String):String {
            IO::class.java.getResourceAsStream(input).use {
                return String(it.readAllBytes())
            }
        }

        fun copy(path1:String, path2:String):Boolean {
            File(path1).copyTo(File(path2), true)
            return true
        }

        fun randomPassword(n:Int):String {
            val characterSet = "13456789ABCEFGHIJKLMNPQRSTUVWXY"

            val password = StringBuilder()

            for (i in 0 until n)
            {
                val rIndex = random.nextInt(characterSet.length)
                password.append(characterSet[rIndex])
            }

            return password.toString()
        }
    }
}