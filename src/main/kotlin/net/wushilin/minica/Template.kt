package net.wushilin.minica

class Template(private var what:String){
    fun apply(tag:String, replacement:String):Template {
        this.what = this.what.replace(tag, replacement)
        return this
    }

    val result:String
        get() = what
}