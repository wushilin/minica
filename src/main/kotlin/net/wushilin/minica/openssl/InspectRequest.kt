package net.wushilin.minica.openssl

data class InspectRequest(var cert:String, var info:Map<String, String>)