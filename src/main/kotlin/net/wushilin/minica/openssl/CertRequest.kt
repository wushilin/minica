package net.wushilin.minica.openssl

data class CertRequest(var commonName:String, var countryCode:String, var organization:String, var validDays:Int = 365,
                       var state:String="", var city:String="", var organizationUnit:String="",
                       var digestAlgorithm:String = "sha256", var keyLength:Int = 4096, var dnsList:List<String> = listOf(), var ipList:List<String> = listOf())