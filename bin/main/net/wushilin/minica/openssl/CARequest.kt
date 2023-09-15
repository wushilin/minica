package net.wushilin.minica.openssl

data class CARequest(var commonName:String, var countryCode:String, var organization:String, var validDays:Int = 365,
                     var state:String="", var city:String="", var organizationUnit:String="",
                     var digestAlgorithm:String = "sha256", var keyLength:Int = 4096, val password:String="")