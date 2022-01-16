package net.wushilin.minica.openssl

import java.io.File
import java.text.SimpleDateFormat
import java.util.regex.Pattern

class CertParser {
    companion object {
        fun parseCert(cert:String):Map<String, String> {
            val out = mutableMapOf<String, String> ()
            val result = Run.ExecWait(File("."), 60000, cert.byteInputStream(), listOf("keytool", "-printcert"))
            if(result.isSuccessful()) {
                val stdout = result.stdout()
                out["version"] = readVersion(stdout)
                out["serial"] = readSerialNumber(stdout)
                out["isCA"] = readIsCA(stdout)
                println("PKI Algorithm: " + readPublicKeyAlgorithm(stdout))
                out["pkiAlgorithm"] = readPublicKeyAlgorithm(stdout)
                out["signatureAlgorithm"] = readSignatureAlgorithm(stdout)
                out["keyUsage"] = readKeyUsage(stdout).joinToString(",")
                out["extendedKeyUsage"] = readExtendedKeyUsage(stdout).joinToString(",")
                out["dnsList"] = readDNSList(stdout).joinToString(",")
                out["ipList"] = readIPList(stdout).joinToString(",")
                val startend = readStartEnd(stdout)
                out["validityStart"] = startend[0].toString()
                out["validityEnd"] = startend[1].toString()
                val issuer = readKey(stdout, "Issuer")
                val owner = readKey(stdout, "Owner")
                val caDetail = readCertDetail(issuer)
                val certDetail = readCertDetail(owner)
                out["certCountryCode"] = certDetail["countryCode"]!!
                out["certCommonName"] = certDetail["commonName"]!!
                out["certOrganization"] = certDetail["organization"]!!
                out["certOrganizationUnit"] = certDetail["organizationUnit"]!!
                out["certCity"] = certDetail["city"]!!
                out["certState"] = certDetail["state"]!!
                out["caCountryCode"] = caDetail["countryCode"]!!
                out["caCommonName"] = caDetail["commonName"]!!
                out["caOrganization"] = caDetail["organization"]!!
                out["caOrganizationUnit"] = caDetail["organizationUnit"]!!
                out["caCity"] = caDetail["city"]!!
                out["caState"] = caDetail["state"]!!
            } else {
                println("Impossible ${result}")
            }

            return out
        }

        fun readCertDetail(input:String):Map<String, String>{
            val result = mutableMapOf<String, String>()
            result["countryCode"] = extractByKey(input, "C")
            result["commonName"] = extractByKey(input, "CN")
            result["organization"] = extractByKey(input, "O")
            result["organizationUnit"] = extractByKey(input, "OU")
            result["city"] = extractByKey(input, "L")
            result["state"] = extractByKey(input, "ST")
            return result
        }

        fun extractByKey(input:String, code:String):String {
            val regex = Pattern.compile("(, )?$code=([^,]+),?", Pattern.CASE_INSENSITIVE)
            val matcher = regex.matcher(input)
            if(matcher.find()) {
                return matcher.group(2)
            }

            return ""
        }
        fun readSerialNumber(input:String):String {
            return readKey(input, "Serial number").split(" ")[0]
        }

        fun keyed(str:List<String>):Map<String, String> {
            val result = mutableMapOf<String, String>()
            str.map{it.trim()}.filter{it.isNotBlank()}.forEach {
                val index = it.indexOf(":")
                if(index == -1) {
                    result.put(it, "")
                } else {
                    result.put(it.substring(0, index), it.substring(index + 1).trim())
                }
            }
            return result
        }
        fun readIsCA(input:String):String {
            return keyed(readSection(input, "BasicConstraints"))["CA"].orEmpty()
        }

        fun readExtendedKeyUsage(input:String):List<String> {
            return readSection(input, "ExtendedKeyUsages")
        }

        fun readKeyUsage(input:String):List<String> {
            return readSection(input, "KeyUsage")
        }

        fun readDNSList(input:String):List<String> {
            val section = readSection(input, "SubjectAlternativeName")
            return section.filter { it.startsWith("DNSName:") }.map {
                val index = it.indexOf(":")
                if(index < 0) {
                    ""
                } else {
                    it.substring(index + 1).trim()
                }
            }.filter{it.isNotBlank()}.toList()
        }

        fun readIPList(input:String):List<String> {
            val section = readSection(input, "SubjectAlternativeName")
            return section.filter { it.startsWith("IPAddress:") }.map {
                val index = it.indexOf(":")
                if(index < 0) {
                    ""
                } else {
                    it.substring(index + 1).trim()
                }
            }.filter{it.isNotBlank()}.toList()
        }

        fun readStartEnd(input:String):List<Long> {
            val line = readKey(input, "Valid from")
            val tokens = line.split(Regex("\\s+until:\\s+"))
            val sdf = SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy")
            val start = sdf.parse(tokens[0])
            val end = sdf.parse(tokens[1])
            return listOf(start.time, end.time)
        }
        fun readPublicKeyAlgorithm(input:String):String {
            return readKey(input, "Subject Public Key Algorithm")
        }
        fun readSignatureAlgorithm(input:String):String {
            return readKey(input, "Signature algorithm name")
        }
        fun readVersion(input:String):String {
            return readKey(input, "Version").split(" ")[0]
        }

        fun readSection(input:String, key:String):List<String> {
            val regex = Pattern.compile("\\n\\s*$key:?\\s*\\[([^\\]]+)\\]", Pattern.DOTALL)
            val matcher = regex.matcher(input)
            if(matcher.find()) {
                val content = matcher.group(1)
                val tokens = content.split(Regex("\\n"))
                return tokens.map{ it.trim() }.filter { it.isNotBlank() }.toList()
            } else {
                return listOf()
            }
        }

        fun readKey(input:String, key:String):String {
            val listResult = readKeyList(input, key)
            if(listResult.isEmpty()) {
                return ""
            }
            return listResult[0]
        }
        fun readKeyList(input:String, key:String):List<String> {
            val regex = Pattern.compile("\\n?\\s*${key}: (.*)\\n")
            val matcher = regex.matcher(input)
            val result = mutableListOf<String>()
            while(matcher.find()) {
                result.add(matcher.group(1))
            }
            return result
        }
        fun match(input:String, regex:String, group:Int):String {
            val regex = Pattern.compile(regex)
            val matcher = regex.matcher(input)
            return if(matcher.find()) {
                matcher.group(group)
            } else {
                ""
            }
        }
    }
}
