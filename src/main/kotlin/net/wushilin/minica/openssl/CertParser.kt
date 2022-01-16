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

fun main(args:Array<String>) {
    val result = CertParser.parseCert("""
        Certificate:
            Data:
                Version: 3 (0x2)
                Serial Number: 1 (0x1)
                Signature Algorithm: sha512WithRSAEncryption
                Issuer: C=SG, ST=Singapore, L=Singapore, O=ABC Corp CA, OU=Home Office, CN=ABC CORP CA
                Validity
                    Not Before: Jan 16 03:07:48 2022 GMT
                    Not After : Feb 10 03:07:48 2042 GMT
                Subject: C=SG, ST=ST1, L=CITY1, O=ORG1, OU=OU1, CN=CN1
                Subject Public Key Info:
                    Public Key Algorithm: rsaEncryption
                        RSA Public-Key: (2048 bit)
                        Modulus:
                            00:d8:61:39:dd:03:7c:0a:a3:84:17:e5:f6:25:24:
                            04:9e:b6:9f:b6:23:e5:bd:01:e5:3b:1c:46:26:fd:
                            be:78:47:b7:30:ef:72:5d:f9:28:d2:11:39:84:3c:
                            ba:d0:5a:ff:e9:7f:17:c9:77:24:85:3f:f9:1b:e1:
                            fc:a0:81:b5:72:87:f8:1f:5a:e2:60:c6:cc:78:49:
                            c7:7c:eb:bc:bc:d5:f1:f7:75:6f:e1:f3:20:f0:f9:
                            da:3d:eb:2f:1d:e6:9c:ca:b0:83:a2:db:e9:87:ca:
                            bc:fc:4d:db:73:21:28:9b:5f:1c:2e:37:28:ff:64:
                            ee:f3:99:69:b3:ff:d4:23:ce:f4:6c:50:00:d4:fb:
                            a1:7b:bf:9c:5b:44:29:93:fa:3c:bf:d2:60:dc:6f:
                            9f:da:00:35:00:af:37:ce:15:d8:80:81:a6:14:ac:
                            5a:41:82:65:d9:f3:63:f1:a5:29:20:b2:e8:18:6b:
                            ed:96:76:db:0e:8c:3f:7e:8e:ab:c3:d2:f6:32:9e:
                            98:40:ed:41:a0:16:fe:0c:c5:0c:c5:fb:d7:a2:98:
                            0d:a1:d7:2a:ba:02:d8:02:b6:f9:ae:ef:d9:88:bf:
                            e9:ca:de:c6:11:53:bc:7d:0b:e5:02:a7:2e:1b:e1:
                            37:7c:5a:01:81:f1:18:58:34:6d:45:55:42:dc:73:
                            e5:11
                        Exponent: 65537 (0x10001)
                X509v3 extensions:
                    X509v3 Subject Key Identifier: 
                        31:49:7A:54:9A:F5:57:02:4F:9B:00:AD:A1:1D:7D:50:44:4D:9B:EB
                    X509v3 Authority Key Identifier: 
                        keyid:7C:C8:99:64:DD:BD:BB:88:6E:C2:BD:EB:E0:A7:77:50:4B:E5:0F:29

                    X509v3 Basic Constraints: 
                        CA:FALSE
                    X509v3 Key Usage: 
                        Digital Signature, Non Repudiation, Key Encipherment
                    X509v3 Extended Key Usage: 
                        TLS Web Client Authentication, E-mail Protection, TLS Web Server Authentication
                    X509v3 Subject Alternative Name: 
                        DNS:CN1, DNS:dns1, IP Address:192.168.44.6
                    Netscape Comment: 
                        OpenSSL Generated Certificate
            Signature Algorithm: sha512WithRSAEncryption
                 09:a7:00:73:16:d0:ad:4b:1d:4c:75:b6:71:82:38:6b:9f:9c:
                 76:b8:14:ad:3b:93:8f:44:30:ed:5b:42:68:75:09:f4:a2:b6:
                 62:bb:17:27:df:66:01:55:76:78:83:05:6c:27:4f:87:92:9f:
                 4c:59:55:bb:22:e4:6f:d0:76:0b:f8:9a:ad:e7:31:f5:05:b7:
                 8b:7a:93:49:ef:99:17:79:8d:8e:bb:d4:ab:94:ea:b6:0e:68:
                 62:2b:34:1f:5e:26:0e:97:64:5d:57:68:aa:95:b4:ef:57:ac:
                 03:fb:a2:56:43:50:76:8d:5e:21:9e:06:d7:4d:fb:88:a1:8e:
                 96:c6:44:f8:f4:92:43:4b:96:f4:fd:38:42:7e:02:6c:67:2a:
                 9c:15:28:1c:09:f5:a1:fa:f9:73:e8:5e:f6:b1:c4:c4:0c:bb:
                 70:7b:28:47:e0:bc:24:59:45:d2:9a:11:b9:4e:f0:49:81:83:
                 f1:5b:d0:13:d0:7a:06:e1:da:7c:dd:cb:7b:b3:8d:13:07:3f:
                 80:aa:b1:62:55:d8:2e:53:17:5d:40:21:9f:e6:1d:15:db:10:
                 42:99:61:89:90:3e:a0:b2:c1:a4:1d:ff:cd:53:af:37:24:8b:
                 53:64:32:bc:69:6c:ff:9b:8a:da:4a:ff:4a:be:82:66:d8:44:
                 64:a1:f9:48:a9:d8:53:64:36:27:25:1a:bb:f3:f6:c1:9f:e9:
                 17:48:28:76:2c:34:fb:fc:33:e4:59:08:1c:7f:33:3d:64:7f:
                 b3:a8:9a:d8:3b:a3:26:8c:5f:4b:2d:41:63:e4:83:c8:07:67:
                 40:14:a1:c7:4d:6c:dd:9e:34:2a:1c:fd:ba:8e:04:2b:4e:05:
                 dd:b3:a8:b1:d2:12:d5:47:20:6d:ee:3d:db:de:26:b3:e0:fd:
                 cf:4d:dc:ae:3e:12:72:92:3f:5a:f1:3f:11:fe:56:80:8a:2c:
                 76:9d:5e:fa:a8:05:00:1e:9f:11:c6:ca:ec:7a:86:16:6d:65:
                 18:a3:87:61:35:0b:a6:2d:87:f0:23:e2:75:b5:fe:21:7f:a8:
                 d5:db:91:4d:f8:cd:3c:4b:14:7a:59:63:a6:b2:45:3d:a8:19:
                 53:48:05:e2:9b:fb:a2:54:93:f2:52:4d:7d:0f:6c:af:22:c7:
                 7b:70:a3:c7:85:41:26:85:78:e5:77:64:90:fc:61:79:85:05:
                 c1:13:6a:17:6c:3b:b9:99:b1:47:38:5d:c0:72:48:d9:5b:91:
                 8e:31:f0:53:81:09:57:41:02:53:be:28:73:24:f1:72:5a:cf:
                 b2:56:2b:f3:ae:c4:93:04:f0:51:2b:d4:80:e9:51:07:89:58:
                 bb:d6:91:7d:78:23:a3:e9
        -----BEGIN CERTIFICATE-----
        MIIFFzCCAv+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADB3MQswCQYDVQQGEwJTRzES
        MBAGA1UECAwJU2luZ2Fwb3JlMRIwEAYDVQQHDAlTaW5nYXBvcmUxFDASBgNVBAoM
        C0FCQyBDb3JwIENBMRQwEgYDVQQLDAtIb21lIE9mZmljZTEUMBIGA1UEAwwLQUJD
        IENPUlAgQ0EwHhcNMjIwMTE2MDMwNzQ4WhcNNDIwMjEwMDMwNzQ4WjBWMQswCQYD
        VQQGEwJTRzEMMAoGA1UECAwDU1QxMQ4wDAYDVQQHDAVDSVRZMTENMAsGA1UECgwE
        T1JHMTEMMAoGA1UECwwDT1UxMQwwCgYDVQQDDANDTjEwggEiMA0GCSqGSIb3DQEB
        AQUAA4IBDwAwggEKAoIBAQDYYTndA3wKo4QX5fYlJASetp+2I+W9AeU7HEYm/b54
        R7cw73Jd+SjSETmEPLrQWv/pfxfJdySFP/kb4fyggbVyh/gfWuJgxsx4Scd867y8
        1fH3dW/h8yDw+do96y8d5pzKsIOi2+mHyrz8TdtzISibXxwuNyj/ZO7zmWmz/9Qj
        zvRsUADU+6F7v5xbRCmT+jy/0mDcb5/aADUArzfOFdiAgaYUrFpBgmXZ82PxpSkg
        sugYa+2WdtsOjD9+jqvD0vYynphA7UGgFv4MxQzF+9eimA2h1yq6AtgCtvmu79mI
        v+nK3sYRU7x9C+UCpy4b4Td8WgGB8RhYNG1FVULcc+URAgMBAAGjgc4wgcswHQYD
        VR0OBBYEFDFJelSa9VcCT5sAraEdfVBETZvrMB8GA1UdIwQYMBaAFHzImWTdvbuI
        bsK96+Cnd1BL5Q8pMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgXgMCcGA1UdJQQgMB4G
        CCsGAQUFBwMCBggrBgEFBQcDBAYIKwYBBQUHAwEwGgYDVR0RBBMwEYIDQ04xggRk
        bnMxhwTAqCwGMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0
        aWZpY2F0ZTANBgkqhkiG9w0BAQ0FAAOCAgEACacAcxbQrUsdTHW2cYI4a5+cdrgU
        rTuTj0Qw7VtCaHUJ9KK2YrsXJ99mAVV2eIMFbCdPh5KfTFlVuyLkb9B2C/iarecx
        9QW3i3qTSe+ZF3mNjrvUq5Tqtg5oYis0H14mDpdkXVdoqpW071esA/uiVkNQdo1e
        IZ4G1037iKGOlsZE+PSSQ0uW9P04Qn4CbGcqnBUoHAn1ofr5c+he9rHExAy7cHso
        R+C8JFlF0poRuU7wSYGD8VvQE9B6BuHafN3Le7ONEwc/gKqxYlXYLlMXXUAhn+Yd
        FdsQQplhiZA+oLLBpB3/zVOvNySLU2QyvGls/5uK2kr/Sr6CZthEZKH5SKnYU2Q2
        JyUau/P2wZ/pF0godiw0+/wz5FkIHH8zPWR/s6ia2DujJoxfSy1BY+SDyAdnQBSh
        x01s3Z40Khz9uo4EK04F3bOosdIS1Ucgbe49294ms+D9z03crj4ScpI/WvE/Ef5W
        gIosdp1e+qgFAB6fEcbK7HqGFm1lGKOHYTULpi2H8CPidbX+IX+o1duRTfjNPEsU
        elljprJFPagZU0gF4pv7olST8lJNfQ9sryLHe3Cjx4VBJoV45XdkkPxheYUFwRNq
        F2w7uZmxRzhdwHJI2VuRjjHwU4EJV0ECU74ocyTxclrPslYr867EkwTwUSvUgOlR
        B4lYu9aRfXgjo+k=
        -----END CERTIFICATE-----


    """.trimIndent())
    println(result)
}