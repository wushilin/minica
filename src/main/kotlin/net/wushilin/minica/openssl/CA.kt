package net.wushilin.minica.openssl

import net.wushilin.minica.IO
import org.slf4j.LoggerFactory
import java.io.File
import java.util.*
import javax.print.attribute.IntegerSyntax
import kotlin.IllegalArgumentException

class CA(var base: File) {
    companion object {
        val log = LoggerFactory.getLogger(CA::class.java)
    }
    private var _key: String = ""
    val key: String
        get() = _key

    private var _cert: String = ""
    val cert: String
        get() = _cert

    private var _keyFile: File = File(base, "ca-key.pem")
    val keyFile: File
        get() = _keyFile

    private var _certFile: File = File(base, "ca-cert.pem")
    val certFile: File
        get() = _certFile

    private var _commonName: String = ""
    val commonName: String
        get() = _commonName

    private var _city: String = ""
    val city: String
        get() = _city

    private var _countryCode: String = ""
    val countryCode: String
        get() = _countryCode

    private var _state: String = ""
    val state: String
        get() = _state

    private var _organization: String = ""
    val organization: String
        get() = _organization

    private var _organizationUnit: String = ""
    val organizationUnit: String
        get() = _organizationUnit

    private var _issueTime: Long = 0L
    val issueTime: Long
        get() = _issueTime

    private var _validDays: Int = 0
    val validDays: Int
        get() = _validDays

    private var _subject: String = ""
    val subject: String
        get() = _subject

    val id:String
        get() = base.name

    private var _certCount: Long = 0
    val certCount:Long
        get() = _certCount

    private var _keyLength: Int = 0
    val keyLength:Int
        get() = _keyLength

    private var _digestAlgorithm: String = ""
    val digestAlgorithm:String
        get() = _digestAlgorithm

    init {
        // read meta data here
        _key = IO.readFileAsString(keyFile)
        _cert = IO.readFileAsString(certFile)

        val props = Properties()
        File(base, "meta.properties").inputStream().use {
            props.load(it)
        }
        _validDays = props.getProperty("validDays", "0").toInt()
        this._city = props.getProperty("city", "")
        this._commonName = props.getProperty("commonName", "")
        this._countryCode = props.getProperty("countryCode", "")
        this._organization = props.getProperty("organization", "")
        this._organizationUnit = props.getProperty("organizationUnit", "")
        this._issueTime = props.getProperty("issueTime", "0").toLong()
        this._state = props.getProperty("state", "")
        this._subject = props.getProperty("subject", "")
        this._certCount = this.listCert().size.toLong()
        this._digestAlgorithm = props.getProperty("digestAlgorithm", "")
        this._keyLength = props.getProperty("keyLength", "0").toInt()
        if(!File(base, "CA.complete").exists()) {
            throw IllegalArgumentException("possibly invalid ca")
        }
    }

    fun listCert():List<Cert> {
        val result = mutableListOf<Cert>()
        val childrenFiles = base.listFiles()
        childrenFiles.filter {
            it.isDirectory
        }.filter {
            !it.name.startsWith(".")
        }.filter {
            File(it, "CERT.complete").exists()
        }.forEach {
            result.add(Cert(it))
        }
        return result
    }
    override fun toString():String {
        return "CA:$_subject@${base.name}"
    }


    fun removeCertById(id:String):Cert {
        val result = getCertById(id)
        val deleteResult = result.base.deleteRecursively()
        if(!deleteResult) {
            throw IllegalArgumentException("Not possible.")
        }
        return result
    }
    fun getCertById(id:String):Cert {
        return Cert(File(base, id))
    }

    fun scan() {
        val childrenFiles = base.listFiles()
        childrenFiles?.filter {
            it.isDirectory
        }?.filter {
            !it.name.startsWith(".")
        }?.filter {
            !it.name.equals("certs")
        }?.forEach {
            if (!File(it, "CERT.complete").exists()) {
                val deleteResult = it.deleteRecursively()
                log.info("Found invalid cert $it, deleted => $deleteResult")
            }
        }
    }
}