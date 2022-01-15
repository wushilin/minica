package net.wushilin.minica.openssl

import net.wushilin.minica.IO
import java.io.File
import java.lang.IllegalArgumentException
import java.util.*

class Cert(var base: File){
    private var _key: String = ""
    val key: String
        get() = _key

    private var _cert: String = ""
    val cert: String
        get() = _cert

    private var _keyFile: File = File(base, "cert.key")
    val keyFile: File
        get() = _keyFile

    private var _certFile: File = File(base, "cert.pem")
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

    private var _dnsList:List<String> = listOf()
    val dnsList:List<String>
        get() = _dnsList

    private var _ipList:List<String> = listOf()
    val ipList:List<String>
        get() = _ipList

    private var _keyLength:Int = 0
    val keyLength:Int
        get() = _keyLength

    val id:String
        get() = base.name

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
        this._keyLength = props.getProperty("keyLength", "0").toInt()
        this._state = props.getProperty("state", "")
        this._subject = props.getProperty("subject", "")
        this._dnsList = props.getProperty("dnsList", "").split(";").toList().map{ it.trim() }.filter { it.isNotEmpty() }
        this._ipList = props.getProperty("ipList", "").split(";").toList().map{it.trim()}.filter{it.isNotEmpty()}
        this._digestAlgorithm = props.getProperty("digestAlgorithm", "")

        if(!File(base, "CERT.complete").exists()) {
            throw IllegalArgumentException("possibly invalid CERT")
        }
    }

    override fun toString():String {
        return "CERT:$_subject@${base.name}"
    }

}