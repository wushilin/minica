# minica
A Certificate Authority with RESTful interface and WEB UI

# Home page
![home](https://github.com/wushilin/minica/blob/main/resources/home.png?raw=true)

# View CA detail
![CA View](https://github.com/wushilin/minica/blob/main/resources/cadetail.png?raw=true)

# View Cert Detail
![Cert View](https://github.com/wushilin/minica/blob/main/resources/certdetail.png?raw=true)


With RESTful interface, you can manage certificate authority, request certs, get truststore, pkcs12, jks keystores in realtime, in a automated way.

You don't ever need to remember openssl command again, just run this service.

The project is written in Kotlin (supports Java 11 or newer), and Angular JS.

It is my first attempt with Front End Project.

This software is suitable for development & testing only, where you don't want to manage a microsoft Active Directory server for certificates.

It is purely built using openssl and java keytool (shipped with JDK).
You need to have both installed in your system.

# Change log

## 1.0.3
Since 1.0.3, additional support for external trusted http header authentication is added.

Now it should be easy to put this service behind IAM services where user can enjoy SSO to this application.
The trusted user can be passed in by any header name, and trusted group can be passed in by any header name too in CSV format.
e.g. 
```
x-user: steve
x-groups: iam_group3, iam_group4
```

See configuration example below for details. It is easy!

This feature may not be very useful for individual developers that has no IAM services.

# Requirements
Requirement:
```
openssl 1.0+
jdk 17+ (springboot requirement)
```
# Building the MiniCA RESTful service
```sh
$ git clone https://github.com/wushilin/minica.git
$ cd minica
$ ./gradlew clean bootJar
```
The executable jar is located at build/libs/minica-1.0.3-SNAPSHOT.jar

To run it, 

Create a file named: application.properties like this:
```
openssl.path=/usr/bin/openssl <=points to your openssl
minica.root=/opt/minica <= point to a directory for all your CA certificates and issued certificates
keytool.path=/usr/local/bin/keytool <= point to your jdk keytool command
users.config=admin@adminpass:admin;user@password:viewer;invalid@invalid:invalid <= config the user access in username@password:role;username2@password2:role2 format. You can specify many users. The users will be using Basic authentication when talking to the RESTful service. The admin role users will be able to make changes (e.g. create/delete CA, request/delete certificates). The viewer will not able to do so, but viewer can download and view the certs without problem.
server.port=9988 <= default port is 8080, you may change it here


# If you want to support trusted header (where idm/iam is protecting this service, you may use external header authentication)
# Uncomment to use:
# authentication.mode=request-header|default <= default: use users.config and basic, request-header: use trusted header for username
# request-header.name.username=x-user <= the http request header name to retrieve curently loggedin user
# request-header.name.group=x-group <= the http request header name to retrieve current user's group. 
# # Groups is in csv format. it can be aaa,bbb,ccc, or "aaa","bbb","ccc". Any CSV format is good!
# request-header.group.admin.name=admin <= the group name for admin user rights
# request-header.group.viewer.name=viewer <= the group name for viewer user rights

# Every user, on top of the groups retrieved from group name header(if set), will be given additional role '$any'.
# you can choose not to set `request-header.name.group` and use '$any' for group names.


# Do not use this if your end user can directly access the minica. as they can always pass user header and group header
# directly
```

Start the service:
```sh
$ java -jar build/libs/minica-1.0.3-SNAPSHOT.jar --spring.config.location=./application.properties
```

Access the UI:
Open your browser and access via http://host:9988

Login with your configure password.


Test the service:

# IMPORTANT 

Cross Site Request Forgery notes

MiniCA added XSRF protection now. The angular / UI automatically handles that for you.

For RESTful API, you will have to add additional two headers.
```
-H "X-XSRF-TOKEN: 123" -H "Cookie: XSRF-TOKEN=123;"
```

The cookie value XSRF-TOKEN must equal to request header X-XSRF-TOKEN value.
Otherwise, the request will be denied because of CSRF check failed.

```sh
$ curl -H "X-XSRF-TOKEN: 123" -H "Cookie: XSRF-TOKEN=123;" -u "admin:adminpass" -vvvv -H "Content-Type: application/json"  -X PUT --data '{"commonName": "ABC CORP CA", "validDays": 7300, "countryCode":"SG", "organization":"ABC Corp CA", "state":"Singapore", "city":"Singapore", "organizationUnit":"Home Office", "digestAlgorithm":"SHA512", "keyLength": 4096, "password":"changeit" }' http://localhost:9988/ca/new
```

If you see something like this, that means your RESTful service is up.
```json
{
	"base":"/opt/minica/CAs/d60f9bed-05e2-4fe3-b326-7ba6db0c94e0",
	"key":"-----BEGIN RSA PRIVATE KEY-----\n....\n-----END RSA PRIVATE KEY-----\n",
	"id":"d60f9bed-05e2-4fe3-b326-7ba6db0c94e0",
	"state":"Singapore",
	"cert":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
	"city":"Singapore",
	"keyFile":"/opt/minica/CAs/d60f9bed-05e2-4fe3-b326-7ba6db0c94e0/ca-key.pem",
	"subject":"/C=SG/ST=Singapore/L=Singapore/O=ABC Corp CA/OU=Home Office/CN=ABC CORP CA",
	"certFile":"/opt/minica/CAs/d60f9bed-05e2-4fe3-b326-7ba6db0c94e0/ca-cert.pem",
	"commonName":"ABC CORP CA",
	"countryCode":"SG",
	"organization":"ABC Corp CA",
	"validDays":7300,
	"organizationUnit":"Home Office",
	"digestAlgorithm":"SHA512",
	"keyLength":4096,
	"issueTime":1642263016206,
	"certCount":0
}
```

You may refer to the following URLs for interacting with the RESTfulservices endpoints. 

```
admin = view/download + modify
viewer = view/download
```
All endpoints requires basic authentication with at least viewer.
Modifications requires at least admin.
1. Register new CA: 
```
PUT /ca/new
Authorization: xxx

{
  "commonName": "ABC CORP CA",
  "validDays": 7300,
  "countryCode":"SG",
  "organization":"ABC Corp CA",
  "state":"Singapore",
  "city":"Singapore",
  "organizationUnit":"Home Office",
  "digestAlgorithm":"SHA512",
  "keyLength": 4096,
  "password": "changeit"
}

---
Requires admin role
```

2. Listing all CAs:
```
GET /ca
Authorization: xxx

---
Requires viewer role
Note that each CA has an ID in json response, the ID is the unique identifier
```
3. Get a single CA detail:
```
GET /ca/<ca-id>
Authorization: xxx

---
Requires viewer role
```

4. Delete a CA
```
DELETE /ca/<ca-id>
Authorization: xxxxx

Note that delete CA will also delete all certs in that CA. The issued certs can still be used. 

---
Requires admin role
```

5. List certs under CA
```
GET /ca/<ca-id>/cert
Authorization: xxx

---
Requires viwer role
Note certs have unique identifier. A cert is uniquely identifiable via a pair of ca-id, which identifies which ca, and cert-id, which identifies the cert.
```

6. Request new cert under CA
```
PUT /ca/<ca-id>/new
Authorization: xxx

{
  "commonName": "acme.abc.com",
  "validDays": 7300,
  "email":"wushilin@live.com",
  "countryCode":"SG",
  "organization":"Home",
  "state":"Singapore",
  "city":"Singapore",
  "organizationUnit":"home team",
  "digestAlgorithm":"SHA512",
  "keyLength": 4096,
  "dnsList": ["jumper.abc.com", "*.abc.com"],
  "ipList": ["192.168.44.1", "192.168.44.2"]
}

---
Requires admin role

```

7. Get a cert detail 
```
GET /ca/<ca-id>/cert/<cert-id>
Authorization: xxx

---
Requires viewer role
```
8. Delete a cert from CA
```
DELETE /ca/<ca-id>/cert/<cert-id>
Authorization: xxx

---
Requires admin role
```

9. Exporting
All following requests required Authorization, and at least viewer permission.

Download CA Cert in PEM format
```
GET /ca/download/<ca-id>/cert
Authorization: xxx

---
Requires viewer role
```

Download CA Key in PEM format, unencrypted
```
GET /ca/download/<ca-id>/key
Authorization: xxx

---
Requires viewer role
```

Download CA Cert & Key pair in PKCS12, encrypted with the `password` below.
```
GET /ca/download/<ca-id>/pkcs12
Authorization: xxx

---
Requires viewer role
```

Download the truststore in JKS format, encrypted with the `password` below.
```
GET /ca/download/<ca-id>/truststore
Authorization: xxx

---
Requires viewer role
```

Download the keystore for pkcs12, keystore password, in text format
```
GET /ca/download/<ca-id>/password
Authorization: xxx

---
Requires viewer role
```

Renew certificate by X days
```
POST /ca/<ca-id>/cert/<cert-id>/<days>
Authorization: xxx

---
Requires admin role
```

Download everything about the cert in a zip file, include cert, csr, 
private key in PEM format, jks and pkcs12 keystore, jks truststore, 
ca cert in PEM, and all keystore passwords
```
GET /ca/download/<ca-id>/cert/<cert-id>/bundle
Authorization: xxx

---
Requires viewer role
```

Download the cert which is signed by the CA
```
GET /ca/download/<ca-id>/cert/<cert-id>/cert
Authorization: xxx

---
Requires viewer role
```

Download the CSR
```
GET /ca/download/<ca-id>/cert/<cert-id>/csr
Authorization: xxx

---
Requires viewer role
```

Download the key
```
GET /ca/download/<ca-id>/cert/<cert-id>/key
Authorization: xxx

---
Requires viewer role
```

Download the keystore in JKS, encrypted with the `password` below
```
GET /ca/download/<ca-id>/cert/<cert-id>/jks
Authorization: xxx

---
Requires viewer role
```

Download the keystore in PKCS12, encrypted with the `password` below
```
GET /ca/download/<ca-id>/cert/<cert-id>/pkcs12
Authorization: xxx

---
Requires viewer role
```

Download the keystore password
```
GET /ca/download/<ca-id>/cert/<cert-id>/password
Authorization: xxx

---
Requires viewer role
```

Download the truststore in jks. The truststore is from the CA
```
GET /ca/download/<ca-id>/cert/<cert-id>/truststore
Authorization: xxx

---
Requires viewer role
```

Download the trust store password. Trust store is from the CA, thus using a different password
```
GET /ca/download/<ca-id>/cert/<cert-id>/truststorePassword
Authorization: xxx

---
Requires viewer role
```


# Building the UI service
NOTE: The UI is built and bundled in automatically. Use this only if you are keen to make the UI better.


1. Install node and npm - steps skipped, node 16.10+

2. Install angular js cli
```
$ npm install -g @angular/cli
$ npm install

```

3. Edit the proxy configuration `vim proxy.conf.js`
This proxies /ca to the endpoint of your RESTful service. If you changed your port above in RESTful service, please change accordingly here.
If you run the RESTful service in another host, please remember to change the target host as well.
```
const PROXY_CONFIG = [
  {
    context: [
                 "/ca/"
    ],
    target: "http://localhost:9988/",
    changeOrigin: true,
    secure: false
  }
];

module.exports = PROXY_CONFIG;

```

4. Starting the UI
```sh
$ ng serve --proxy-config proxy.conf.js --host 0.0.0.0 --configuration production
```

5. Test
Open your browser and access http://<host>:4200. You will be prompted to login, enter the RESTful userid and password.

For the admin users, you can do everything. For viewer users, the modifications are prohibited.


# Live demo
You can see a live demo at http://ca.wushilin.net:40000/

The login user (in username///password format):
* Admin: admin///admin
* Viewer: user///user

Note that Certificated Created in this Live Demo will be deleted after 30 days automatically

