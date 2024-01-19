# Transport Layer Security (TLS): Theory, Techniques, and Tools
An ongoing & curated collection of awesome software best practices and techniques, libraries and frameworks, E-books and videos, websites, blog posts, links to github Repositories, technical guidelines and important resources about TLS in Cybersecurity.
> Thanks to all contributors, you're awesome and wouldn't be possible without you! Our goal is to build a categorized community-driven collection of very well-known resources.


## What is TLS?
[TLS](https://www.internetsociety.org/deploy360/tls/basics/) encrypts communications between a client and server, primarily web browsers and web sites/applications. Specifically, TLS is a cryptographic protocol that provides end-to-end security of data sent between applications over the Internet.
> Transport Layer Security (TLS) encrypts data sent over the Internet to ensure that eavesdroppers and hackers are unable to see what you transmit which is particularly useful for private and sensitive information such as passwords, credit card numbers, and personal correspondence.
![tls](https://github.com/paulveillard/cybersecurity-tls-security/blob/main/img/tls.png)

SSL (Secure Sockets Layer) encryption, and its more modern and secure replacement, TLS (Transport Layer Security) encryption, protect data sent over the internet or a computer network.

![tls-history](https://github.com/paulveillard/cybersecurity-tls-security/blob/main/img/history.png)

- TLS evolved from Secure Socket Layers (SSL) which was originally developed by Netscape Communications Corporation in 1994 to secure web sessions. SSL 1.0 was never publicly released, whilst SSL 2.0 was quickly replaced by SSL 3.0 on which TLS is based.


## How Does SSL/TLS Encryption Work?
SSL/TLS uses both asymmetric and symmetric encryption to protect the confidentiality and integrity of data-in-transit. Asymmetric encryption is used to establish a secure session between a client and a server, and symmetric encryption is used to exchange data within the secured session. 

A website must have an SSL/TLS certificate for their web server/domain name to use SSL/TLS encryption. Once installed, the certificate enables the client and server to securely negotiate the level of encryption in the following steps:

![handshake](https://github.com/paulveillard/cybersecurity-tls-security/blob/main/img/ssl_handcheck2.png)

- 1) The client contacts the server using a secure URL (HTTPS…).
- 2) The server sends the client its certificate and public key.
- 3) The client verifies this with a Trusted Root Certification Authority to ensure the certificate is legitimate.
- 4) The client and server negotiate the strongest type of encryption that each can support.
- 5) The client encrypts a session (secret) key with the server’s public key, and sends it back to the server.
- 6) The server decrypts the client communication with its private key, and the session is established.
- 7) The session key (symmetric encryption) is now used to encrypt and decrypt data transmitted between the client and server.
Both the client and server are now using HTTPS (SSL/TLS + HTTP) for their communication. Web browsers validate this with a lock icon in the browser address bar. HTTPS functions over Port 443.

Once you leave the website, those keys are discarded. On your next visit, a new handshake is negotiated, and a new set of keys are generated.


## Table of Contents

  - [Introduction](#what-is-tls)
  - [SSL/TLS Protocol History](#ssltls-protocol-history)
  - [SSL/TLS Hacks](#ssltls-hacks)
    - [Cryptographic Issues](#cryptographic-issues)
      - [CBC Issues](#cbc-issues)
      - [RC4 Issues](#rc4-issues)
      - [Compression Issues](#compression-issues)
      - [RSA Issues](#rsa-issues)
    - [Implementation Issues](#implementation-issues)
  - [Some Open Source Implementations of SSL/TLS](#some-open-source-implementations-of-ssltls)
  - [OpenSSL Version History](#openssl-version-history)
  - [Vulnerabilities](#vulnerabilities)
    - [Fizz Vulnerabilities](#fizz-vulnerabilities)
    - [OpenSSL Vulnerabilities](#openssl-vulnerabilities)
  - [Tools](#tools)
    - [Fuzzing](#fuzzing)
    - [Programing](#programing)
    - [Scanning](#scanning)
    - [Others](#others)
  - [Glossary](#glossary)
 - [TLS General](#tls-general)
 - [TLS Attacks](#tls-attacks)
 - [PKIX](#pkix)
 - [SSL Interception](#ssl-interception)
 - [Protocols](#protocols)
 - [SSL Labs Research](https://github.com/ssllabs/research/wiki)
 - [License](#license)



## SSL/TLS Protocol History

| Protocol Name | Release Date | Author | RFC |
| --- | --- | --- | --- |
| SSL 1.0 | N/A | Netscape | N/A |
| SSL 2.0 | 1995 | Netscape | N/A |
| SSL 3.0 | 1996 | Netscape | N/A |
| TLS 1.0 | 1999-01 | IETF TLS Working Group | [RFC 2246](https://tools.ietf.org/html/rfc2246) |
| TLS 1.1 | 2006-04 | IETF TLS Working Group | [RFC 4346](https://tools.ietf.org/html/rfc4346) |
| TLS 1.2 | 2008-08 | IETF TLS Working Group | [RFC 5246](https://tools.ietf.org/html/rfc5246) |
| TLS 1.3 | 2018-08 | IETF TLS Working Group | [RFC 8446](https://tools.ietf.org/html/rfc8446) |

## SSL/TLS Hacks

### Cryptographic Issues

#### CBC Issues

| Attack Name | Published Date | Affected Version | Paper |
| --- | --- | --- | --- |
| Bleichenbacher | 2003-09 | SSL 3.0 | [Klima, Vlastimil, Ondrej Pokorný, and Tomáš Rosa. "Attacking RSA-based sessions in SSL/TLS." International Workshop on Cryptographic Hardware and Embedded Systems. Springer, Berlin, Heidelberg, 2003.](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.304.9703&rep=rep1&type=pdf) |
| BEAST | 2011-05 | SSL 3.0, TLS 1.0 | [Rizzo, Juliano, and Thai Duong. "Here come the xor ninjas." In Ekoparty Security Conference, 2011.](https://nerdoholic.org/uploads/dergln/beast_part2/ssl_jun21.pdf) |
| Lucky Thirteen | 2013-02 | SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2 | [Al Fardan, Nadhem J., and Kenneth G. Paterson. "Lucky thirteen: Breaking the TLS and DTLS record protocols." 2013 IEEE Symposium on Security and Privacy. IEEE, 2013.](http://isg.rhul.ac.uk/tls/TLStiming.pdf) |
| POODLE | 2014-10 | SSL 3.0 | [Möller, Bodo, Thai Duong, and Krzysztof Kotowicz. "This POODLE bites: exploiting the SSL 3.0 fallback." Security Advisory (2014).](https://computergeek.nl/wp-content/uploads/2014/10/ssl-poodle.pdf) |
| DROWN | 2016-08 | SSL 2.0 | [Aviram, Nimrod, et al. "DROWN: Breaking TLS Using SSLv2." 25th USENIX Security Symposium (USENIX Security 16). 2016.](https://drownattack.com/drown-attack-paper.pdf) |

#### RC4 Issues

| Attack Name | Published Date | Paper |
| --- | --- | --- |
| Single-byte Bias & Double-byte Bias | 2013-07 | [AlFardan, Nadhem, et al. "On the Security of RC4 in TLS." Presented as part of the 22nd USENIX Security Symposium (USENIX Security 13). 2013.](https://profs.info.uaic.ro/~fltiplea/CC/ABPPS2013.pdf) |
| N/A | 2015-03 | [Garman, Christina, Kenneth G. Paterson, and Thyla Van der Merwe. "Attacks Only Get Better: Password Recovery Attacks Against RC4 in TLS." 24th USENIX Security Symposium (USENIX Security 15). 2015.](https://pdfs.semanticscholar.org/698a/16014ca19866c247348e1f00af48d5b2acfe.pdf) |
| Bar-Mitzva | 2015-03 | [Mantin, Itsik. "Bar-Mitzva Attack: Breaking SSL with 13-Year Old RC4 Weakness." Black Hat Asia (2015).](https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf) |
| N/A | 2015-07 | [Vanhoef, Mathy, and Frank Piessens. "All your biases belong to us: Breaking RC4 in WPA-TKIP and TLS." 24th USENIX Security Symposium (USENIX Security 15). 2015.](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-vanhoef.pdf) |

#### Compression Issues

| Attack Name | Published Date | Paper |
| --- | --- | --- |
| CRIME | 2012-09 | [Rizzo, Juliano, and Thai Duong. "The CRIME attack." Ekoparty Security Conference. 2012.](http://netifera.com/research/crime/CRIME_ekoparty2012.pdf) |
| TIME | 2013-03 | [Be’ery, Tal, and Amichai Shulman. "A perfect CRIME? only TIME will tell." Black Hat Europe 2013 (2013).](https://media.blackhat.com/eu-13/briefings/Beery/bh-eu-13-a-perfect-crime-beery-wp.pdf) |
| BREACH | 2013-03 | [Prado, A., N. Harris, and Y. Gluck. "The BREACH Attack." (2013).](http://breachattack.com/)|

#### RSA Issues

| Attack Name | Published Date | Paper |
| --- | --- | --- |
| Adaptive chosen ciphertext attack | 1998-08 | [Bleichenbacher, Daniel. "Chosen ciphertext attacks against protocols based on the RSA encryption standard PKCS# 1." Annual International Cryptology Conference. Springer, Berlin, Heidelberg, 1998.](https://link.springer.com/content/pdf/10.1007/BFb0055716.pdf) |
| ROBOT | 2018-08 | [Böck, Hanno, Juraj Somorovsky, and Craig Young. "Return Of Bleichenbacher’s Oracle Threat (ROBOT)." 27th USENIX Security Symposium (USENIX Security 18). 2018.](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-bock.pdf) |

### Implementation Issues

| Attack Name | Published Date | Paper |
| --- | --- | --- |
| OpenSSL Heartbleed | 2014-04 | [Durumeric, Zakir, et al. "The matter of heartbleed." Proceedings of the 2014 conference on internet measurement conference. 2014.](http://conferences2.sigcomm.org/imc/2014/papers/p475.pdf) |
| Triple Handshake | 2014-05 | [Bhargavan, Karthikeyan, et al. "Triple handshakes and cookie cutters: Breaking and fixing authentication over TLS." 2014 IEEE Symposium on Security and Privacy. IEEE, 2014.](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.686.2786&rep=rep1&type=pdf) |
| FREAK | 2015-05 | [Beurdouche, Benjamin, et al. "A messy state of the union: Taming the composite state machines of TLS." 2015 IEEE Symposium on Security and Privacy. IEEE, 2015.](https://prosecco.gforge.inria.fr/personal/karthik/pubs/messy-state-of-the-union-oakland15.pdf) |
| Logjam | 2015-10| [Adrian, David, et al. "Imperfect forward secrecy: How Diffie-Hellman fails in practice." Proceedings of the 22nd ACM SIGSAC Conference on Computer and Communications Security. 2015.](https://weakdh.org/imperfect-forward-secrecy.pdf) |
| SLOTH | 2016-02 | [Bhargavan, Karthikeyan, and Gaëtan Leurent. "Transcript Collision Attacks: Breaking Authentication in TLS, IKE, and SSH." In Network and Distributed System Security Symposium (NDSS). 2016.](https://www.ndss-symposium.org/wp-content/uploads/2017/09/transcript-collision-attacks-breaking-authentication-tls-ike-ssh.pdf) |

## Some Open Source Implementations of SSL/TLS

| Implementation | Initial release | Developed by | Written in |
| --- | --- | --- | --- |
| [NSS](https://hg.mozilla.org/projects/nss) | 1998-03 | Mozilla, AOL, Red Hat, Sun, Oracle, Google and others | C, Assembly |
| [OpenSSL](https://github.com/openssl/openssl) | 1998-12 | OpenSSL Project | C, Assembly |
| [GnuTLS](https://gitlab.com/gnutls/gnutls) | 2000-03 | GnuTLS Project | C |
| [MatrixSSL](https://github.com/matrixssl/matrixssl) | 2004-01 | PeerSec Networks | C |
| [wolfSSL](https://github.com/wolfSSL/wolfssl) | 2006-02 | wolfSSL | C |
| [MbedTLS](https://github.com/ARMmbed/mbedtls) | 2009-01 | Arm | C |
| [BoringSSL](https://github.com/google/boringssl) | 2014-06 | Google | C, C++, Go, Assembly |
| [s2n](https://github.com/awslabs/s2n) | 2014-06 | Amazon | C |
| [LibreSSL](https://www.libressl.org/) | 2014-07 | OpenBSD Project | C, Assembly |
| [Rustls](https://github.com/ctz/rustls) | 2016-08 | Joseph Birr-Pixton etc. | Rust |
| [Fizz](https://github.com/facebookincubator/fizz) | 2018-06 | Facebook | C++ |

More information:  
<https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations>

## OpenSSL Version History

| Major version | Original release date | Last minor version | Last update date |
| --- | --- | --- | --- |
| 0.9.1 | 1998-12-23 | 0.9.1c | 1998-12-23 |
| 0.9.2 | 1999-03-22 | 0.9.2b | 1999-04-06 |
| 0.9.3 | 1999-05-25 | 0.9.3a | 1999-05-27 |
| 0.9.4 | 1999-08-09 | 0.9.4 | 1999-08-09 |
| 0.9.5 | 2000-02-28 | 0.9.5a | 2000-04-01 |
| 0.9.6 | 2000-09-24 | 0.9.6m | 2004-03-17 |
| 0.9.7 | 2002-12-31 | 0.9.7m | 2007-02-23 |
| 0.9.8 | 2005-07-05 | 0.9.8zh | 2015-12-03 |
| 1.0.0 | 2010-03-29 | 1.0.0t | 2015-12-03 |
| 1.0.1 | 2012-03-14 | 1.0.1u | 2016-09-22 |
| 1.0.2 | 2015-01-22 | 1.0.2u | 2019-12-20 |
| 1.1.0 | 2016-08-25 | 1.1.0l | 2019-09-10 |
| 1.1.1 | 2018-09-11 | 1.1.1l | 2021-08-24 |

## Vulnerabilities

### Fizz Vulnerabilities

| CVE-ID |  Disclosure date | Type | Analysis |
| --- | --- | --- | --- |
| CVE-2019-3560 | 2019-02-26 | Server Side DoS | [Facebook Fizz integer overflow vulnerability (CVE-2019-3560)](https://securitylab.github.com/research/facebook-fizz-CVE-2019-3560) |
| CVE-2019-11924 | 2019-08-09 | Server Side Memory Leak | [Facebook Fizz memory leak vulnerability (CVE-2019-11924) reproduce and analysis](https://lennysec.github.io/fizz-memory-leak-analysis/) |

### OpenSSL Vulnerabilities

## Tools

### Fuzzing

tlsfuzzer  
<https://github.com/tomato42/tlsfuzzer>

boofuzz  
<https://github.com/jtpereyda/boofuzz>

Fuzzowski  
<https://github.com/nccgroup/fuzzowski>

AFLNet  
<https://github.com/aflnet/aflnet>

### Programing

Python built-in TLS wrapper  
<https://docs.python.org/3.8/library/ssl.html>

Go Package tls  
<https://golang.org/pkg/crypto/tls/>

tlslite-ng: TLS implementation in pure python  
<https://github.com/tomato42/tlslite-ng>

Scapy: the Python-based interactive packet manipulation program & library  
<https://github.com/secdev/scapy/>

### Scanning

SSLyze: Fast and powerful SSL/TLS scanning library  
<https://github.com/nabla-c0d3/sslyze>

testSSL: Testing TLS/SSL encryption  
<https://github.com/drwetter/testssl.sh>

Qualys SSL Labs online tests  
<https://www.ssllabs.com/projects/index.html>

### Others

The New Illustrated TLS Connection  
<https://tls13.ulfheim.net/>

## Glossary

| Abbreviation | Explanation |
| --- | --- |
| SSL | Secure Sockets Layer |
| TLS | Transport Layer Security |
| IETF | Internet Engineering Task Force |
| POODLE | Padding Oracle On Downgrade Legacy Encryption |
| DROWN | Decrypting RSA using Obsolete and Weakened eNcryption |
| CRIME | Compression Ratio Info-leak Made Easy |
| TIME | Timing Info-leak Made Easy |
| BREACH | Browser Reconnaissance & Exfiltration via Adaptive Compression of Hypertext |
| FREAK | Factoring RSA Export Keys |


## TLS General

- [You should read this an skip the rest of the list](https://www.feistyduck.com/books/bulletproof-ssl-and-tls/reviewerKit.html)

### Trends

- [Looking Back, Moving Forward (2017)](https://casecurity.org/2017/01/13/2017-looking-back-moving-forward/)

### Pervasive Monitoring
- [Pervasive Monitoring is an Attack. RFC 7258](https://tools.ietf.org/html/rfc7258)

- [Confidentiality in the Face of Pervasive Surveillance: A Threat Model and Problem Statement. RFC 7624 (2015)](https://tools.ietf.org/html/rfc7624)


### Certificates / PKIX

[Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile. RFC 5280](https://doi.org/10.17487/rfc5280)

[Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS). RFC 6125](https://doi.org/10.17487/rfc6125)

[tls - How does OCSP stapling work? - Information Security Stack Exchange. (2013)](https://security.stackexchange.com/questions/29686/how-does-ocsp-stapling-work)

## TLS Attacks

### Overview

[SSL/TLS Vulnerabilities](https://www.gracefulsecurity.com/tls-ssl-vulnerabilities/)  

[ATTACKS ON SSL A COMPREHENSIVE STUDY OF BEAST, CRIME, TIME, BREACH, LUCK Y 13 & RC4 BIASES](https://www.nccgroup.trust/globalassets/our-research/us/whitepapers/ssl_attacks_survey.pdf)


### Recent Attacks

#### TLS/SSL

[On the Practical (In-)Security of 64-bit Block Ciphers: Collision Attacks on HTTP over TLS and OpenVPN (SWEET32, 2016)](https://sweet32.info/SWEET32_CCS16.pdf)

[Summarizing Known Attacks on Transport Layer Security (TLS) and Datagram TLS (DTLS). RFC 7457 (2015)](https://doi.org/10.17487/rfc7457 )

[DROWN: Breaking TLS Using SSLv2 (DROWN, 2016)](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/aviram)

[Out of Character: Use of Punycode and Homoglyph Attacks to Obfuscate URLs for Phishing (2015)](http://www.irongeek.com/i.php?page=security/out-of-character-use-of-punycode-and-homoglyph-attacks-to-obfuscate-urls-for-phishing)

[All Your Biases Belong to Us: Breaking RC4 in WPA-TKIP and TLS (RC4NOMORE, 2015)](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/vanhoef)

[Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice (LOGJAM, 2015)](https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf)

[A messy state of the union: Taming the composite state machines of TLS (2015)](http://www.ieee-security.org/TC/SP2015/papers-archived/6949a535.pdf)

[Bar Mitzvah Attack: Breaking SSL with a 13-year old RC4 Weakness (2015)](https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf)

[This POODLE bites: exploiting the SSL 3.0 fallback (POODLE, 2014)](https://www.openssl.org/~bodo/ssl-poodle.pdf)

[Lucky Thirteen: Breaking the TLS and DTLS Record Protocols (Lucky13, 2013](http://www.isg.rhul.ac.uk/tls/TLStiming.pdf) 

[SSL, gone in 30 seconds. Breach attack (BREACH,2013)](http://news.asis.io/sites/default/files/US-13-Prado-SSL-Gone-in-30-seconds-A-BREACH-beyond-CRIME-Slides_0.pdf)

[On the Security of RC4 in TLS (2013)](https://www.usenix.org/conference/usenixsecurity13/technical-sessions/paper/alFardan)

[The CRIME Attack (CRIME, 2012)](https://www.ekoparty.org/archive/2012/CRIME_ekoparty2012.pdf)

[Here come the ⊕ Ninjas (BEAST, 2011)](http://nerdoholic.org/uploads/dergln/beast_part2/ssl_jun21.pdf)

### Software Vulnerabilities


[Java’s SSLSocket: How Bad APIs compromise security (2015)](https://deepsec.net/docs/Slides/2014/Java's_SSLSocket_-_How_Bad_APIs_Compromise_Security_-_Georg_Lukas.pdf)

[A Survey on {HTTPS} Implementation by Android Apps: Issues and Countermeasures](https://www.researchgate.net/publication/309895574_A_Survey_on_HTTPS_Implementation_by_Android_Apps_Issues_and_Countermeasures) 


## PKIX

[Analysis of the HTTPS Certificate Ecosystem (2013)](http://conferences.sigcomm.org/imc/2013/papers/imc257-durumericAemb.pdf)

### Incidents

[Secure» in Chrome Browser Does Not Mean «Safe» (2017)](https://www.wordfence.com/blog/2017/03/chrome-secure/ )

[Overview of Symantec CA Issues (2014 (aprox) -2017)](https://wiki.mozilla.org/CA:Symantec_Issues)

[Intent to Deprecate and Remove: Trust in existing Symantec-issued Certificates (Symantec, 2017)](https://groups.google.com/a/chromium.org/forum/#!topic/blink-dev/eUAKwjihhBs)

[Incidents involving the CA WoSign (WoSign, 2016)](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/k9PBmyLCi8I%5B1-25%5D)

[Sustaining Digital Certificate Security (Symantec, 2015)](https://security.googleblog.com/2015/10/sustaining-digital-certificate-security.html)

[Improved Digital Certificate Security (Symantec, 2015)](https://security.googleblog.com/2015/09/improved-digital-certificate-security.html)

[TURKTRUST Unauthorized CA Certificates. (2013)](https://www.entrust.com/turktrust-unauthorized-ca-certificates/)

[Flame malware collision attack explained (FLAME, 2012)](https://blogs.technet.microsoft.com/srd/2012/06/06/flame-malware-collision-attack-explained/
)

[An update on attempted man-in-the-middle attacks (DIGINOTAR, 2011)](https://security.googleblog.com/2011/08/update-on-attempted-man-in-middle.html)

[Detecting Certificate Authority compromises and web browser collusion (COMODO, 2011)](https://blog.torproject.org/blog/detecting-certificate-authority-compromises-and-web-browser-collusion)

## SSL Interception

### Remarkable works

[Certified lies: Detecting and defeating government interception attacks against ssl (2011)](http://files.cloudprivacy.net/ssl-mitm.pdf)

[The Security Impact of HTTPS Interception (2017)](https://zakird.com/papers/https_interception.pdf)

[US-CERT TA17-075A Https interception weakens internet security (2017)](https://www.us-cert.gov/ncas/alerts/TA17-075A) 

[ Killed by Proxy: Analyzing Client-end TLS Interception Software (2016)](https://madiba.encs.concordia.ca/~x_decarn/papers/tls-proxy-ndss2016.pdf)

[TLS interception considered harmful How Man-in-the-Middle filtering solutions harm the security of HTTPS (2015)](https://events.ccc.de/camp/2015/Fahrplan/events/6833.html) 

[The Risks of SSL Inspection (2015)](https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html) 

[TLS in the wild—An Internet-wide analysis of TLS-based protocols for electronic communication (2015)]()

[The Matter of Heartbleed (2014)](https://jhalderm.com/pub/papers/heartbleed-imc14.pdf)

[How the NSA, and your boss, can intercept and break SSL (2013)](http://www.zdnet.com/article/how-the-nsa-and-your-boss-can-intercept-and-break-ssl/)

### SSL Interception-related Incidents

[Komodia superfish ssl validation is broken (2015)](https://blog.filippo.io/komodia-superfish-ssl-validation-is-broken/)

[More TLS Man-in-the-Middle failures - Adguard, Privdog again and ProtocolFilters.dll (2015)](https://blog.hboeck.de/archives/874-More-TLS-Man-in-the-Middle-failures-Adguard,-Privdog-again-and-ProtocolFilters.dll.html)

[Software Privdog worse than Superfish (2015)](https://blog.hboeck.de/archives/865-Software-Privdog-worse-than-Superfish.html)

[Superfish 2.0: Dangerous Certificate on Dell Laptops breaks encrypted HTTPS Connections (2015)](https://blog.hboeck.de/archives/876-Superfish-2.0-Dangerous-Certificate-on-Dell-Laptops-breaks-encrypted-HTTPS-Connections.html)

[How Kaspersky makes you vulnerable to the FREAK attack and other ways Antivirus software lowers your HTTPS security (2015)](https://blog.hboeck.de/archives/869-How-Kaspersky-makes-you-vulnerable-to-the-FREAK-attack-and-other-ways-Antivirus-software-lowers-your-HTTPS-security.htm)

## Tools
### TLS Audit

#### Online

[Qualys SSL Server Test](https://www.ssllabs.com/ssltest/)

[Qualys SSL Client Test](https://www.ssllabs.com/ssltest/viewMyClient.html)

#### Local

[sslyze](https://github.com/iSECPartners/sslyze)

[Qualys SSL Labs (local version)](https://github.com/ssllabs/ssllabs-scan)

[testssl.sh](https://testssl.sh/)

### Sysadmins

[Qualys SSL/TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)

[Mozilla's Recommendations for TLS Servers](https://wiki.mozilla.org/Security/Server_Side_TLS)

[IISCrypto: Tune up your Windows Server TLS configuration](https://www.nartac.com/Products/IISCrypto)

### MITM
[bettercap - A complete, modular, portable and easily extensible MITM framework’](https://www.bettercap.org/)

[dns2proxy](https://github.com/LeonardoNve/dns2proxy)

[MITMf](https://github.com/byt3bl33d3r/MITMf)


## Protocols

### UTA (Use TLS in Applications) IETF WG

- [Drafts and RFCs (HTTP and SMTP)](https://datatracker.ietf.org/wg/uta/documents/)

### Strict Transport Security (STS)

- [HTTP Strict Transport Security (HSTS). RFC 6797 (2012)](https://doi.org/10.17487/rfc6797)

- [STS Preload List - Google Chrome](https://cs.chromium.org/chromium/src/net/http/transport_security_state_static.json)

- [HSTS Preload List Submission.](https://hstspreload.org/)

- [HTTP Strict Transport Security for Apache, NGINX and Lighttpd](https://raymii.org/s/tutorials/HTTP_Strict_Transport_Security_for_Apache_NGINX_and_Lighttpd.html) 



### HPKP

- [Public Key Pinning Extension for HTTP. RFC 7469 (2015)](https://doi.org/10.17487/rfc7469)

- [Is HTTP Public Key Pinning Dead? (2016)](https://blog.qualys.com/ssllabs/2016/09/06/is-http-public-key-pinning-dead)

### Certificate Transparency

- [Certificate Transparency](https://www.certificate-transparency.org/) 

- [How Certificate Transparency Works - Certificate Transparency](https://www.certificate-transparency.org/how-ct-works)

- [Google Certificate Transparency (CT) to Expand to All Certificates Types (2016)](https://casecurity.org/2016/11/08/google-certificate-transparency-ct-to-expand-to-all-certificates-types/)

### CAA

- [DNS Certification Authority Authorization (CAA) Resource Record. RFC 6844](https://doi.org/10.17487/rfc6844)

- [CAA Record Generator](https://sslmate.com/labs/caa/)

### DANE and DNSSEC

- [DANE Resources](https://www.huque.com/dane/)

- [The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA. RFC 6698](https://doi.org/10.17487/rfc6698)

- [DANE: Taking TLS Authentication to the Next Level Using DNSSEC (2011)](https://www.internetsociety.org/articles/dane-taking-tls-authentication-next-level-using-dnssec)

- [Generate TLSA Record](https://www.huque.com/bin/gen_tlsa)

- [DNS security introduction and requirements. RFC 4033](https://tools.ietf.org/html/rfc4033)

### SSL / TLS Best Practices
 - [TLS 2021](https://www.ssl.com/guide/ssl-best-practices/#ftoc-heading-4)
 - [SSL and TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)




**[`^        back to top        ^`](#)**

## License
MIT License & [cc](https://creativecommons.org/licenses/by/4.0/) license

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.

To the extent possible under law, [Paul Veillard](https://github.com/paulveillard/) has waived all copyright and related or neighboring rights to this work.

