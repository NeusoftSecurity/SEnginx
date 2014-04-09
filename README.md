SEnginx
=======
Security-Enhanced nginx by Neusoft corporation. 

Features
--------
* All features of original nginx, you can find more at: http://nginx.org/en/docs/
* Application Delivery
    * TCP Proxy and Load Balancing
    * Enhanced "if" Direcitve in Rewrite Module
    * Dynamic DNS Resolve in Upstream
    * Proxy HTTPS Client Certificate
    * Load Balancing Algorithm
        * Fastest Load Balancing Algorithm
        * Fair Load Balancing Alogorithm
    * Session Persistence
    * Caching Based on MIME Type
    * Server Health Monitor
* Web Security
    * IP Access Behavior Module
    * Conditional limit_req module
    * HTTP Robot Mitigation:
        * HTTP DDoS Mitigation (Low Orbit Ion Cannon ...)
        * Vulnerability Scanning (AppScan, Acunetix Web Vulnerability Scanner, Metasploit Pro, Nessus ...)
        * Spiders, Crawlers and other robotic evil
    * Dynamic IP Blacklist
    * User-Agent Whitelist with DNS Reverse Resolve
    * Cookie Poisoning
    * Web Defacement
    * Protection of Web Vulnerabilities (Integrated Naxsi and ModSecurity):
        * SQL Injection
        * Cross Site Scripting
        * Directory Traversal
        * Remote File Inclusion
        * Evading Tricks
        * ...
    * Secure Session Mechanism
    * NetEye Security Layer
* Managment
    * Syslog Support

Installation
------------
Almost the same as original nginx installation, but use se-configure.sh to generate Makefile instead.

The se-configure.sh script can also accept original configure.sh's parameters.

Example:

    ./se-configure.sh --prefix=/path/to/some/where
    make
    make install


Auto Test
---------
We have prepared a set of test cases in the test directory, use the auto-test.sh script to run all the test cases.

Example:

    cd test/
    ./auto-test.sh -s ./ -n /path/to/senginx/binary/file


Other
-----
More information, check our website: http://www.senginx.org
