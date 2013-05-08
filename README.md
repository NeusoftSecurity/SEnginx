SEnginx
=======

Security-Enhanced nginx by Neusoft corporation. 


Features
--------

* Session Persistence
* Fastest Load Balancing Algorithm
* Robot Mitigation
* if directive extension
* proxy cache types support
* ...


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
