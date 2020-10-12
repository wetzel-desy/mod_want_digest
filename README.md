Description
=================

This module is an alpha version of an Apache2 httpd module that implements data integrity check in accordance with RFC 3230 (https://tools.ietf.org/html/rfc3230).
It has been tested with instances of CERN's FTS3 and WebFTS, which do not return an error on the integrity checks.

The module is compiled with 
```
sudo apxs -i -a -c mod_want_digest.c
```
on the target machine. Currently, there is no config for the module, it just works on the HTTP GET and HEAD requests.
FTS first transfers a file to the destination and at the end of the transfer sends a HEAD request with the additional "Want-Digest: ADLER32" header token.
Currently, ADLER32, MD5 and SHA-1 checksums are supported.

TODO:
- implement a caching mechanism that calculates the checksum of a file on the fly for a PUT request (although it would be more correct to calculate the checksum from the file on disk)
- implement a precalculation for all files on disk that are exposed to the internet(TM) in order to save time for large files. the checksums could be placed in a hidden directory .checksums in files like filename.md5, filename.sha and filename.adler32.

Contributors
================
The module has been developed by Tim Wetzel and Paul Millar at Deutsches Elektronen-Synchrotron DESY.

License
=================
The project is licensed under the Apache 2.0 license.

How to contribute
=================

**mod\_want\_digest** uses the linux kernel model where git is not only source repository,
but also the way to track contributions and copyrights.

Each submitted patch must have a "Signed-off-by" line.  Patches without
this line will not be accepted.

The sign-off is a simple line at the end of the explanation for the
patch, which certifies that you wrote it or otherwise have the right to
pass it on as an open-source patch.  The rules are pretty simple: if you
can certify the below:
```

    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
         have the right to submit it under the open source license
         indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.

```
then you just add a line saying ( git commit -s )

    Signed-off-by: Random J Developer <random@developer.example.org>

using your real name (sorry, no pseudonyms or anonymous contributions.)


