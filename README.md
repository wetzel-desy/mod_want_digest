Description
=================

This module is an **alpha** version of an Apache2 httpd module that implements a data integrity check in accordance with RFC 3230 (https://tools.ietf.org/html/rfc3230).
It has been tested with various HTTP header combinations and returns the correct digests according to specifications in RFC 3230.
Currently, ADLER32, MD5 and SHA-1 checksums are supported.

The module is compiled, installed and activated (-cia) via
```
sudo apxs -cia mod_want_digest.c
```
on the target machine.
Currently, there is one config option for the module that sets the digest caching location on a per-directory basis (the directive to use in a <Directory>-directive is `DigestRootDir`). The digests will be cached in the `DigestRootDir` from the directory in which the directive is placed.
Example configuration:
```
<Directory "/mnt/data">
    # other configuration options
    DigestRootDir /var/run/apache2/digests
    # other configuration options
</Directory>
```

Example HTTP request via cURL:
``` 
curl --head https://foo.bar.com/foobar.txt -H "Want-Digest: MD5"

HTTP/1.1 200 OK
Date: Mon, 12 Oct 2020 12:49:41 GMT
Server: Apache/2.4.41 (Ubuntu)
Digest: MD5=TZYmtg997D5xY2K5m/CKXg==
Last-Modified: Thu, 08 Oct 2020 11:59:29 GMT
Accept-Ranges: bytes
Content-Length: 3000678009
Vary: Accept-Encoding
Content-Type: text/plain
```

Version 0.1 was shipped without caching and can be found under the tag `v0.1`. The main branch is always hosting the newest version and is hopefully stable.

Nota bene:
The module does not calculate or cache digests for files that are copied directly into the directory configured to be served via webDAV. There is, however, the option to use a combination of `inotifywait` and a fitting script on system level to achieve that. If you are interested in such an implementation, please let us know.

Contributors
================
The module has been developed by T. Wetzel and P. Millar at Deutsches Elektronen-Synchrotron DESY.

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


