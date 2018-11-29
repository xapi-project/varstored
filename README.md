varstored
=========

varstored is a helper for implementing variable services for a UEFI guest.
It runs outside of the guest context to ensure that updates to secure variables
are verified correctly.

varstored has a corresponding frontend which is part of OVMF. The code for this
is available at:
- https://github.com/rosslagerwall/edk2
- https://github.com/rosslagerwall/edk2.pg

varstored is designed to allow using multiple different backends for storage of
NVRAM. Currently the primary storage backend stores and retrieves the data from
the XAPI database.

Building
--------

For Secure Boot to work in user mode (enforcing) rather than setup mode, some
keys are needed during the build. The build generates "auth" files which are
used to populate PK, KEK, db, and dbx in a VM's NVRAM when it is booted for the
first time.

The platform owner key (PK) is generated during the build and used to sign
updates to PK, KEK, db. The private key is not used after the build.

At least one KEK certificate and at least one db certificate should be
available during the build. These are used for authenticated variable support
and Secure Boot verification. If these certificates are not acquired from
elsewhere, they can be generated as follows:

$ make KEK.pem
$ echo KEK.pem > KEK.list
$ make db.pem
$ echo db.pem > db.list

Finally, build the auth files:

$ make auth

And place them where varstored can find them:

$ mkdir -p /usr/share/varstored
$ cp PK.auth KEK.auth db.auth dbx.auth /usr/share/varstored

Build the main daemon and tools and install them:

$ make varstored tools
$ mkdir -p /usr/sbin /usr/bin
$ cp varstored /usr/sbin
$ cp tools/varstore-{get,set,ls,rm,sb-state} /usr/bin

Contributing
------------
Please send a pull request to https://github.com/rosslagerwall/varstored

Maintainers
-----------
* Ross Lagerwall <ross.lagerwall@citrix.com>

License
-------
See the LICENSE file for details.

Credits
-------
Some of the code for implementing variable services is derived from edk2
(https://github.com/tianocore/edk2).
