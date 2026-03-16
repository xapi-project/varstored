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

```
$ make KEK.pem
$ echo KEK.pem > KEK.list
$ make db.pem
$ echo db.pem > db.list
```

Finally, build the auth files:

```
$ make auth
```

And place them where varstored can find them:

```
$ mkdir -p /usr/share/varstored
$ cp PK.auth KEK.auth db.auth dbx.auth /usr/share/varstored
```

Build the main daemon and tools and install them:

```
$ make varstored tools
$ mkdir -p /usr/sbin /usr/bin
$ cp varstored /usr/sbin
$ cp tools/varstore-{get,set,ls,rm,sb-state} /usr/bin
```

create-auth
-----------

The `create-auth` utility prepares authenticated variable update files ("auth"
files) used to populate PK, KEK, db, and dbx.

Options:

* `-k <key>` - Private key (PEM) used to sign the auth data
* `-c <cert>` - Certificate (PEM) corresponding to the signing key
* `-t <seconds>` - Timestamp as seconds since epoch (defaults to current time)
* `-s <signature>` - Pre-computed signature file (alternative to `-k`)
* `-o` - Output a file suitable for external signing instead of the signed auth
* `-g <guid>` - Vendor GUID in RFC-4122 format
  (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`). If not provided, defaults to the
  Citrix GUID for PK and the Microsoft GUID for KEK/db/dbx.

The GUID is stored using mixed-endian encoding per the EFI specification:

| Field | Size    | Endianness    |
|-------|---------|---------------|
| Data1 | 4 bytes | little-endian |
| Data2 | 2 bytes | little-endian |
| Data3 | 2 bytes | little-endian |
| Data4 | 8 bytes | big-endian    |

For example, the GUID `aabbccdd-eeff-gghh-iijj-kkllmmnnoopp` is stored as
`dd cc bb aa ff ee hh gg ii jj kk ll mm nn oo pp`.

### Inline signing

When both `-k` and `-c` are provided, `create-auth` signs the data directly:

```
./create-auth -k PK.key -c PK.pem PK PK.auth PK.pem
```

### External signing

The `-o`, `-s`, and `-t` options support a workflow where signing is performed
externally (e.g. by an HSM or a separate signing service). The same `-t`
timestamp value must be used for all three steps.

1. Generate a signable file:

```
./create-auth -o -t <timestamp> -c PK.pem PK PK.tosign PK.pem
```

2. Sign it externally, e.g. with OpenSSL:

```
openssl smime -sign -binary -in PK.tosign -out PK.sig \
    -signer PK.pem -inkey PK.key -outform DER -md sha256 -noattr
```

3. Import the detached signature to produce the `.auth` file:

```
./create-auth -s PK.sig -t <timestamp> -c PK.pem PK PK.auth PK.pem
```

Contributing
------------
Please send a pull request to https://github.com/xapi-project/varstored

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
