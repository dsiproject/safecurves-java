# SafeCurves-Java- Low-level elliptic curve primitives for safe elliptic curves

SafeCurves-Java aims to provide the low-level primitives for implementing
elliptic-curve cryptographic functionality.  SafeCurves-Java does *not* aim to
implement the JCA interfaces.  The underlying goal of SafeCurves-Java is to
help provide a greater diversity of reliable ciphers for common use.

The supported curves are taken from the
[SafeCurves Project](https://safecurves.cr.yp.to/).

## Supported Curves

SafeCurves-Java aims to support the following curves:

* M-221
* E-222
* Curve1174
* Curve25519
* E-382
* M-383
* Curve383187
* Curve41417
* M-512
* E-521

## Prime Field Support

In order to support the list of curves, SafeCurves-Java must provide prime-field
arithmetic for the following prime-order fields:

* `2^221 - 3`
* `2^222 - 117`
* `2^251 - 9`
* `2^255 - 19`
* `2^382 - 105`
* `2^383 - 187`
* `2^414 - 17`
* `2^511 - 187`
* `2^521 - 1`

### Prime Field Operations

SafeCurves-Java aims to support the following prime-field operations for all
fields:

* Basic field operations (add, subtract, multiply, divide)
* Add, subtract, multiply by "small" numbers
* Additive and multiplicative inverse
* Square root
* Inverse square root
* Legendre symbol

## Additional Operations

SafeCurves-Java aims to support the following additional functionality for all
curves:

* Elligator hash algorithm
* Decaf point compression
