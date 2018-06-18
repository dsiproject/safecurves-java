/* Copyright (c) 2018, Eric McCorkle.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package net.metricspace.crypto.math.ec.group;

import net.metricspace.crypto.math.ec.curve.Curve25519Curve;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.ModE255M19;

/**
 * The Curve25519 elliptic curve.  This curve was introduced by
 * Bernstein in his paper <a
 * href="https://cr.yp.to/ecdh/curve25519-20060209.pdf">"Curve25519:
 * New Diffie-Hellman Speed Records"</a>.  It is defined
 * by the Montgomery-form equation {@code y^2 = x^3 + 486662 * x^2 *
 * x} over the prime field {@code mod 2^255 - 19}, and the
 * corresponding group provides roughly {@code 125.8} bits of security
 * against the Pollard-Rho attack.
 * <p>
 * This curve is also birationally equivalent to the twisted Edwards
 * curve {@code 486664 * x^2 + y^2 = 1 + 486660 * x^2 * y^2}.
 *
 * @see ModE255M19
 * @see net.metricspace.crypto.math.ec.curve.Curve25519Curve
 */
public abstract class Curve25519<P extends ECPoint<ModE255M19, P>>
    extends MontgomeryCurveGroup<ModE255M19, P>
    implements Curve25519Curve {
    /**
     * Prime order for the group.  The value is {@code
     * 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed}
     */
    public static final ModE255M19 PRIME_ORDER =
        new ModE255M19(new byte[] {
                (byte)0xed, (byte)0xd3, (byte)0xf5, (byte)0x5c,
                (byte)0x1a, (byte)0x63, (byte)0x12, (byte)0x58,
                (byte)0xd6, (byte)0x9c, (byte)0xf7, (byte)0xa2,
                (byte)0xde, (byte)0xf9, (byte)0xde, (byte)0x14,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x10
            });

    /**
     * Base point x-coordinate in the base Montgomery curve
     * representation.  The value is {@code 0x9}.
     */
    public static final ModE255M19 BASE_X = new ModE255M19(0x9);

    /**
     * Base point y-coordinate in the base Montgomery curve
     * representation.  The value is {@code
     * 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9}.
     */
    public static final ModE255M19 BASE_Y =
        new ModE255M19(new byte[] {
                (byte)0xd9, (byte)0xd3, (byte)0xce, (byte)0x7e,
                (byte)0xa2, (byte)0xc5, (byte)0xe9, (byte)0x29,
                (byte)0xb2, (byte)0x61, (byte)0x7c, (byte)0x6d,
                (byte)0x7e, (byte)0x4d, (byte)0x3d, (byte)0x92,
                (byte)0x4c, (byte)0xd1, (byte)0x48, (byte)0x77,
                (byte)0x2c, (byte)0xdd, (byte)0x1e, (byte)0xe0,
                (byte)0xb4, (byte)0x86, (byte)0xa0, (byte)0xb8,
                (byte)0xa1, (byte)0x19, (byte)0xae, (byte)0x20
            });

    /**
     * Base point x-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code 0x9}.
     */
    public static ModE255M19 baseX() {
        return BASE_X.clone();
    }

    /**
     * Base point y-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code
     * 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9}.
     */
    public static ModE255M19 baseY() {
        return BASE_Y.clone();
    }

    /**
     * The prime order of Curve25519 is {@code
     * 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed}
     *
     * @return The value {@code
     * 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed}
     */
    @Override
    public ModE255M19 primeOrder() {
        return PRIME_ORDER.clone();
    }
}
