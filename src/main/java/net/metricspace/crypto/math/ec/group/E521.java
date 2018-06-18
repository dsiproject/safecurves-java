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

import net.metricspace.crypto.math.ec.curve.E521Curve;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.ModE521M1;

/**
 * The E-521 elliptic curve.  This curve was introduced independently
 * by three parties: Bernstein and Lange, Hamburg, and Aranha,
 * Barreto, Periera, and Ricardini in their paper <a
 * href="https://eprint.iacr.org/2013/647.pdf">"A Note on
 * High-Security General-Purpose Elliptic Curves"</a>.  It is defined
 * by the equation {@code x^2 + y^2 = 1 - 376014 * x^2 * y^2} over the
 * prime field {@code mod 2^521 - 1}, and the corresponding group
 * provides roughly {@code 259.3} bits of security against the
 * Pollard-Rho attack.
 *
 * @param <P> The concrete point type.
 * @see ModE521M1
 * @see net.metricspace.crypto.math.ec.curve.E521Curve
 */
public abstract class E521<P extends ECPoint<ModE521M1, P>>
    extends EdwardsCurveGroup<ModE521M1, P>
    implements E521Curve {
    /**
     * Prime order for the base Edwards curve representation.  The
     * value is {@code
     * 0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd15b6c64746fc85f736b8af5e7ec53f04fbd8c4569a8f1f4540ea2435f5180d6b}.
     */
    private static final ModE521M1 PRIME_ORDER =
        new ModE521M1(new byte[] {
                (byte)0x6b, (byte)0x0d, (byte)0x18, (byte)0xf5,
                (byte)0x35, (byte)0x24, (byte)0xea, (byte)0x40,
                (byte)0x45, (byte)0x1f, (byte)0x8f, (byte)0x9a,
                (byte)0x56, (byte)0xc4, (byte)0xd8, (byte)0xfb,
                (byte)0x04, (byte)0x3f, (byte)0xc5, (byte)0x7e,
                (byte)0x5e, (byte)0xaf, (byte)0xb8, (byte)0x36,
                (byte)0xf7, (byte)0x85, (byte)0xfc, (byte)0x46,
                (byte)0x47, (byte)0xc6, (byte)0xb6, (byte)0x15,
                (byte)0xfd, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0x7f, (byte)0x00
            });

    /**
     * Base point x-coordinate in the base Edwards curve
     * representation.  The value is {@code
     * 0x752cb45c48648b189df90cb2296b2878a3bfd9f42fc6c818ec8bf3c9c0c6203913f6ecc5ccc72434b1ae949d568fc99c6059d0fb13364838aa302a940a2f19ba6c}.
     */
    private static final ModE521M1 BASE_X =
        new ModE521M1(new byte[] {
                (byte)0x6c, (byte)0xba, (byte)0x19, (byte)0x2f,
                (byte)0x0a, (byte)0x94, (byte)0x2a, (byte)0x30,
                (byte)0xaa, (byte)0x38, (byte)0x48, (byte)0x36,
                (byte)0x13, (byte)0xfb, (byte)0xd0, (byte)0x59,
                (byte)0x60, (byte)0x9c, (byte)0xc9, (byte)0x8f,
                (byte)0x56, (byte)0x9d, (byte)0x94, (byte)0xae,
                (byte)0xb1, (byte)0x34, (byte)0x24, (byte)0xc7,
                (byte)0xcc, (byte)0xc5, (byte)0xec, (byte)0xf6,
                (byte)0x13, (byte)0x39, (byte)0x20, (byte)0xc6,
                (byte)0xc0, (byte)0xc9, (byte)0xf3, (byte)0x8b,
                (byte)0xec, (byte)0x18, (byte)0xc8, (byte)0xc6,
                (byte)0x2f, (byte)0xf4, (byte)0xd9, (byte)0xbf,
                (byte)0xa3, (byte)0x78, (byte)0x28, (byte)0x6b,
                (byte)0x29, (byte)0xb2, (byte)0x0c, (byte)0xf9,
                (byte)0x9d, (byte)0x18, (byte)0x8b, (byte)0x64,
                (byte)0x48, (byte)0x5c, (byte)0xb4, (byte)0x2c,
                (byte)0x75, (byte)0x00
            });

    /**
     * Base point y-coordinate in the base Edwards curve
     * representation.  The value is {@code 0xc}.
     */
    private static final ModE521M1 BASE_Y = new ModE521M1(0xc);

    /**
     * Base point x-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code
     * 0x752cb45c48648b189df90cb2296b2878a3bfd9f42fc6c818ec8bf3c9c0c6203913f6ecc5ccc72434b1ae949d568fc99c6059d0fb13364838aa302a940a2f19ba6c}.
     */
    public static ModE521M1 baseX() {
        return BASE_X.clone();
    }

    /**
     * Base point y-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code 0xc}.
     */
    public static ModE521M1 baseY() {
        return BASE_Y.clone();
    }

    /**
     * The prime order of E-521 is {@code
     * 0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd15b6c64746fc85f736b8af5e7ec53f04fbd8c4569a8f1f4540ea2435f5180d6b}.
     *
     * @return The value {@code
     * 0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd15b6c64746fc85f736b8af5e7ec53f04fbd8c4569a8f1f4540ea2435f5180d6b}.
     */
    @Override
    public ModE521M1 primeOrder() {
        return PRIME_ORDER.clone();
    }

    /**
     * The cofactor of E-521 is {@code 4}.
     *
     * @return The value {@code 4}
     */
    @Override
    public int cofactor() {
        return 4;
    }
}
