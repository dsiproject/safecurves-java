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

import net.metricspace.crypto.math.ec.curve.Curve41417Curve;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.ModE414M17;

/**
 * The Curve41417 elliptic curve group.  This curve was introduced by
 * Bernstein, Chuengsatiansup, and Lange in their paper <a
 * href="https://cr.yp.to/ecdh/curve41417-20140706.pdf">"Curve41417:
 * Karatsuba Revisited"</a> and satisfies all criteria of the <a
 * href="https://safecurves.cr.yp.to/index.html">SafeCurves
 * project</a>.  It is defined by the equation {@code x^2 + y^2 = 1 +
 * 3673 * x^2 * y^2} over the prime field {@code mod 2^414 - 17}, and
 * provides roughly {@code 205.3} bits of security against the
 * Pollard-Rho attack.
 *
 * @param <P> The concrete point type.
 * @see ModE414M17
 * @see net.metricspace.crypto.math.ec.curve.Curve41417Curve
 */
public abstract class Curve41417<P extends ECPoint<ModE414M17, P, ?>>
    extends EdwardsCurveGroup<ModE414M17, P>
    implements Curve41417Curve {
    /**
     * Prime order for the base Edwards curve representation.  The
     * value is {@code
     * 0x7ffffffffffffffffffffffffffffffffffffffffffffffffffeb3cc92414cf706022b36f1c0338ad63cf181b0e71a5e106af79}.
     */
    private static final ModE414M17 PRIME_ORDER =
        new ModE414M17(new byte[] {
                (byte)0x79, (byte)0xaf, (byte)0x06, (byte)0xe1,
                (byte)0xa5, (byte)0x71, (byte)0x0e, (byte)0x1b,
                (byte)0x18, (byte)0xcf, (byte)0x63, (byte)0xad,
                (byte)0x38, (byte)0x03, (byte)0x1c, (byte)0x6f,
                (byte)0xb3, (byte)0x22, (byte)0x60, (byte)0x70,
                (byte)0xcf, (byte)0x14, (byte)0x24, (byte)0xc9,
                (byte)0x3c, (byte)0xeb, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0x07
            });

    /**
     * Base point x-coordinate in the base Edwards curve
     * representation.  The value is {@code
     * 0x1a334905141443300218c0631c326e5fcd46369f44c03ec7f57ff35498a4ab4d6d6ba111301a73faa8537c64c4fd3812f3cbc595}.
     */
    private static final ModE414M17 BASE_X =
        new ModE414M17(new byte[] {
                (byte)0x95, (byte)0xc5, (byte)0xcb, (byte)0xf3,
                (byte)0x12, (byte)0x38, (byte)0xfd, (byte)0xc4,
                (byte)0x64, (byte)0x7c, (byte)0x53, (byte)0xa8,
                (byte)0xfa, (byte)0x73, (byte)0x1a, (byte)0x30,
                (byte)0x11, (byte)0xa1, (byte)0x6b, (byte)0x6d,
                (byte)0x4d, (byte)0xab, (byte)0xa4, (byte)0x98,
                (byte)0x54, (byte)0xf3, (byte)0x7f, (byte)0xf5,
                (byte)0xc7, (byte)0x3e, (byte)0xc0, (byte)0x44,
                (byte)0x9f, (byte)0x36, (byte)0x46, (byte)0xcd,
                (byte)0x5f, (byte)0x6e, (byte)0x32, (byte)0x1c,
                (byte)0x63, (byte)0xc0, (byte)0x18, (byte)0x02,
                (byte)0x30, (byte)0x43, (byte)0x14, (byte)0x14,
                (byte)0x05, (byte)0x49, (byte)0x33, (byte)0x1a
            });

    /**
     * Base point x-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code
     * 0x1a334905141443300218c0631c326e5fcd46369f44c03ec7f57ff35498a4ab4d6d6ba111301a73faa8537c64c4fd3812f3cbc595}.
     */
    public static ModE414M17 baseX() {
        return BASE_X.clone();
    }

    /**
     * Base point y-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code 0x22}.
     */
    public static ModE414M17 baseY() {
        return BASE_Y.clone();
    }

    /**
     * Base point y-coordinate in the base Edwards curve
     * representation.  The value is {@code 0x22}.
     */
    public static final ModE414M17 BASE_Y = new ModE414M17(0x22);

    /**
     * The prime order of Curve41417 is {@code
     * 0x7ffffffffffffffffffffffffffffffffffffffffffffffffffeb3cc92414cf706022b36f1c0338ad63cf181b0e71a5e106af79}.
     *
     * @return The value {@code
     * 0x7ffffffffffffffffffffffffffffffffffffffffffffffffffeb3cc92414cf706022b36f1c0338ad63cf181b0e71a5e106af79}.
     */
    @Override
    public ModE414M17 primeOrder() {
        return PRIME_ORDER.clone();
    }

    /**
     * The cofactor of Curve41417 is {@code 8}.
     *
     * @return The value {@code 8}
     */
    @Override
    public int cofactor() {
        return 8;
    }
}
