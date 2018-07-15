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

import net.metricspace.crypto.math.ec.curve.Curve1174Curve;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.ec.point.EdwardsPoint;
import net.metricspace.crypto.math.field.ModE251M9;

/**
 * The Curve1174 elliptic curve.  This curve was introduced by
 * Bernstein, Hamburg, Krasnova, and Lange in their paper <a
 * href="https://eprint.iacr.org/2013/325.pdf">"Elligator:
 * Elliptic-Curve Points Indistinguishable from Uniform Random
 * Strings"</a>.  It is defined by the equation {@code x^2 + y^2 = 1 -
 * 1174 * x^2 * y^2} over the prime field {@code mod 2^251 - 9}, and
 * provides roughly {@code 124.3} bits of security against the
 * Pollard-Rho attack.
 *
 * @param <P> The concrete point type.
 * @see ModE251M9
 * @see net.metricspace.crypto.math.ec.curve.Curve1174Curve
 */
public abstract class Curve1174<P extends EdwardsPoint<ModE251M9, P, T>,
                                T extends ECPoint.Scratchpad<ModE251M9>>
    extends EdwardsCurveGroup<ModE251M9, P, T>
    implements Curve1174Curve {
    /**
     * Prime order for the base Edwards curve representation.  The
     * value is {@code
     * 0x1fffffffffffffffffffffffffffffff77965c4dfd307348944d45fd166c971}.
     */
    public static final ModE251M9 PRIME_ORDER =
        new ModE251M9(new byte[] {
                (byte)0x71, (byte)0xc9, (byte)0x66, (byte)0xd1,
                (byte)0x5f, (byte)0xd4, (byte)0x44, (byte)0x89,
                (byte)0x34, (byte)0x07, (byte)0xd3, (byte)0xdf,
                (byte)0xc4, (byte)0x65, (byte)0x79, (byte)0xf7,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0x01
            });

    /**
     * Base point x-coordinate in the base Edwards curve
     * representation.  The value is {@code
     * 0x037fbb0cea308c479343aee7c029a190c021d96a492ecd6516123f27bce29eda}.
     */
    private static final ModE251M9 BASE_X =
        new ModE251M9(new byte[] {
                (byte)0xda, (byte)0x9e, (byte)0xe2, (byte)0xbc,
                (byte)0x27, (byte)0x3f, (byte)0x12, (byte)0x16,
                (byte)0x65, (byte)0xcd, (byte)0x2e, (byte)0x49,
                (byte)0x6a, (byte)0xd9, (byte)0x21, (byte)0xc0,
                (byte)0x90, (byte)0xa1, (byte)0x29, (byte)0xc0,
                (byte)0xe7, (byte)0xae, (byte)0x43, (byte)0x93,
                (byte)0x47, (byte)0x8c, (byte)0x30, (byte)0xea,
                (byte)0x0c, (byte)0xbb, (byte)0x7f, (byte)0x03
            });

    /**
     * Base point y-coordinate in the base Edwards curve
     * representation.  The value is {@code
     * 0x06b72f82d47fb7cc6656841169840e0c4fe2dee2af3f976ba4ccb1bf9b46360e}.
     */
    private static final ModE251M9 BASE_Y =
        new ModE251M9(new byte[] {
                (byte)0x0e, (byte)0x36, (byte)0x46, (byte)0x9b,
                (byte)0xbf, (byte)0xb1, (byte)0xcc, (byte)0xa4,
                (byte)0x6b, (byte)0x97, (byte)0x3f, (byte)0xaf,
                (byte)0xe2, (byte)0xde, (byte)0xe2, (byte)0x4f,
                (byte)0x0c, (byte)0x0e, (byte)0x84, (byte)0x69,
                (byte)0x11, (byte)0x84, (byte)0x56, (byte)0x66,
                (byte)0xcc, (byte)0xb7, (byte)0x7f, (byte)0xd4,
                (byte)0x82, (byte)0x2f, (byte)0xb7, (byte)0x06
            });

    /**
     * Base point x-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code
     * 0x037fbb0cea308c479343aee7c029a190c021d96a492ecd6516123f27bce29eda}.
     */
    public static ModE251M9 baseX() {
        return BASE_X.clone();
    }

    /**
     * Base point y-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code
     * 0x06b72f82d47fb7cc6656841169840e0c4fe2dee2af3f976ba4ccb1bf9b46360e}.
     */
    public static ModE251M9 baseY() {
        return BASE_Y.clone();
    }

    /**
     * The prime order of Curve1174 is {@code
     * 0x1fffffffffffffffffffffffffffffff77965c4dfd307348944d45fd166c971}.
     *
     * @return The value {@code
     * 0x1fffffffffffffffffffffffffffffff77965c4dfd307348944d45fd166c971}.
     */
    @Override
    public ModE251M9 primeOrder() {
        return PRIME_ORDER.clone();
    }

    /**
     * The cofactor of Curve1174 is {@code 4}.
     *
     * @return The value {@code 4}
     */
    @Override
    public int cofactor() {
        return 4;
    }
}
