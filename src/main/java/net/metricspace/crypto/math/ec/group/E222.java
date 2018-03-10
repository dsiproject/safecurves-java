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

import net.metricspace.crypto.math.ec.curve.E222Curve;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.ModE222M117;

/**
 * The E-222 elliptic curve group.  This curve was introduced by
 * Aranha, Barreto, Periera, and Ricardini in their paper <a
 * href="https://eprint.iacr.org/2013/647.pdf">"A Note on
 * High-Security General-Purpose Elliptic Curves"</a> and satisfies
 * all criteria of the <a
 * href="https://safecurves.cr.yp.to/index.html">SafeCurves
 * project</a>.  It is defined by the equation {@code x^2 + y^2 = 1 +
 * 160102 * x^2 * y^2} over the prime field {@code mod 2^222 - 117},
 * and provides roughly {@code 109.8} bits of security against the
 * Pollard-Rho attack.
 *
 * @param <P> The concrete point type.
 * @see ModE222M117
 * @see net.metricspace.crypto.math.ec.curve.E222Curve
 */
public abstract class E222<P extends ECPoint<ModE222M117, P>>
    extends EdwardsCurveGroup<ModE222M117, P>
    implements E222Curve {
    /**
     * Prime order for the base Edwards curve representation.  The
     * value is {@code
     * 0xffffffffffffffffffffffffffff70cbc95e932f802f31423598cbf}.
     */
    public static final ModE222M117 PRIME_ORDER =
        new ModE222M117(new byte[] {
                (byte)0xbf, (byte)0x8c, (byte)0x59, (byte)0x23,
                (byte)0x14, (byte)0xf3, (byte)0x02, (byte)0xf8,
                (byte)0x32, (byte)0xe9, (byte)0x95, (byte)0xbc,
                (byte)0x0c, (byte)0xf7, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0x0f,
            });

    /**
     * Base point x-coordinate in the base Edwards curve
     * representation.  The value is {@code
     * 0x19b12bb156a389e55c9768c303316d07c23adab3736eb2bc3eb54e51}.
     */
    private static final ModE222M117 BASE_X =
        new ModE222M117(new byte[] {
                (byte)0x51, (byte)0x4e, (byte)0xb5, (byte)0x3e,
                (byte)0xbc, (byte)0xb2, (byte)0x6e, (byte)0x73,
                (byte)0xb3, (byte)0xda, (byte)0x3a, (byte)0xc2,
                (byte)0x07, (byte)0x6d, (byte)0x31, (byte)0x03,
                (byte)0xc3, (byte)0x68, (byte)0x97, (byte)0x5c,
                (byte)0xe5, (byte)0x89, (byte)0xa3, (byte)0x56,
                (byte)0xb1, (byte)0x2b, (byte)0xb1, (byte)0x19,
            });

    /**
     * Base point y-coordinate in the base Edwards curve
     * representation.  The value is {@code 0x1c}.
     */
    private static final ModE222M117 BASE_Y = new ModE222M117(0x1c);

    /**
     * Base point x-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code
     * 0x19b12bb156a389e55c9768c303316d07c23adab3736eb2bc3eb54e51}.
     */
    public static ModE222M117 baseX() {
        return BASE_X.clone();
    }

    /**
     * Base point y-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code 0x1c}.
     */
    public static ModE222M117 baseY() {
        return BASE_Y.clone();
    }

    /**
     * The prime order of E-222 is {@code
     * 0xffffffffffffffffffffffffffff70cbc95e932f802f31423598cbf}
     *
     * @return The value {@code
     * 0xffffffffffffffffffffffffffff70cbc95e932f802f31423598cbf}
     */
    @Override
    public ModE222M117 primeOrder() {
        return PRIME_ORDER.clone();
    }

    /**
     * The cofactor of E-222 is {@code 4}.
     *
     * @return The value {@code 4}
     */
    @Override
    public int cofactor() {
        return 4;
    }
}
