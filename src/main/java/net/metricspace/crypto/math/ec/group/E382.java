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

import net.metricspace.crypto.math.ec.curve.E382Curve;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.ec.point.EdwardsPoint;
import net.metricspace.crypto.math.field.ModE382M105;

/**
 * The E-382 elliptic curve group.  This curve was introduced by
 * Aranha, Barreto, Periera, and Ricardini in their paper <a
 * href="https://eprint.iacr.org/2013/647.pdf">"A Note on
 * High-Security General-Purpose Elliptic Curves"</a> and satisfies
 * all criteria of the <a
 * href="https://safecurves.cr.yp.to/index.html">SafeCurves
 * project</a>.  It is defined by the equation {@code x^2 + y^2 = 1 -
 * 67254 * x^2 * y^2} over the prime field {@code mod 2^382 - 105},
 * and provides roughly {@code 189.8} bits of security against the
 * Pollard-Rho attack.
 *
 * @param <P> The concrete point type.
 * @see ModE382M105
 * @see net.metricspace.crypto.math.ec.curve.E382Curve
 */
public abstract class E382<P extends EdwardsPoint<ModE382M105, P, T>,
                           T extends ECPoint.Scratchpad<ModE382M105>>
    extends EdwardsCurveGroup<ModE382M105, P, T>
    implements E382Curve {
    /**
     * Prime order for the base Edwards curve representation.  The
     * value is {@code
     * 0xfffffffffffffffffffffffffffffffffffffffffffffffd5fb21f21e95eee17c5e69281b102d2773e27e13fd3c9719}.
     */
    public static final ModE382M105 PRIME_ORDER =
        new ModE382M105(new byte[] {
                (byte)0x19, (byte)0x97, (byte)0x3c, (byte)0xfd,
                (byte)0x13, (byte)0x7e, (byte)0xe2, (byte)0x73,
                (byte)0x27, (byte)0x2d, (byte)0x10, (byte)0x1b,
                (byte)0x28, (byte)0x69, (byte)0x5e, (byte)0x7c,
                (byte)0xe1, (byte)0xee, (byte)0x95, (byte)0x1e,
                (byte)0xf2, (byte)0x21, (byte)0xfb, (byte)0xd5,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0x0f
            });

    /**
     * Base point x-coordinate in the base Edwards curve
     * representation.  The value is {@code
     * 0x196f8dd0eab20391e5f05be96e8d20ae68f840032b0b64352923bab85364841193517dbce8105398ebc0cc9470f79603}.
     */
    private static final ModE382M105 BASE_X =
        new ModE382M105(new byte[] {
                (byte)0x03, (byte)0x96, (byte)0xf7, (byte)0x70,
                (byte)0x94, (byte)0xcc, (byte)0xc0, (byte)0xeb,
                (byte)0x98, (byte)0x53, (byte)0x10, (byte)0xe8,
                (byte)0xbc, (byte)0x7d, (byte)0x51, (byte)0x93,
                (byte)0x11, (byte)0x84, (byte)0x64, (byte)0x53,
                (byte)0xb8, (byte)0xba, (byte)0x23, (byte)0x29,
                (byte)0x35, (byte)0x64, (byte)0x0b, (byte)0x2b,
                (byte)0x03, (byte)0x40, (byte)0xf8, (byte)0x68,
                (byte)0xae, (byte)0x20, (byte)0x8d, (byte)0x6e,
                (byte)0xe9, (byte)0x5b, (byte)0xf0, (byte)0xe5,
                (byte)0x91, (byte)0x03, (byte)0xb2, (byte)0xea,
                (byte)0xd0, (byte)0x8d, (byte)0x6f, (byte)0x19
            });

    /**
     * Base point y-coordinate in the base Edwards curve
     * representation.  The value is {@code 0x11}.
     */
    private static final ModE382M105 BASE_Y = new ModE382M105(0x11);

    /**
     * Base point x-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code 0xc}.
     */
    public static ModE382M105 baseX() {
        return BASE_X.clone();
    }

    /**
     * Base point y-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code
     * 0x196f8dd0eab20391e5f05be96e8d20ae68f840032b0b64352923bab85364841193517dbce8105398ebc0cc9470f79603}.
     */
    public static ModE382M105 baseY() {
        return BASE_Y.clone();
    }

    /**
     * The prime order of E-382 is {@code
     * 0xfffffffffffffffffffffffffffffffffffffffffffffffd5fb21f21e95eee17c5e69281b102d2773e27e13fd3c9719}
     *
     * @return The value {@code
     * 0xfffffffffffffffffffffffffffffffffffffffffffffffd5fb21f21e95eee17c5e69281b102d2773e27e13fd3c9719}
     */
    @Override
    public ModE382M105 primeOrder() {
        return PRIME_ORDER.clone();
    }

    /**
     * The cofactor of E-382 is {@code 4}.
     *
     * @return The value {@code 4}
     */
    @Override
    public int cofactor() {
        return 4;
    }
}
