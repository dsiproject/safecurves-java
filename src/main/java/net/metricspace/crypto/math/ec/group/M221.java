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

import net.metricspace.crypto.math.ec.curve.M221Curve;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.ModE221M3;

/**
 * The M-221 elliptic curve.  This curve was introduced by Aranha,
 * Barreto, Periera, and Ricardini in their paper <a
 * href="https://eprint.iacr.org/2013/647.pdf">"A Note on
 * High-Security General-Purpose Elliptic Curves"</a>.  It is defined
 * by the Montgomery-form equation {@code y^2 = x^3 + 117050 * x^2 *
 * x} over the prime field {@code mod 2^221 - 3}, and provides roughly
 * {@code 108.8} bits of security against the Pollard-Rho attack.
 * <p>
 * This curve is also birationally equivalent to the twisted Edwards
 * curve {@code 117052 * x^2 + y^2 = 1 + 117048 * x^2 * y^2}.
 *
 * @see ModE221M3
 * @see net.metricspace.crypto.math.ec.curve.M221Curve
 */
public abstract class M221<P extends ECPoint<ModE221M3, P>>
    extends MontgomeryCurveGroup<ModE221M3, P>
    implements M221Curve {
    /**
     * Prime order for the group.  The value is {@code
     * 0x40000000000000000000000000015a08ed730e8a2f77f005042605b}.
     */
    public static final ModE221M3 PRIME_ORDER =
        new ModE221M3(new byte[] {
                (byte)0x5b, (byte)0x60, (byte)0x42, (byte)0x50,
                (byte)0x00, (byte)0x7f, (byte)0xf7, (byte)0xa2,
                (byte)0xe8, (byte)0x30, (byte)0xd7, (byte)0x8e,
                (byte)0xa0, (byte)0x15, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x04
            });

    /**
     * Base point x-coordinate in the base Montgomery curve
     * representation.  The value is {@code 0x4}.
     */
    private static final ModE221M3 BASE_X = new ModE221M3(0x4);

    /**
     * Base point y-coordinate in the base Montgomery curve
     * representation.  The value is {@code
     * 0xf7acdd2a4939571d1cef14eca37c228e61dbff10707dc6c08c5056d}.
     */
    private static final ModE221M3 BASE_Y =
        new ModE221M3(new byte[] {
                (byte)0x6d, (byte)0x05, (byte)0xc5, (byte)0x08,
                (byte)0x6c, (byte)0xdc, (byte)0x07, (byte)0x07,
                (byte)0xf1, (byte)0xbf, (byte)0x1d, (byte)0xe6,
                (byte)0x28, (byte)0xc2, (byte)0x37, (byte)0xca,
                (byte)0x4e, (byte)0xf1, (byte)0xce, (byte)0xd1,
                (byte)0x71, (byte)0x95, (byte)0x93, (byte)0xa4,
                (byte)0xd2, (byte)0xcd, (byte)0x7a, (byte)0x0f
            });

    /**
     * Base point x-coordinate in the base Montgomery curve
     * representation.
     *
     * @return The value {@code 0x4}.
     */
    public static ModE221M3 baseX() {
        return BASE_X.clone();
    }

    /**
     * Base point y-coordinate in the base Montgomery curve
     * representation.
     *
     * @return The value {@code
     * 0xf7acdd2a4939571d1cef14eca37c228e61dbff10707dc6c08c5056d}.
     */
    public static ModE221M3 baseY() {
        return BASE_Y.clone();
    }

    /**
     * The prime order of M-221 is {@code
     * 0x40000000000000000000000000015a08ed730e8a2f77f005042605b}
     *
     * @return The value {@code
     * 0x40000000000000000000000000015a08ed730e8a2f77f005042605b}
     */
    @Override
    public ModE221M3 primeOrder() {
        return PRIME_ORDER.clone();
    }
}
