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

import net.metricspace.crypto.math.ec.curve.M383Curve;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.ModE383M187;

/**
 * The M383 elliptic curve.  This curve was introduced by Aranha,
 * Barreto, Periera, and Ricardini in their paper <a
 * href="https://eprint.iacr.org/2013/647.pdf">"A Note on
 * High-Security General-Purpose Elliptic Curves"</a>.  It is defined
 * by the Montgomery-form equation {@code y^2 = x^3 + 2065150 * x^2 *
 * x} over the prime field {@code mod 2^383 - 187}, and provides
 * roughly {@code 189.8} bits of security against the Pollard-Rho
 * attack.
 * <p>
 * This curve is also birationally equivalent to the twisted Edwards
 * curve {@code 2065152 * x^2 + y^2 = 1 + 2065148 * x^2 * y^2}.
 *
 * @see ModE383M187
 * @see net.metricspace.crypto.math.ec.group.M383
 */
public abstract class M383<P extends ECPoint<ModE383M187, P, ?>>
    extends MontgomeryCurveGroup<ModE383M187, P>
    implements M383Curve {
    /**
     * Prime order for the group.  The value is {@code
     * 0x10000000000000000000000000000000000000000000000006c79673ac36ba6e7a32576f7b1b249e46bbc225be9071d7}.
     */
    private static final ModE383M187 PRIME_ORDER =
        new ModE383M187(new byte[] {
                (byte)0xd7, (byte)0x71, (byte)0x90, (byte)0xbe,
                (byte)0x25, (byte)0xc2, (byte)0xbb, (byte)0x46,
                (byte)0x9e, (byte)0x24, (byte)0x1b, (byte)0x7b,
                (byte)0x6f, (byte)0x57, (byte)0x32, (byte)0x7a,
                (byte)0x6e, (byte)0xba, (byte)0x36, (byte)0xac,
                (byte)0x73, (byte)0x96, (byte)0xc7, (byte)0x06,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x10
            });

    /**
     * Base point x-coordinate in the base Montgomery curve
     * representation.  The value is {@code 0xc}.
     */
    private static final ModE383M187 BASE_X = new ModE383M187(0xc);

    /**
     * Base point y-coordinate in the base Montgomery curve
     * representation.  The value is {@code
     * 0x1ec7ed04aaf834af310e304b2da0f328e7c165f0e8988abd3992861290f617aa1f1b2e7d0b6e332e969991b62555e77e}.
     */
    private static final ModE383M187 BASE_Y =
        new ModE383M187(new byte[] {
                (byte)0x7e, (byte)0xe7, (byte)0x55, (byte)0x25,
                (byte)0xb6, (byte)0x91, (byte)0x99, (byte)0x96,
                (byte)0x2e, (byte)0x33, (byte)0x6e, (byte)0x0b,
                (byte)0x7d, (byte)0x2e, (byte)0x1b, (byte)0x1f,
                (byte)0xaa, (byte)0x17, (byte)0xf6, (byte)0x90,
                (byte)0x12, (byte)0x86, (byte)0x92, (byte)0x39,
                (byte)0xbd, (byte)0x8a, (byte)0x98, (byte)0xe8,
                (byte)0xf0, (byte)0x65, (byte)0xc1, (byte)0xe7,
                (byte)0x28, (byte)0xf3, (byte)0xa0, (byte)0x2d,
                (byte)0x4b, (byte)0x30, (byte)0x0e, (byte)0x31,
                (byte)0xaf, (byte)0x34, (byte)0xf8, (byte)0xaa,
                (byte)0x04, (byte)0xed, (byte)0xc7, (byte)0x1e
            });

    /**
     * Base point x-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code 0x9}.
     */
    public static ModE383M187 baseX() {
        return BASE_X.clone();
    }

    /**
     * Base point y-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code
     * 0x1ec7ed04aaf834af310e304b2da0f328e7c165f0e8988abd3992861290f617aa1f1b2e7d0b6e332e969991b62555e77e}.
     */
    public static ModE383M187 baseY() {
        return BASE_Y.clone();
    }

    /**
     * The prime order of M-383 is {@code
     * 0x10000000000000000000000000000000000000000000000006c79673ac36ba6e7a32576f7b1b249e46bbc225be9071d7}.
     *
     * @return The value {@code
     * 0x10000000000000000000000000000000000000000000000006c79673ac36ba6e7a32576f7b1b249e46bbc225be9071d7}.
     */
    @Override
    public ModE383M187 primeOrder() {
        return PRIME_ORDER.clone();
    }
}
