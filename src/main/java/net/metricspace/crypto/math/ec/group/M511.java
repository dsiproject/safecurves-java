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

import net.metricspace.crypto.math.ec.curve.M511Curve;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.ModE511M187;

/**
 * The M-511 elliptic curve.  This curve was introduced by Aranha,
 * Barreto, Periera, and Ricardini in their paper <a
 * href="https://eprint.iacr.org/2013/647.pdf">"A Note on
 * High-Security General-Purpose Elliptic Curves"</a>.  It is defined
 * by the Montgomery-form equation {@code y^2 = x^3 + 530438 * x^2 *
 * x} over the prime field {@code mod 2^511 - 187}, and the
 * corresponding group provides roughly {@code 253.8} bits of security
 * against the Pollard-Rho attack.
 * <p>
 * This curve is also birationally equivalent to the twisted Edwards
 * curve {@code 530440 * x^2 + y^2 = 1 + 530436 * x^2 * y^2}.
 *
 * @see ModE511M187
 * @see net.metricspace.crypto.math.ec.group.M511
 */
public abstract class M511<P extends ECPoint<ModE511M187, P, ?>>
    extends MontgomeryCurveGroup<ModE511M187, P>
    implements M511Curve {
    /**
     * Prime order for the group.  The value is {@code
     * 0x100000000000000000000000000000000000000000000000000000000000000017b5feff30c7f5677ab2aeebd13779a2ac125042a6aa10bfa54c15bab76baf1b}.
     */
    private static final ModE511M187 PRIME_ORDER =
        new ModE511M187(new byte[] {
                (byte)0x1b, (byte)0xaf, (byte)0x6b, (byte)0xb7,
                (byte)0xba, (byte)0x15, (byte)0x4c, (byte)0xa5,
                (byte)0xbf, (byte)0x10, (byte)0xaa, (byte)0xa6,
                (byte)0x42, (byte)0x50, (byte)0x12, (byte)0xac,
                (byte)0xa2, (byte)0x79, (byte)0x37, (byte)0xd1,
                (byte)0xeb, (byte)0xae, (byte)0xb2, (byte)0x7a,
                (byte)0x67, (byte)0xf5, (byte)0xc7, (byte)0x30,
                (byte)0xff, (byte)0xfe, (byte)0xb5, (byte)0x17,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x10
            });

    /**
     * Base point x-coordinate in the base Montgomery curve
     * representation.  The value is {@code 0x5}.
     */
    private static final ModE511M187 BASE_X = new ModE511M187(0x5);

    /**
     * Base point x-coordinate in the base Montgomery curve
     * representation.  The value is {@code
     * 0x2fbdc0ad8530803d28fdbad354bb488d32399ac1cf8f6e01ee3f96389b90c809422b9429e8a43dbf49308ac4455940abe9f1dbca542093a895e30a64af056fa5}.
     */
    private static final ModE511M187 BASE_Y =
        new ModE511M187(new byte[] {
                (byte)0xa5, (byte)0x6f, (byte)0x05, (byte)0xaf,
                (byte)0x64, (byte)0x0a, (byte)0xe3, (byte)0x95,
                (byte)0xa8, (byte)0x93, (byte)0x20, (byte)0x54,
                (byte)0xca, (byte)0xdb, (byte)0xf1, (byte)0xe9,
                (byte)0xab, (byte)0x40, (byte)0x59, (byte)0x45,
                (byte)0xc4, (byte)0x8a, (byte)0x30, (byte)0x49,
                (byte)0xbf, (byte)0x3d, (byte)0xa4, (byte)0xe8,
                (byte)0x29, (byte)0x94, (byte)0x2b, (byte)0x42,
                (byte)0x09, (byte)0xc8, (byte)0x90, (byte)0x9b,
                (byte)0x38, (byte)0x96, (byte)0x3f, (byte)0xee,
                (byte)0x01, (byte)0x6e, (byte)0x8f, (byte)0xcf,
                (byte)0xc1, (byte)0x9a, (byte)0x39, (byte)0x32,
                (byte)0x8d, (byte)0x48, (byte)0xbb, (byte)0x54,
                (byte)0xd3, (byte)0xba, (byte)0xfd, (byte)0x28,
                (byte)0x3d, (byte)0x80, (byte)0x30, (byte)0x85,
                (byte)0xad, (byte)0xc0, (byte)0xbd, (byte)0x2f
            });

    /**
     * Base point y-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code 0x5}.
     */
    public static ModE511M187 baseX() {
        return BASE_X.clone();
    }

    /**
     * Base point y-coordinate in the base Edwards curve
     * representation.
     *
     * @return The value {@code 0x2fbdc0ad8530803d28fdbad354bb488d32399ac1cf8f6e01ee3f96389b90c809422b9429e8a43dbf49308ac4455940abe9f1dbca542093a895e30a64af056fa5}.
     */
    public static ModE511M187 baseY() {
        return BASE_Y.clone();
    }

    /**
     * The prime order of M-511 is {@code
     * 0x100000000000000000000000000000000000000000000000000000000000000017b5feff30c7f5677ab2aeebd13779a2ac125042a6aa10bfa54c15bab76baf1b}.
     *
     * @return The value {@code
     * 0x100000000000000000000000000000000000000000000000000000000000000017b5feff30c7f5677ab2aeebd13779a2ac125042a6aa10bfa54c15bab76baf1b}.
     */
    @Override
    public ModE511M187 primeOrder() {
        return PRIME_ORDER.clone();
    }
}
