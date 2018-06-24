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
package net.metricspace.crypto.math.ec.curve;

import net.metricspace.crypto.math.field.ModE221M3;

/**
 * The E-221 elliptic curve.  This curve was introduced by Aranha,
 * Barreto, Periera, and Ricardini in their paper <a
 * href="https://eprint.iacr.org/2013/647.pdf">"A Note on
 * High-Security General-Purpose Elliptic Curves"</a>.  It is defined
 * by the Montgomery-form equation {@code y^2 = x^3 + 117050 * x^2 +
 * x} over the prime field {@code mod 2^221 - 3}, and the
 * corresponding group provides roughly {@code 108.8} bits of security
 * against the Pollard-Rho attack.
 * <p>
 * This curve is also birationally equivalent to the twisted Edwards
 * curve {@code 117052 * x^2 + y^2 = 1 + 117048 * x^2 * y^2}.
 *
 * @see ModE221M3
 * @see net.metricspace.crypto.math.ec.group.M221
 */
public interface M221Curve
    extends TwistedEdwardsCurve<ModE221M3>,
            MontgomeryBirationalEquivalence<ModE221M3> {
    public static final int EDWARDS_A = 117052;
    public static final int EDWARDS_D = 117048;
    public static final ModE221M3 MONTGOMERY_A =
        MontgomeryBirationalEquivalence
        .montgomeryAfromEdwards(new ModE221M3(EDWARDS_A),
                                new ModE221M3(EDWARDS_D));
    public static final ModE221M3 MONTGOMERY_B =
        MontgomeryBirationalEquivalence
        .montgomeryBfromEdwards(new ModE221M3(EDWARDS_A),
                                new ModE221M3(EDWARDS_D));

    /**
     * Defined as the value {@code 117052}.
     *
     * @return The value {@code 117052}.
     */
    @Override
    public default int edwardsA() {
        return EDWARDS_A;
    }

    /**
     * Defined as the value {@code 117048}.
     *
     * @return The value {@code 117048}.
     */
    @Override
    public default int edwardsD() {
        return EDWARDS_D;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public default ModE221M3 montgomeryA() {
        return MONTGOMERY_A.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public default ModE221M3 montgomeryB() {
        return MONTGOMERY_B.clone();
    }
}
