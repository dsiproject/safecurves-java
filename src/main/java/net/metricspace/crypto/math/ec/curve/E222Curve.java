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

import net.metricspace.crypto.math.field.ModE222M117;

/**
 * The E-222 elliptic curve.  This curve was introduced by Aranha,
 * Barreto, Periera, and Ricardini in their paper <a
 * href="https://eprint.iacr.org/2013/647.pdf">"A Note on
 * High-Security General-Purpose Elliptic Curves"</a>.  It is defined
 * by the equation {@code x^2 + y^2 = 1 + 160102 * x^2 * y^2} over the
 * prime field {@code mod 2^222 - 117}, and the corresponding group
 * provides roughly {@code 109.8} bits of security against the
 * Pollard-Rho attack.
 *
 * @see ModE222M117
 * @see net.metricspace.crypto.math.ec.group.E222
 */
public interface E222Curve
    extends EdwardsCurve<ModE222M117>,
            MontgomeryBirationalEquivalence<ModE222M117> {
    public static final int EDWARDS_D = 160102;
    public static final ModE222M117 MONTGOMERY_A =
        MontgomeryBirationalEquivalence
        .montgomeryAfromEdwards(new ModE222M117(1),
                                new ModE222M117(EDWARDS_D));
    public static final ModE222M117 MONTGOMERY_B =
        MontgomeryBirationalEquivalence
        .montgomeryBfromEdwards(new ModE222M117(1),
                                new ModE222M117(EDWARDS_D));

    /**
     * Defined as the value {@code 160102}.
     *
     * @return The value {@code 160102}.
     */
    @Override
    public default int edwardsD() {
        return EDWARDS_D;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public default ModE222M117 montgomeryA() {
        return MONTGOMERY_A.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public default ModE222M117 montgomeryB() {
        return MONTGOMERY_B.clone();
    }
}
