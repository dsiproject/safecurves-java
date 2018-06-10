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

import net.metricspace.crypto.math.field.PrimeField;

/**
 * A Montgomery curve which is derived through the birationally
 * equivalence to an underlying twisted Edwards curve.
 *
 * @param <F> The field underlying the Edwards curve.
 */
public interface MontgomeryBirationalEquivalence<F extends PrimeField<F>>
    extends MontgomeryCurve<F>,
            TwistedEdwardsCurve<F> {
    /**
     * Calculate the Montgomery {@code A} parameter from Edwards parameters.
     *
     * @param <F> The field underlying the Edwards curve.
     * @param edwardsA The Edwards {@code a} parameter.
     * @param edwardsD The Edwards {@code d} parameter.
     * @return The Montgomery {@code A} parameter.
     */
    public static <F extends PrimeField<F>>
        F montgomeryAfromEdwards(final F edwardsA,
                                 final F edwardsD) {
        final F out = edwardsA.clone();
        final F denom = edwardsA.clone();

        denom.sub(edwardsD);
        out.add(edwardsD);
        out.mul(2);
        out.div(denom);

        return out;
    };

    /**
     * Calculate the Montgomery {@code B} parameter from Edwards parameters.
     *
     * @param <F> The field underlying the Edwards curve.
     * @param edwardsA The Edwards {@code a} parameter.
     * @param edwardsD The Edwards {@code d} parameter.
     * @return The Montgomery {@code B} parameter.
     */
    public static <F extends PrimeField<F>>
        F montgomeryBfromEdwards(final F edwardsA,
                                 final F edwardsD) {
        final F out = edwardsA.clone();
        final F denom = edwardsA.clone();

        out.set(4);
        denom.sub(edwardsD);
        out.div(denom);

        return out;
    };
}
