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
package net.metricspace.crypto.math.ec;

import net.metricspace.crypto.math.ec.curve.MontgomeryCurve;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * Interface for the Elligator hash algorithms.  The Elligator hash
 * algorithms were introduced by Bernstein, Hamburg, Krasnova, and
 * Lange in their paper <a
 * href="https://elligator.cr.yp.to/elligator-20130828.pdf">"Elligator:
 * Elliptic-Curve Points Indistinguishable from Uniform Random
 * Strings"</a>.  It provides the ability to hash any scalar value to
 * a point on an elliptic curve.
 * <p>
 * This is <i>not</i> a cryptogrophic function.  In fact, Elligator
 * provides a preimage function which produces scalar values from
 * elliptic curve points with a uniform distribution.
 * <p>
 * Elligator-2 functions on Montgomery curves of the form {@code y^2 =
 * x^3 + A * x^2 + Bx}, where {@code A * B * (A^2 - 4 * B) != 0}.
 *
 * @param <S> Scalar type.
 * @param <P> Point type.
 */
public interface Elligator2<S extends PrimeField<S>,
                            P extends Elligator<S, P, T>,
                            T extends ECPoint.Scratchpad>
    extends Elligator<S, P, T>,
            MontgomeryCurve<S>  {
    /**
     * {@inheritDoc}
     */
    @Override
    public default void decodeHash(final int u,
                                   final S code) {
        final S a = montgomeryA();

        /* r0 = -A / (u * code^2 + 1) */
        final S r0 = code.clone();

        r0.square();
        r0.mul(u);
        r0.add(1);
        r0.inv();
        r0.mul(a);
        r0.neg();

        /* r1 = A * r0 */
        final S r1 = r0.clone();

        r1.mul(a);

        /* r2 = ((r0^2 + r1 + 1) * r0),
         * r1 dead
         */
        final S r2 = r0.clone();

        r2.square();
        r2.add(r1);
        r2.add(1);
        r2.mul(r0);

        /* l = r2.legendre,
         * r2 dead
         */
        final int l = r2.legendre();

        /* r1 = (1 - l) * A / 2 */
        r1.set(1);
        r1.sub(r2);
        r1.mul(a);
        r1.div(2);

        /* x = l * r0 - r1,
         * r0, r1 dead
         */
        final S x = r0.clone();

        x.mul(l);
        x.sub(r1);

        /* r0 = x * A */
        r0.set(x);
        r0.mul(a);

        /* y = sqrt((x^2 + r0 + 1) * x) * -l */
        final S y = x.clone();

        y.square();
        y.add(r0);
        y.add(1);
        y.mul(x);
        y.sqrt();
        y.mul(-l);

        set(x, y);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public default S encodeHash(final int u) {
        final S x = getX();
        final S y = getY();

        /* r0 = x + A */
        final S r0 = x.clone();

        r0.add(montgomeryA());

        /* r1 = -x / r0 * u */
        final S r1 = r0.clone();

        r1.mul(u);
        r1.inv();
        r1.mul(x);
        r1.neg();

        /* r2 = u * x */
        final S r2 = x.clone();

        r2.mul(u);

        /* r0.1 = -r0 / r2,
         * r0, r2 dead
         */
        r0.neg();
        r0.div(r2);

        /* out = r1 if y.legendre == 1, r0 if y.legendre == -1 */
        final int leg = (y.legendre() + 1) >> 1;

        r1.mask(leg);
        r0.mask(leg ^ 0x1);
        r0.or(r1);

        return r0;
    }
}
