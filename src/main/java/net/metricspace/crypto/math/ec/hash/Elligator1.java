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

import net.metricspace.crypto.math.ec.curve.EdwardsCurve;
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
 * Elligator-1 functions on Edwards curves over primes of the form
 * {@code 3 mod 4}.
 *
 * @param <S> Scalar type.
 * @param <P> Point type.
 */
public interface Elligator1<S extends PrimeField<S>,
                            P extends Elligator<S, P>>
    extends Elligator<S, P>, EdwardsCurve<S> {
    /**
     * {@inheritDoc}
     */
    @Override
    public default void decodeHash(final int s,
                                   final S t) {
        /* r0 = 2 / s^2 */
        final S r0 = t.clone();

        r0.set(s);
        r0.square();
        r0.inv();
        r0.mul(2);

        /* r1 = r0 + 1 / r0 */
        final S r1 = r0.clone();

        r1.inv();
        r1.add(r0);

        /* r2 = 1 + t */
        final S r2 = t.clone();

        r2.add(1);

        /* r3 = (1 - t) / r2,
         * r2 dead
         */
        final S r3 = t.clone();

        r3.sub(1);
        r3.neg();
        r3.div(r2);

        /* r4 = r3^2 */
        final S r4 = r3.clone();

        r4.square();

        /* r2.1 = (r1^2 - 2) * r4 */
        r2.set(r1);
        r2.square();
        r2.sub(2);
        r2.mul(r4);

        /* r5 = (r4^2 + r2.1 + 1) * r3,
         * r2.1 dead
         */
        final S r5 = r4.clone();

        r5.add(r2);
        r5.add(1);
        r5.mul(r3);

        /* r2.2 = r5.legendre * r3,
         * r3 dead
         */
        r2.set(r3);
        r2.mul(r5.legendre());

        /* r3.1 = 1 / r0^2 */
        r3.set(r0);
        r3.square();
        r3.inv();

        /* r4.1 = r4 + r3.1,
         * r4, r3.1 dead
         */
        r4.add(r3);

        /* l = r5.legendre */
        final int l = r5.legendre();

        /* r5.1 = (l * r5).sqrt * l * r4.1.legendre,
         * r5, r4.1 dead
         */
        r5.mul(l);
        r5.sqrt();
        r5.mul(l);
        r5.mul(r4.legendre());

        /* r3.3 = r2.2 + 1 */
        r3.set(r2);
        r3.add(1);

        /* r0.1 = (r0 - 1) * s * r2.2 * r3.3 / r5.1,
         * r0, r5.1 dead
         */
        r0.sub(1);
        r0.mul(s);
        r0.mul(r2);
        r0.mul(r3);
        r5.inv();
        r0.mul(r5);

        /* r3.4 = r3.3^2 */
        r3.square();
        /* r4.1 = r1 * r2.2,
         * r1, r2.2 dead
         */
        r4.set(r1);
        r4.mul(r2);

        /* r1.1 = r4.1 + r3.4 */
        r1.set(r4);
        r1.add(r3);

        /* r4.2 = r4.1 - r3.4 */
        r4.sub(r3);

        /* r1.2 = r4.2 / r1.1,
         * r4.2, r1.1, r3.4 dead
         */
        r1.inv();
        r1.mul(r4);

        /* x = r0.1
         * y = r1.2
         */
        set(r0, r1);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public default S encodeHash(final int s) {
        final S x = getX();
        final S y = getY();

        /* r0 = 2 / s^2 */
        final S r0 = x.clone();

        r0.set(s);
        r0.square();
        r0.inv();
        r0.mul(2);

        /* r1 = r0 + 1 / r0*/
        final S r1 = r0.clone();

        r1.inv();
        r1.add(r0);

        /* r2 = 2 * (y + 1) */
        final S r2 = y.clone();

        r2.add(1);
        r2.mul(2);

        /* r3 = (y - 1) / r2,
         * r2 dead
         */
        final S r3 = y.clone();

        r3.sub(1);
        r3.div(r2);

        /* r2.1 = r3 * r1 + 1,
         * r3 dead
         */
        r2.set(r3);
        r2.mul(r1);
        r2.add(1);

        /* r3.1 = sqrt(r2.1^2 - 1) */
        r3.set(r2);
        r3.square();
        r3.sub(1);
        r3.sqrt();

        /* r3.2 = r3.1 - r2.1,
         * r1, r2.1, r3.1 dead
         */
        r3.sub(r2);

        /* r1.1 = 1 / r0^2 */
        r1.set(r0);
        r1.square();
        r1.inv();

        /* r2.2 = r3.2^2 + r1.1),
         * r1.1 dead
         */
        r2.set(r3);
        r2.square();
        r2.add(r1);

        /* r1.2 = r3.2 + 1 */
        r1.set(r3);
        r1.add(1);

        /* r0.1 = ((r0 - 1) * s * r3.2 * r1.2 * x * r2.2.legendre,
         * r0, r1.2, r2.2 dead
         */
        r0.sub(1);
        r0.mul(s);
        r0.mul(r3);
        r0.mul(r1);
        r0.mul(x);
        r0.mul(r2.legendre());

        /* r0.2 = r0.1 * r3.2,
         * r0.1, r3.2 dead
         */
        r0.mul(r3);

        /* r1.3 = 1 - r0.2 */
        r1.set(1);
        r1.sub(r0);

        /* r0.3 = r1.3 / (r0.2 + 1),
         * r0.2 dead
         */
        r0.add(1);
        r0.inv();
        r0.mul(r1);

        return r0;
    }
}
