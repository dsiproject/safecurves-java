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
package net.metricspace.crypto.math.ec.hash;

import net.metricspace.crypto.math.ec.curve.EdwardsCurve;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.ec.point.EdwardsPoint;
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
                            P extends Elligator1<S, P, T>,
                            T extends ECPoint.Scratchpad>
    extends Elligator<S, P, T>,
            EdwardsPoint<S, P, T>,
            EdwardsCurve<S> {
    /**
     * Calculate the Elligator 1 {@code c} parameter from the Edwards
     * {@code d} parameter.
     *
     * @param d The Edwards {@code d} parameter.
     * @return The Elligator 1 {@code c} parameter.
     */
    public static <S extends PrimeField<S>>
        S calculateElligatorC(final S d) {
        final S out = d.clone();

        out.neg();
        out.sqrt();

        final S denom = out.clone();

        out.sub(1);
        denom.add(1);
        out.div(denom);

        return out;
    }

    /**
     * Calculate the Elligator 1 {@code s} parameter from the
     * Elligator {@code c} parameter.
     *
     * @param c The Elligator 1 {@code c} parameter.
     * @return The Elligator 1 {@code s} parameter.
     */
    public static <S extends PrimeField<S>>
        S calculateElligatorS(final S c) {
        final S out = c.clone();

        out.inv();
        out.mul(2);
        out.sqrt();

        return out;
    }

    /**
     * Calculate the Elligator 1 {@code r} parameter from the
     * Elligator {@code c} parameter.
     *
     * @param c The Elligator 1 {@code c} parameter.
     * @return The Elligator 1 {@code r} parameter.
     */
    public static <S extends PrimeField<S>>
        S calculateElligatorR(final S c) {
        final S out = c.clone();

        out.inv();
        out.add(c);

        return out;
    }

    /**
     * Get the Elligator {@code s} parameter.
     *
     * @return The Elligator {@code s} parameter.
     */
    public S elligatorS();

    /**
     * Get the Elligator {@code r} parameter.
     *
     * @return The Elligator {@code r} parameter.
     */
    public S elligatorR();

    /**
     * Get the Elligator {@code c} parameter.
     *
     * @return The Elligator {@code c} parameter.
     */
    public S elligatorC();

    /**
     * {@inheritDoc}
     */
    @Override
    public default void decodeHash(final S t) {
        /* Original formula from https://eprint.iacr.org/2013/325.pdf
         *
         * u = (1 - t) / (1 + t)
         * v = u^5 + (r^2 - 2) * u^3 + u
         * X = v.legendre * u
         * Y = (v.legendre * v)^((p+1)/4) * v.legendre *
         *     (u^2 + 1 / c^2).legendre
         * x = (c - 1) * s * X * (1 + X) / Y
         * y = (r * X - (1 + X)^2) / (r * X + (1 + X)^2)
         *
         * Rewritten slightly as
         *
         * u = (1 - t) / (1 + t)
         * r = elligatorR()
         * v = (u^4 + (r^2 - 2) * u^2 + 1) * u
         * c = elligatorC()
         * Y = (v.legendre * v).sqrt * v.legendre *
         *     (u^2 + 1 / c^2).legendre
         * X = v.legendre * u
         * x = (c - 1) * elligatorS() * X * (1 + X) / Y
         * y = (r * X - (1 + X)^2) / (r * X + (1 + X)^2)
         *
         * Manual common subexpression elimination produces the following:
         *
         * F = 1 + t
         * U = (1 - t) / F
         * U2 = U^2
         * C = elligatorC()
         * H = U2 + (1 / C^2)
         * l2 = H.legendre
         * R = elligatorR
         * G = (R^2 - 2) * U2
         * U4 = U2^2
         * V = (U4 + G + 1) * U
         * l1 = V.legendre
         * Y = (l1 * V).sqrt * l1 * l2
         * X = l1 * U
         * I = 1 + X
         * x = (C - 1) * elligatorS() * X * I / Y
         * J = I^2
         * K = R * X
         * L = K + J
         * y = (K - J) / L
         *
         * Manual register allocation produces the following assignments:
         *
         * r0 = F
         * r1 = U
         * r0.1 = U2
         * r2 = C
         * r3 = H
         * r3.1 = R
         * r4 = G
         * r0.2 = U4
         * r0.3 = V
         * r4.1 = Y
         * r1.1 = X
         * r0.4 = I
         * r2.1 = x
         * r0.5 = J
         * r3.2 = K
         * r1.1 = L
         * r3.3 = y
         *
         * Final formula:
         *
         * r0 = 1 + t
         * r1 = (1 - t) / r0
         * r0.1 = r1^2
         * r2 = elligatorC()
         * r3 = r0.1 + (1 / r2^2)
         * l2 = r3.legendre
         * r3.1 = elligatorR
         * r4 = (r3.1^2 - 2) * r0.1
         * r0.2 = r0.1^2
         * r0.3 = (r0.2 + r4 + 1) * r1
         * l1 = r0.3.legendre
         * r4.1 = (l1 * r0.3).sqrt * l1 * l2
         * r1.1 = l1 * r1
         * r0.4 = 1 + r1.1
         * r2.1 = (r2 - 1) * elligatorS() * r1.1 * r0.4 / r4.1
         * r0.5 = r0.4^2
         * r3.2 = r3.1 * r1.1
         * r1.1 = r3.2 + r0.5
         * r3.3 = (r3.2 - r0.5) / r1.1
         * x = r2.1
         * y = r3.3
         */

        /* r0 = 1 + t */
        final S r0 = t.clone();

        r0.add(1);

        /* r1 = (1 - t) / r0 */
        final S r1 = t.clone();

        r1.neg();
        r1.add(1);
        r1.div(r0);

        /* r0.1 = r1^2 */
        r0.set(r1);
        r0.square();

        /* r2 = elligatorC() */
        final S r2 = elligatorC();

        /* r3 = r0.1 + (1 / r2^2) */
        final S r3 = r2.clone();

        r2.square();
        r2.neg();
        r2.add(r0);

        /* l2 = r3.legendre */
        final int l2 = r3.legendre();

        /* r3.1 = elligatorR */
        r3.set(elligatorR());

        /* r4 = (r3.1^2 - 2) * r0.1 */
        final S r4 = r3.clone();

        r3.square();
        r3.sub(2);
        r3.mul(r0);

        /* r0.2 = r0.1^2 */
        r0.square();

        /* r0.3 = (r0.2 + r4 + 1) * r1 */
        r0.add(r4);
        r0.add(1);
        r0.mul(r1);

        /* l1 = r0.3.legendre */
        final int l1 = r0.legendre();

        /* r4.1 = (l1 * r0.3).sqrt * l1 * l2 */
        r4.set(r0);
        r4.mul(l1);
        r4.sqrt();
        r4.mul(l1 * l2);

        /* r1.1 = l1 * r1 */
        r1.mul(l1);

        /* r0.4 = 1 + r1.1 */
        r0.set(r1);
        r0.add(1);

        /* r2.1 = (r2 - 1) * elligatorS() * r1.1 * r0.4 / r4.1 */
        r2.sub(1);
        r2.mul(elligatorS());
        r2.mul(r1);
        r2.mul(r0);
        r2.div(r4);

        /* r0.5 = r0.4^2 */
        r0.square();

        /* r3.2 = r3.1 * r1.1 */
        r3.mul(r1);

        /* r1.1 = r3.2 + r0.5 */
        r1.set(r3);
        r1.set(r0);

        /* r3.3 = (r3.2 - r0.5) / r1.1 */
        r3.sub(r0);
        r3.div(r1);

        /* x = r2.1 */
        /* y = r3.3 */
        setEdwards(r2, r3);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public default S encodeHash() {
        /* Formula from https://eprint.iacr.org/2013/325.pdf
         *
         * e = (y - 1) / (2 * (y + 1))
         * X = ((1 + e * r)^2 - 1)^((p+1)/4) - (1 + e * r)
         * z = ((c - 1) * s * X * (1 + X) * x * (X^2 + (1 / c^2)).legendre
         * u = z * X
         * t = (1 - u) / (1 + u)
         *
         * Rewritten slightly as:
         *
         * e = (y - 1) / (2 * (y + 1))
         * r = elligatorR()
         * X = ((1 + e * r)^2 - 1).sqrt - (1 + e * r)
         * c = elligatorC()
         * z = ((c - 1) * elligatorS() * X * (1 + X) * x *
         *     (X^2 + (1 / c^2))).legendre
         * u = z * X
         * t = (1 - u) / (1 + u)
         *
         * Manual common subexpression elimination produces the following:
         *
         * G = 2 * (y + 1)
         * E = (y - 1) / G
         * H = 1 + E * elligatorR()
         * X = (H^2 - 1).sqrt - H
         * C = elligatorC()
         * I = C - 1
         * J = 1 + X
         * K = X^2
         * Z = I * elligatorS * X * J * x * (K + (1 / C^2))
         * l1 = Z.legendre
         * u = l1 * X
         * L = 1 + u
         * t = (1 - u) / L
         *
         * Manual register allocation produces the following assignments:
         *
         * r0 = G
         * r1 = E
         * r0.1 = H
         * r1.1 = X
         * r0.2 = C
         * r2 = I
         * r3 = J
         * r4 = K
         * r0.3 = Z
         * r0.4 = u
         * r1.2 = L
         *
         * Final formula:
         *
         * r0 = 2 * (y + 1)
         * r1 = (y - 1) / r0
         * r0.1 = 1 + r1 * elligatorR()
         * r1.1 = (r0.1^2 - 1).sqrt - r0.1
         * r0.2 = elligatorC()
         * r2 = r0.2 - 1
         * r3 = 1 + r1.1
         * r4 = r1.1^2
         * r0.3 = r2 * elligatorS() * r1.1 * r3 * x * (r4 + (1 / r0.2^2))
         * l1 = r0.3.legendre
         * r0.4 = l1 * r1.1
         * r1.2 = 1 + r0.4
         * r0.5 = (1 - r0.4) / r1.2
         * t = r0.5
         */
        final S y = getY();

        /* r0 = 2 * (y + 1) */
        final S r0 = y.clone();

        r0.add(1);
        r0.mul(2);

        /* r1 = (y - 1) / r0 */
        final S r1 = y.clone();

        r1.sub(1);
        r1.div(r0);

        /* r0.1 = 1 + r1 * elligatorR() */
        r0.set(elligatorR());
        r0.add(r1);
        r0.add(1);

        /* r1.1 = (r0.1^2 - 1).sqrt - r0.1 */
        r1.set(r0);
        r1.square();
        r1.sub(1);
        r1.sqrt();
        r1.sub(r0);

        /* r0.2 = elligatorC() */
        r0.set(elligatorC());

        /* r2 = r0.2 - 1 */
        final S r2 = r0.clone();

        r2.sub(1);

        /* r3 = 1 + r1.1 */
        final S r3 = r1.clone();

        r3.add(1);

        /* r4 = r1.1^2 */
        final S r4 = r1.clone();

        r4.square();

        /* r0.3 = r2 * elligatorS() * r1.1 * r3 * x * (r4 + (1 / r0.2^2)) */
        r0.square();
        r0.inv();
        r0.add(r4);
        r0.mul(edwardsX());
        r0.mul(r3);
        r0.mul(r1);
        r0.mul(elligatorS());
        r0.mul(r2);

        /* l1 = r0.3.legendre */
        final int l1 = r0.legendre();

        /* r0.4 = l1 * r1.1 */
        r0.set(r1);
        r0.mul(l1);

        /* r1.2 = 1 + r0.4 */
        r1.set(r0);
        r1.add(1);

        /* r0.5 = (1 - r0.4) / r1.2 */
        r0.neg();
        r0.add(1);
        r0.div(r1);

        /* t = r0.5 */
        return r0;
    }
}
