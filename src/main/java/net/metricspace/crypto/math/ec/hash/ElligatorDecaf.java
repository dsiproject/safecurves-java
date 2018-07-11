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
import net.metricspace.crypto.math.ec.point.DecafPoint;
import net.metricspace.crypto.math.ec.point.TwistedEdwardsPoint;
import net.metricspace.crypto.math.ec.ladder.MontgomeryLadder;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * Interface for the Elligator hash algorithm for Decaf points.  The
 * Elligator hash algorithms were introduced by Bernstein, Hamburg,
 * Krasnova, and Lange in their paper <a
 * href="https://elligator.cr.yp.to/elligator-20130828.pdf">"Elligator:
 * Elliptic-Curve Points Indistinguishable from Uniform Random
 * Strings"</a>.  It provides the ability to hash any scalar value to
 * a point on an elliptic curve.  The Elligator variant for Decaf
 * points was introduced by Hamburg in his paper <a
 * href="https://eprint.iacr.org/2015/673.pdf">"Decaf: Eliminating
 * Cofactors through Point Compression"</a>.
 * <p>
 * This is <i>not</i> a cryptogrophic hash function.  In fact,
 * Elligator provides a preimage function which produces scalar values
 * from elliptic curve points with a uniform distribution.
 *
 * @param <S> Scalar type.
 * @param <P> Point type.
 */
public interface ElligatorDecaf<S extends PrimeField<S>,
                                P extends ElligatorDecaf<S, P, T>,
                                T extends MontgomeryLadder.Scratchpad<S>>
    extends Elligator<S, P, T>,
            DecafPoint<S, P, T>,
            TwistedEdwardsPoint<S, P, T>,
            EdwardsCurve<S> {
    /**
     * {@inheritDoc}
     */
    @Override
    public default void decodeHash(final S r,
                                   final T scratch) {
        /* Formula from https://eprint.iacr.org/2015/673.pdf
         *
         * n = nonresidue
         * r = n * r0^2
         * D = ((d * r) + a - d) * ((d * r) - (a * r) - d)
         * N = (r + 1) * (a - (2 * d))
         * c, e = if N * D is square
         *           then (1, 1 / sqrt (N * D)
         *           else (-1, (n * r0) / sqrt (n * N * D)
         * s = c * abs (N * e)
         * (t is omitted because it isn't needed)
         *
         * Then abs (s) is a decaf-compressed point.
         *
         * Note that we can safely branch, because we are decoding a
         * hash; therefore, any attacker will know in advance whether
         * the branch is taken.
         *
         * Rewritten, renaming "r" to "q", "r0" to "r", dropping c,
         * setting a = 1:
         *
         * n = nonresidue
         * Q = n * R^2
         * D = ((d * Q) + 1 - d) * ((d * Q) - Q - d)
         * N = (Q + 1) * (1 - (2 * d))
         * E = if (N * D).legendre == 1
         *        then (N * D).invsqrt
         *        else (n * R) * (n * N * D).invsqrt
         * S = (N * E).abs
         * decompress S
         *
         * Manual common subexpression elimination produces the following:
         *
         * n = nonresidue
         * Q = n * R^2
         * E = d * Q
         * F = E - Q - d
         * D = (E + 1 - d) * F
         * N = (Q + 1) * (1 - (2 * d))
         * G = N * D
         * E = if G.legendre == 1
         *        then G.invsqrt
         *        else {
         *          H = (n * G).invsqrt
         *          (n * R) * H
         *        }
         * S = (N * E).abs
         * decompress S
         *
         * Manual register allocation produces the following assignments:
         *
         * r0 = Q
         * r1 = E
         * r2 = F
         * r1.1 = D
         * r2.1 = N
         * r1.2 = G
         * r1.3 = H
         * r0.1 = E
         * r0.2 = S
         *
         * Final formula:
         *
         * n = nonresidue
         * r0 = n * R^2
         * r1 = d * r0
         * r2 = r1 - r0 - d
         * r1.1 = (r1 + 1 - d) * r2
         * r2.1 = (r0 + 1) * (1 - (2 * d))
         * r1.2 = r2.1 * r1.1
         * r0.1 = if r1.2.legendre == 1
         *           then r1.2.invsqrt
         *           else {
         *             r1.3 = (n * r1.2).invsqrt
         *             (n * R) * r1.3
         *           }
         * r0.2 = (r2.1 * r0.1).abs
         * decompress r0.2
         */

        /* n = nonresidue */
        final int n = nonresidue();
        final int d = edwardsD();

        /* r0 = n * R^2 */
        final S r0 = r.clone();

        r0.square();
        r0.mul(n);

        /* r1 = d * r0 */
        final S r1 = r0.clone();

        r1.mul(d);

        /* r2 = r1 - r0 - d */
        final S r2 = r1.clone();

        r2.sub(r0);
        r2.sub(d);

        /* r1.1 = (r1 + 1 - d) * r2 */
        r1.add(1);
        r1.sub(d);
        r1.mul(r2);

        /* r2.1 = (r0 + 1) * (1 - (2 * d)) */
        r2.set(r0);
        r2.add(1);
        r2.mul(1 - (2 * d));

        /* r1.2 = r2.1 * r1.1 */
        r1.mul(r2);

        /* r0.1 = if r1.2.legendre == 1
         *           then r1.2.invsqrt
         *           else (n * R) * (n * r1.2).invsqrt
         */
        if (r1.legendre() == 1) {
            r0.set(r1);
            r0.invSqrt();
        } else {
            r1.mul(n);
            r1.invSqrt();
            r0.set(r);
            r0.mul(n);
            r0.mul(r1);
        }

        /* r0.2 = (r2.1 * r0.1).abs */
        r0.mul(r2);
        r0.abs();

        /* decompress r0.2 */
        decompress(r0.clone());

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public default S encodeHash(final T scratch) {
        /* Formula from https://eprint.iacr.org/2015/673.pdf
         * (This hashes Jacobi quartic points)
         *
         * n = nonresidue
         * c = s.signum
         * r = ((((2 * d) - a) * s^2) + (c * (t + 1))) /
         *     ((((2 * d) - a) * s^2) - (c * (t + 1)))
         * r0 = sqrt (r / n)
         * (r / n must be a square)
         *
         * Formula for Jacobi quartic points from the same source:
         *
         * s = (1 + (sqrt (1 - (a * x^2)))) / (a * x)
         * t = (2 * s * (sqrt (1 - (a * x^2)))) / (x * y)
         *
         * Combined, "r" renamed to "Q", "r0" renamed to "R", set a = 1:
         *
         * n = nonresidue
         * S = (1 + (sqrt (1 - x^2))) / x
         * T = (2 * S * (sqrt (1 - x^2))) / (x * y)
         * c = S.signum
         * Q = ((((2 * d) - 1) * S^2) + (c * (T + 1))) /
         *     ((((2 * d) - 1) * S^2) - (c * (T + 1)))
         * R = sqrt (Q / n)
         *
         * Manual common subexpression elimination produces the following:
         *
         * X = edwardsX
         * E = sqrt (1 - X^2)
         * S = (1 + E) / X
         * F = X * Y
         * T = (2 * S * E) / F
         * H = S.signum * (T + 1)
         * G = ((2 * d) - 1) * S^2
         * I = (G - H)
         * Q = (G + H) / I
         * R = sqrt (Q / nonresidue)
         *
         * Manual register allocation produces the following assignments:
         *
         * r0 = X
         * r1 = E
         * r2 = S
         * r0.1 = F
         * r1.1 = T
         * r1.2 = H
         * r2.1 = G
         * r0.2 = I
         * r2.2 = Q
         * r2.3 = R
         *
         * Final formula
         *
         * r0 = edwardsX
         * r1 = sqrt (1 - r0^2)
         * r2 = (1 + r1) / r0
         * r0.1 = r0 * Y
         * r1.1 = (2 * r2 * r1) / r0.1
         * r1.2 = c * (r1.1 + 1)
         * r2.1 = ((2 * d) - 1) * r2^2
         * r0.2 = (r2.1 - r1.2)
         * r2.2 = (r2.1 + r1.2) / r0.2
         * r2.3 = sqrt (r2.2 / nonresidue)
         * R = r2.3
         */

        /* r0 = edwardsX */
        final S r0 = edwardsX();

        /* r1 = sqrt (1 - r0^2) */
        final S r1 = r0.clone();

        r1.square();
        r1.neg();
        r1.add(1);
        r1.sqrt();

        /* r2 = (1 + r1) / r0 */
        final S r2 = r1.clone();

        r2.add(1);
        r2.div(r0);

        /* r0.1 = r0 * Y */
        r0.mul(edwardsY());

        /* r1.1 = (2 * r2 * r1) / r0.1 */
        r1.mul(r2);
        r1.mul(2);
        r1.div(r0);

        /* r1.2 = r2.signum * (r1.1 + 1) */
        r1.add(1);
        r1.mul(r2.signum());

        /* r2.1 = ((2 * d) - 1) * r2^2 */
        r2.square();
        r2.mul((2 * edwardsD()) - 1);

        /* r0.2 = (r2.1 - r1.2) */
        r0.set(r2);
        r0.sub(r1);

        /* r2.2 = (r2.1 + r1.2) / r0.2 */
        r2.add(r1);
        r2.div(r0);

        /* r2.3 = sqrt (r2.2 / n) */
        r2.div(nonresidue());
        r2.sqrt();

        return r2.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public default boolean canEncode(final T scratch) {
        /* Formula derived from encodeHash:
         *
         * n = nonresidue
         * X = edwardsX
         * E = sqrt (1 - X^2)
         * S = (1 + E) / X
         * F = X * Y
         * T = (2 * S * E) / F
         * H = S.signum * (T + 1)
         * G = ((2 * d) - 1) * S^2
         * I = (G - H)
         * Q = (G + H) / I
         * R = sqrt (Q / n)
         *
         * Q / n must be a square, therefore, use final formula for
         * encoding, with a modification:
         *
         * n = nonresidue
         * r0 = edwardsX
         * r1 = sqrt (1 - r0^2)
         * r2 = (1 + r1) / r0
         * r0.1 = r0 * Y
         * r1.1 = (2 * r2 * r1) / r0.1
         * r1.2 = c * (r1.1 + 1)
         * r2.1 = ((2 * d) - 1) * r2^2
         * r0.2 = (r2.1 - r1.2)
         * r2.2 = (r2.1 + r1.2) / r0.2
         * r2.3 = r2.2 / n
         *
         * r2.3.legendre == 1
         */

        /* r0 = edwardsX */
        final S r0 = edwardsX();

        /* r1 = sqrt (1 - r0^2) */
        final S r1 = r0.clone();

        r1.square();
        r1.neg();
        r1.add(1);
        r1.sqrt();

        /* r2 = (1 + r1) / r0 */
        final S r2 = r1.clone();

        r2.add(1);
        r2.div(r0);

        /* r0.1 = r0 * Y */
        r0.mul(edwardsY());

        /* r1.1 = (2 * r2 * r1) / r0.1 */
        r1.mul(r2);
        r1.mul(2);
        r1.div(r0);

        /* r1.2 = r2.signum * (r1.1 + 1) */
        r1.add(1);
        r1.mul(r2.signum());

        /* r2.1 = ((2 * d) - 1) * r2^2 */
        r2.square();
        r2.mul((2 * edwardsD()) - 1);

        /* r0.2 = (r2.1 - r1.2) */
        r0.set(r2);
        r0.sub(r1);

        /* r2.2 = (r2.1 + r1.2) / r0.2 */
        r2.add(r1);
        r2.div(r0);

        /* r2.3 = r2.2 / n */
        r2.div(nonresidue());

        return r2.legendre() == 1;
    }
}
