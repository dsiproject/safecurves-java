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
package net.metricspace.crypto.math.ec.ladder;

import javax.security.auth.Destroyable;

import net.metricspace.crypto.math.ec.curve.MontgomeryCurve;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.ec.point.MontgomeryPoint;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * Montgomery ladder implementation of scalar point multiplication.
 * The method was introduced by Montgomery in his paper <a
 * href="https://www.ams.org/journals/mcom/1987-48-177/S0025-5718-1987-0866113-7/S0025-5718-1987-0866113-7.pdf">"Speeding
 * the Pollard-Rho and Elliptic Curve Methods of Factorization"</a>.
 * This is combined with the {@code y}-coordinate recovery method
 * described by Oyeka and Sakurai in their paper <a
 * href="https://link.springer.com/content/pdf/10.1007%2F3-540-44709-1_12.pdf">"Efficient
 * Elliptic Curve Cryptosystems from a Scalar Multiplication Algorithm
 * with Recovery of the y -Coordinate on a Montgomery-Form Elliptic
 * Curve"</a> to obtain a complete implementation of two-coordinate
 * multiply. Both the one-coordinate and two-coordinate
 * multiplications are made available.
 *
 * @param <S> Scalar values.
 * @param <P> Point type used as an argument.
 * @param <T> Scratchpad type.
 */
public interface MontgomeryLadder<S extends PrimeField<S>,
                                  P extends MontgomeryLadder<S, P, T>,
                                  T extends MontgomeryLadder.Scratchpad<S>>
    extends MontgomeryPoint<S, P, T>,
            MontgomeryCurve<S> {
    /**
     * Superclass of scratchpads for Montgomery ladders.
     *
     * @param <S> Scalar values.
     */
    public static abstract class Scratchpad<S extends PrimeField<S>>
        extends ECPoint.Scratchpad<S> {
        public final S r3;
        public final S r4;

        /**
         * Initialize a {@code Scratchpad}.
         */
        protected Scratchpad(final S r0,
                             final S r1,
                             final S r2,
                             final S r3,
                             final S r4,
                             final int ndigits) {
            super(r0, r1, r2, ndigits);

            this.r3 = r3;
            this.r4 = r4;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void destroy() {
            super.destroy();

            r3.destroy();
            r4.destroy();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean isDestroyed() {
            return super.isDestroyed() && r3.isDestroyed() && r4.isDestroyed();
        }
    }

    /**
     * Single-coordinate Montgomery ladder step.  This computes the
     * {@code 2n}th and {@code 2n+1}th {@code x} and {@code z}
     * coordinates from the {@code n}th and {@code n+1}th.
     *
     * @param <S> The scalar type.
     * @param <T> The scratchpad type.
     * @param scratch The scratchpad object.
     * @param x1 The first {@code x} coordinate (not changed)
     * @param z1 The first {@code z} coordinate (not changed)
     * @param xn The {@code n}th {@code x} coordinate, replaced with
     *           the {@code 2n}th {@code x} coordinate.
     * @param zn The {@code n}th {@code z} coordinate, replaced with
     *           the {@code 2n}th {@code z} coordinate.
     * @param xnp1 The {@code n+1}th {@code x} coordinate, replaced with
     *             the {@code 2n+1}th {@code x} coordinate.
     * @param znp1 The {@code n+1}th {@code z} coordinate, replaced with
     *             the {@code 2n+1}th {@code z} coordinate.
     * @param curveparam The value {@code (a - 2) / 4}, where {@code a} is
     *                   from the Montgomery-form equation.
     */
    public static <S extends PrimeField<S>,
                   T extends MontgomeryLadder.Scratchpad<S>>
        void ladderStepX(final S x1,
                         final S z1,
                         final S xn,
                         final S zn,
                         final S xnp1,
                         final S znp1,
                         final S curveparam,
                         final T scratch) {
        /* Formula from https://cr.yp.to/papers/montladder-20170330.pdf
         *
         * X2n = (Xn - Zn)^2 * (Xn + Zn)^2
         * Z2n = ((Xn + Zn)^2 - (Xn - Zn)^2) *
         *       ((Xn + Zn)^2 + (a - 2 / 4) * ((Xn + Zn)^2 - (Xn - Zn)^2)))
         * X2np1 = ((Xn - Zn) * (Xn+1 + Zn+1) +
         *          (Xn + Zn) * (Xn+1 - Zn+1))^2 * Z1
         * Z2np1 = ((Xn - Zn) * (Xn+1 + Zn+1) -
         *          (Xn + Zn) * (Xn+1 - Zn+1))^2 * X1
         *
         * Manual common subexpression elimination produces the
         * following assigments:
         *
         * B = Xn - Zn
         * BB = B^2
         * C = Xn + Zn
         * CC = C^2
         * D = CC - BB
         * E = Xn+1 + Zn+1
         * F = Xn+1 - Zn+1
         * G = B * E
         * H = C * F
         * I = G + C * F
         * II = I^2
         * J = G - C * F
         * JJ = J^2
         *
         * Resulting formula, reordered to minimize liveness overlap:
         *
         * B = Xn - Zn
         * E = Xn+1 + Zn+1
         * G = B * E
         * C = Xn + Zn
         * F = Xn+1 - Zn+1
         * H = C * F
         * I = G + H
         * J = G - H
         * II = I^2
         * JJ = J^2
         * BB = B^2
         * CC = C^2
         * D = CC - BB
         * X2n = BB * CC
         * Z2n = D * (CC + (a - 2 / 4) * D))
         * X2np1 = II * Z1
         * Z2np1 = JJ * X1
         *
         * Manual register allocation produces the following assignments:
         *
         * B = r0
         * E = r1
         * G = r2
         * C = r1.1
         * F = r3
         * H = r3.1
         * I = r4
         * J = r2.1
         * II = r4.1
         * JJ = r2.2
         * BB = r0.1
         * CC = r1.2
         * D = r3.2
         *
         * Final formula:
         *
         * r0 = Xn - Zn
         * r1 = Xn+1 + Zn+1
         * r2 = r0 * r1
         * r1.1 = Xn + Zn
         * r3 = Xn+1 - Zn+1
         * r3.1 = r1.1 * r3
         * r4 = r2 + r3.1
         * r2.1 = r2 - r3.1
         * r4.1 = r4^2
         * r2.2 = r2.1^2
         * r0.1 = r0^2
         * r1.2 = r1.1^2
         * r3.2 = r1.2 - r0.1
         * X2n = r0.1 * r1.2
         * Z2n = r3.2 * (r1.2 + (a - 2 / 4) * r3.2))
         * X2np1 = r4.1 * Z1
         * Z2np1 = r2.2 * X1
         */

        final S r0 = scratch.r0;
        final S r1 = scratch.r1;
        final S r2 = scratch.r2;
        final S r3 = scratch.r3;
        final S r4 = scratch.r4;

        /* r0 = Xn - Zn */
        r0.set(xn);
        r0.sub(zn);

        /* r1 = Xn+1 + Zn+1 */
        r1.set(xnp1);
        r1.add(znp1);

        /* r2 = r0 * r1 */
        r2.set(r0);
        r2.mul(r1);

        /* r1.1 = Xn + Zn */
        r1.set(xn);
        r1.add(zn);

        /* r3 = Xn+1 - Zn+1 */
        r3.set(xnp1);
        r3.sub(znp1);

        /* r3.1 = r1.1 * r3 */
        r3.mul(r1);

        /* r4 = r2 + r3.1 */
        r4.set(r2);
        r4.add(r3);

        /* r2.1 = r2 - r3.1 */
        r2.sub(r3);

        /* r4.1 = r4^2 */
        r4.square();

        /* r2.2 = r2.1^2 */
        r2.square();

        /* r0.1 = r0^2 */
        r0.square();

        /* r1.2 = r1.1^2 */
        r1.square();

        /* r3.2 = r1.2 - r0.1 */
        r3.set(r1);
        r3.sub(r0);

        /* X2n = r0.1 * r1.2 */
        xn.set(r0);
        xn.mul(r1);

        /* Z2n = r3.2 * (r1.2 + (a - 2 / 4) * r3.2)) */
        zn.set(r3);
        zn.mul(curveparam);
        zn.add(r1);
        zn.mul(r3);

        /* X2np1 = r4.1 * Z1 */
        xnp1.set(r4);
        xnp1.mul(z1);

        /* Z2np1 = r2.2 * X1 */
        znp1.set(r2);
        znp1.mul(x1);
    }

    /**
     * Branch-free bit-controlled swap operation.  Exchanges {@code
     * xn} with {@code xnp1} and {@code zn} with {@code znp1} if the
     * bit is set, does nothing if it is cleared.  This is
     * accomplished using bitwise operations.
     *
     * @param <S> The scalar type.
     * @param <T> The scratchpad type.
     * @param bit The bit value as a {@code long}.
     * @param xn The {@code n}th {@code x} coordinate.
     * @param zn The {@code n}th {@code z} coordinate.
     * @param xnp1 The {@code n+1}th {@code x} coordinate.
     * @param znp1 The {@code n+1}th {@code z} coordinate.
     */
    public static <S extends PrimeField<S>,
                   T extends MontgomeryLadder.Scratchpad<S>>
        void cswap(final long bit,
                   final S xn,
                   final S zn,
                   final S xnp1,
                   final S znp1,
                   final T scratch) {
        final S r0 = scratch.r0;
        final S r1 = scratch.r1;
        final S r2 = scratch.r2;
        final S r3 = scratch.r3;
        final long negbit = bit ^ 0x1;

        r0.set(xnp1);
        r1.set(znp1);
        r2.set(xn);
        r3.set(zn);
        xn.mask(negbit);
        zn.mask(negbit);
        xnp1.mask(negbit);
        znp1.mask(negbit);
        r0.mask(bit);
        r1.mask(bit);
        r2.mask(bit);
        r3.mask(bit);
        xn.or(r0);
        zn.or(r1);
        xnp1.or(r2);
        znp1.or(r3);
    }

    /**
     * Branch-free bit-controlled swap operation.  Exchanges {@code
     * xn} with {@code xnp1} and {@code zn} with {@code znp1} if the
     * bits differ, nothing if they are equal.  This is accomplished
     * using bitwise operations.
     *
     * @param <S> The scalar type.
     * @param <T> The scratchpad type.
     * @param bitn The bit value as a {@code long}.
     * @param bitnp1 The bit value as a {@code long}.
     * @param xn The {@code n}th {@code x} coordinate.
     * @param zn The {@code n}th {@code z} coordinate.
     * @param xnp1 The {@code n+1}th {@code x} coordinate.
     * @param znp1 The {@code n+1}th {@code z} coordinate.
     */
    public static <S extends PrimeField<S>,
                   T extends MontgomeryLadder.Scratchpad<S>>
        void cswap(final long bitn,
                   final long bitnp1,
                   final S xn,
                   final S zn,
                   final S xnp1,
                   final S znp1,
                   final T scratch) {
        cswap(bitn ^ bitnp1, xn, zn, xnp1, znp1, scratch);
    }

    /**
     * Single-coordinate Montgomery ladder.  This computes the {@code
     * x} coordinate of scalar multiplication of a point.  This form
     * only takes the {@code x} coordinate (along with a
     * projective-style {@code z} coordinate, which can be {@code 1}.
     *
     * @param x The initial x-coordinate.
     * @param z The initial z-coordinate.
     * @param xn Initially {@code 1}, replaced with the {@code n}th
     *           {@code x} coordinate.
     * @param zn Initially {@code 0}, replaced with the {@code n}th
     *           {@code z} coordinate.
     * @param xnp1 Initially {@code x}, replaced with the {@code n +
     *             1}th {@code x} coordinate.
     * @param znp1 Initially {@code z}, replaced with the {@code n +
     *             1}th {@code z} coordinate.
     * @param scalar The scalar coefficient.
     * @param curveparam The value {@code (a - 2) / 4}, where {@code a} is
     *                   from the Montgomery-form equation.
     * @param scratch The scratchpad.
     */
    public static <S extends PrimeField<S>,
                   T extends MontgomeryLadder.Scratchpad<S>>
        void ladderX(final S x,
                     final S z,
                     final S xn,
                     final S zn,
                     final S xnp1,
                     final S znp1,
                     final S scalar,
                     final S curveparam,
                     final T scratch) {
        final int len = scalar.numBits();

        cswap(scalar.bit(len), xn, zn, xnp1, znp1, scratch);

        for(int i = len; i > 0; i--) {
            final long bitn = scalar.bit(i);
            final long bitnm1 = scalar.bit(i - 1);

            ladderStepX(x, z, xn, zn, xnp1, znp1, curveparam, scratch);
            cswap(bitn, bitnm1, xn, zn, xnp1, znp1, scratch);
        }

        ladderStepX(x, z, xn, zn, xnp1, znp1, curveparam, scratch);
        cswap(scalar.bit(0), xn, zn, xnp1, znp1, scratch);
    }

    /**
     * Single-coordinate Montgomery ladder.  This computes the {@code
     * x} coordinate of scalar multiplication of a point.  This form
     * only takes the {@code x} coordinate (along with a
     * projective-style {@code z} coordinate, which can be {@code 1}.
     *
     * @param x The initial {@code x}-coordinate, replaced with the
    *           {@code n}th {@code x} coordinate.
     * @param z The initial {@code z}-coordinate, replaced with the
    *           {@code n}th {@code z} coordinate.
     * @param scalar The scalar coefficient.
     * @param curveparam The value {@code (a - 2) / 4}, where {@code a} is
     *                   from the Montgomery-form equation.
     * @param scratch The scratchpad.
     */
    public static <S extends PrimeField<S>,
                   T extends MontgomeryLadder.Scratchpad<S>>
        void ladderX(final S x,
                     final S z,
                     final S scalar,
                     final S curveparam,
                     final T scratch) {
        try(final S xn = x.clone();
            final S zn = z.clone();
            final S xnp1 = x.clone();
            final S znp1 = z.clone()) {
            final int len = scalar.numBits();

            xn.set(1);
            zn.set(0);
            ladderX(x, z, xn, zn, xnp1, znp1, scalar, curveparam, scratch);
            x.set(xn);
            z.set(zn);
        }
    }

    /**
     * Recover the {@code y}-coordinate from a result of the {@code
     * x}-coordinate Montgomery ladder.  The formula for achieving
     * this was introduced by Oyeka and Sakurai in their paper <a
     * href="https://link.springer.com/content/pdf/10.1007%2F3-540-44709-1_12.pdf">"Efficient
     * Elliptic Curve Cryptosystems from a Scalar Multiplication
     * Algorithm with Recovery of the y -Coordinate on a
     * Montgomery-Form Elliptic Curve"</a>.
     *
     * @see #ladderX
     * @param <S> The scalar type.
     * @param <T> The scratchpad type.
     * @param point The original point.
     * @param xn The {@code x}-coordinate produced by {@link #ladderX}
     * multiplying ({@code point} by some {@code n}).
     * @param zn The {@code z}-coordinate produced by {@link #ladderX}
     * multiplying ({@code point} by some {@code n}).
     * @param xnp1 The {@code x}-coordinate of {@code (n * point) +
     * point = (n + 1) * point} (also produced by {@link #ladderX}).
     * @param znp1 The {@code z}-coordinate of {@code (n * point) +
     * point = (n + 1) * point} (also produced by {@link #ladderX}).
     * @param curvea The {@code A} parameter of the Montgomery curve.
     * @param curveb The {@code B} parameter of the Montgomery curve.
     * @param out The point to which to write the results (can be the
     *            same object as {@code point}.
     * @param scratch The scratchpad object.
     */
    public static <S extends PrimeField<S>,
                   P extends MontgomeryLadder<S, ?, T>,
                   T extends MontgomeryLadder.Scratchpad<S>>
        void recoverY(final P point,
                      final S xn,
                      final S zn,
                      final S xnp1,
                      final S znp1,
                      final S curvea,
                      final S curveb,
                      final P out,
                      final T scratch) {
        /* Formula from
         * https://link.springer.com/content/pdf/10.1007%2F3-540-44709-1_12.pdf
         *
         * T1 = x * Z1
         * T2 = X1 + T1
         * T3 = X1 - T1
         * T3 = T3^2
         * T3 = T3 * X2
         * T1 = 2 * A * Z1
         * T2 = T2 + T1
         * T4 = x * X1
         * T4 = T4 + Z1
         * T2 = T2 * T4
         * T1 = T1 * Z1
         * T2 = T2 - T1
         * T2 = T2 * Z2
         * Yrec = T2 - T3
         * T1 = 2 * B * y
         * T1 = T1 * Z1
         * T1 = T1 * Z2
         * Xrec = T1 * X1
         * Zrec = T1 * Z1
         *
         * Rewritten to our convertions:
         *
         * r0 = x * Zn
         * r1 = Xn + r0
         * r2 = Xn - r0
         * r2.1 = r2^2
         * r2.2 = r2.1 * Xnp1
         * r0.1 = 2 * A * Zn
         * r1.1 = r1 + r0.1
         * r3 = x * Xn
         * r3.1 = r3 + Zn
         * r1.2 = r1.1 * r3.1
         * r0.2 = r0.1 * Zn
         * r1.3 = r1.2 - r0.2
         * r1.4 = r1.3 * Znp1
         * Yrec = r1.4 - r2.2
         * r0.3 = 2 * B * y
         * r0.4 = r0.3 * Zn
         * r0.5 = r0.4 * Znp1
         * Xrec = r0.5 * Xn
         * Zrec = r0.5 * Zn
         *
         * Rewritten slightly as:
         *
         * r0 = x * Zn
         * r1 = Xn + r0
         * r2 = Xn - r0
         * r2.1 = r2^2
         * r2.2 = r2.1 * Xnp1
         * r0.1 = 2 * A * Zn
         * r1.1 = r1 + r0.1
         * r3 = x * Xn
         * r3.1 = r3 + Zn
         * r1.2 = r1.1 * r3.1
         * r0.2 = r0.1 * Zn
         * r1.3 = r1.2 - r0.2
         * r1.4 = r1.3 * Znp1
         * r1.5 = r1.4 - r2.2
         * r0.3 = 2 * B * y
         * r0.4 = r0.3 * Zn
         * r0.5 = r0.4 * Znp1
         * r2.3 = r0.5 * Xn
         * r3.2 = r0.5 * Zn
         * Xout = r2.3 / r3.2
         * Yout = r1.5 / r3.2
         */

        final S r0 = scratch.r0;
        final S r1 = scratch.r1;
        final S r2 = scratch.r2;
        final S r3 = scratch.r3;

        /* r0 = x * Zn */
        r0.set(point.montgomeryX());
        r0.mul(zn);

        /* r1 = Xn + r0 */
        r1.set(xn);
        r1.add(r0);

        /* r2 = Xn - r0 */
        r2.set(xn);
        r2.sub(r0);

        /* r2.1 = r2^2 */
        r2.square();

        /* r2.2 = r2.1 * Xnp1 */
        r2.mul(xnp1);

        /* r0.1 = 2 * A * Zn */
        r0.set(zn);
        r0.mul(2);
        r0.mul(curvea);

        /* r1.1 = r1 + r0 */
        r1.add(r0);

        /* r3 = x * Xn */
        r3.set(point.montgomeryX());
        r3.mul(xn);

        /* r3.1 = r3 + Zn */
        r3.add(zn);

        /* r1.2 = r1.1 * r3.1 */
        r1.mul(r3);

        /* r0.2 = r0.1 * Zn */
        r0.mul(zn);

        /* r1.3 = r1.2 - r0.2 */
        r1.sub(r0);

        /* r1.4 = r1.3 * Znp1 */
        r1.mul(znp1);

        /* r1.5 = r1.4 - r2.2 */
        r1.sub(r2);

        /* r0.3 = 2 * y */
        r0.set(point.montgomeryY());
        r0.mul(curveb);
        r0.mul(2);

        /* r0.4 = r0.3 * Zn */
        r0.mul(zn);

        /* r0.5 = r0.4 * Znp1 */
        r0.mul(znp1);

        /* r2.3 = r0.5 * Xn */
        r2.set(r0);
        r2.mul(xn);

        /* r3.2 = r0.5 * Zn */
        r3.set(r0);
        r3.mul(zn);

        /* Xout = r2.3 / r3.2 */
        r2.div(r3);

        /* Yout = r1.5 / r3.2 */
        r1.div(r3);

        /* Convert back to underlying coordinates */
        out.setMontgomery(r2, r1);

        /* Set to zero if Zout is zero */
        out.reset(r3.isZero());
    }

    /**
     * Obtain the (Montgomery) {@code x}-coordinate resulting from
     * multiplying this point by a scalar.
     *
     * @param scalar The scalar by which to multiply.
     * @param scratch The scratchpad.
     * @return The X coordinate from multiplying this point by {@code
     *         scalar}.
     */
    public default S mulX(final S scalar,
                          final T scratch) {
        final S x = montgomeryX();

        try(final S z = x.clone()) {
            final S curveparam = montgomeryA();

            curveparam.sub(2);
            curveparam.div(4);
            z.set(1);
            ladderX(x, z, scalar, curveparam, scratch);
            x.div(z);

            return x;
        }
    }

    /**
     * Obtain the (Montgomery) {@code x}-coordinate resulting from
     * multiplying this point by a scalar.
     *
     * @param scalar The scalar by which to multiply.
     * @return The X coordinate from multiplying this point by {@code
     *         scalar}.
     */
    public default S mulX(final S scalar) {
        try(final T scratch = scratchpad()) {
            return mulX(scalar, scratch);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public default void mul(final S scalar,
                            final T scratch) {
        try(final S x = montgomeryX();
            final S z = x.clone();
            final S xn = x.clone();
            final S zn = z.clone();
            final S xnp1 = x.clone();
            final S znp1 = z.clone()) {
            final int len = scalar.numBits();
            final S curvea = montgomeryA();
            final S curveb = montgomeryB();
            final S curveparam = montgomeryA();

            curveparam.sub(2);
            curveparam.div(4);
            z.set(1);
            xn.set(1);
            zn.set(0);
            znp1.set(1);
            ladderX(x, z, xn, zn, xnp1, znp1, scalar, curveparam, scratch);
            recoverY(this, xn, zn, xnp1, znp1, curvea, curveb, this, scratch);
        }
    }
}
