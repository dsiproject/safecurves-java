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
package net.metricspace.crypto.math.ec.point;

import javax.security.auth.Destroyable;

import net.metricspace.crypto.math.ec.curve.EdwardsCurve;
import net.metricspace.crypto.math.ec.ladder.MontgomeryLadder;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * Projective Edwards curve points, as described Bernstein and Lange's
 * paper <a
 * href="https://cr.yp.to/newelliptic/newelliptic-20070906.pdf">"Faster
 * Addition and Doubling on Elliptic Curves"</a>.  Curve points are
 * represented as a triple, {@code (X, Y, Z)}, where {@code X = x/Z},
 * {@code Y = y/Z}, where {@code x} and {@code y} are the original
 * curve coordinates.
 *
 * @param <S> Scalar values.
 * @param <P> Point type used as an argument.
 */
public abstract class
    ProjectiveEdwardsPoint<S extends PrimeField<S>,
                           P extends ProjectiveEdwardsPoint<S, P, T>,
                           T extends ProjectiveEdwardsPoint.Scratchpad<S>>
    extends ProjectivePoint<S, P, T>
    implements MontgomeryLadder<S, P, T>,
               EdwardsPoint<S, P, T>,
               EdwardsCurve<S> {

    /**
     * Superclass of scratchpads for projective Edwards points.
     */
    public static abstract class Scratchpad<S extends PrimeField<S>>
        extends MontgomeryLadder.Scratchpad<S> {
        protected final S r5;
        protected final S r6;

        /**
         * Initialize a {@code Scratchpad}.
         */
        protected Scratchpad(final S r0,
                             final S r1,
                             final S r2,
                             final S r3,
                             final S r4,
                             final S r5,
                             final S r6,
                             final int ndigits) {
            super(r0, r1, r2, r3, r4, ndigits);
            this.r5 = r5;
            this.r6 = r6;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void destroy() {
            super.destroy();
            r5.destroy();
            r6.destroy();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean isDestroyed() {
            return super.isDestroyed() && r5.isDestroyed() &&
                   r6.isDestroyed();
        }
    }

    /**
     * Initialize a {@code ProjectiveEdwardsPoint} with three scalar
     * objects.  This constructor takes possession of the parameters,
     * which are used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     */
    protected ProjectiveEdwardsPoint(final S x,
                                     final S y,
                                     final S z) {
        super(x, y, z);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void suadd(final P point,
                            final T scratch) {
        add(point, scratch);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void add(final P point,
                          final T scratch) {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#addition-add-2007-bl:
         *
         * A = Z1 * Z2
         * B = A^2
         * C = X1 * X2
         * D = Y1 * Y2
         * E = d * C * D
         * F = B - E
         * G = B + E
         * X3 = A * F * ((X1 + Y1) * (X2 + Y2) - C - D)
         * Y3 = A * G * (D - C)
         * Z3 = F * G
         *
         * Rewritten to
         *
         * A = Z1 * Z2
         * B = A^2
         * C = X1 * X2
         * D = Y1 * Y2
         * E = d * C * D
         * F = B - E
         * G = B + E
         * T = X2 + Y2
         * X3 = A * F * ((X1 + Y1) * T - C - D)
         * Y3 = A * G * (D - C)
         * Z3 = F * G
         *
         * Manual register allocation produces the following assignments:
         *
         * r0 = A
         * r1 = B
         * r2 = C
         * r3 = D
         * r4 = E
         * r5 = F
         * r1.1 = G
         * r4.1 = T
         *
         * Final formula is:
         *
         * r0 = Z1 * Z2
         * r1 = r0^2
         * r3 = X1 * X2
         * r3 = Y1 * Y2
         * r4 = d * r3 * r3
         * r5 = r1 - r4
         * r1.1 = r1 + r4
         * r4.1 = X2 + Y2
         * X3 = r0 * r5 * ((X1 + Y1) * r4.1 - r2 - r3)
         * Y3 = r0 * r1.1 * (r3 - r3)
         * Z3 = r5 * r1.1
         */

        final S r0 = scratch.r0;
        final S r1 = scratch.r1;
        final S r2 = scratch.r2;
        final S r3 = scratch.r3;
        final S r4 = scratch.r4;
        final S r5 = scratch.r5;

        /* r0 = Z1 * Z2 */
        r0.set(z);
        r0.mul(point.z);

        /* r1 = r0^2 */
        r1.set(r0);
        r1.square();

        /* r2 = X1 * X2 */
        r2.set(x);
        r2.mul(point.x);

        /* r3 = Y1 * Y2 */
        r3.set(y);
        r3.mul(point.y);

        /* r4 = d * r2 * r3 */
        r4.set(r3);
        r4.mul(r2);
        r4.mul(edwardsD());

        /* r5 = r1 - r4 */
        r5.set(r1);
        r5.sub(r4);

        /* r1.1 = r1 + r4,
         * r1, r4 dead
         */
        r1.add(r4);

        /* r4.1 = X2 + Y2 */
        r4.set(point.x);
        r4.add(point.y);

        /* X3 = ((X1 + Y1) * r4.1 - r2 - r3) * r5 * r0 */
        x.add(y);
        x.mul(r4);
        x.sub(r2);
        x.sub(r3);
        x.mul(r5);
        x.mul(r0);

        /* Y3 = (r3 - r2) * r0 * r1.1 */
        y.set(r3);
        y.sub(r2);
        y.mul(r0);
        y.mul(r1);

        /* Z3 = r5 * r1.1 */
        z.set(r5);
        z.mul(r1);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void madd(final P point,
                           final T scratch) {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#addition-madd-2007-bl-3:
         *
         * B = Z1^2
         * C = X1 * X2
         * D = Y1 * Y2
         * E = d * C * D
         * F = B - E
         * G = B + E
         * X3 = Z1 * F * ((X1 + Y1) * (X2 + Y2) - C - D)
         * Y3 = Z1 * G * (D - C)
         * Z3 = F * G
         *
         * Rewritten as:
         *
         * B = Z1^2
         * C = X1 * X2
         * D = Y1 * Y2
         * E = d * C * D
         * F = B - E
         * G = B + E
         * T = X2 + Y2
         * X3 = Z1 * F * ((X1 + Y1) * T - C - D)
         * Y3 = Z1 * G * (D - C)
         * Z3 = F * G
         *
         * Manual register allocation produces the following assignments:
         *
         * r0 = B
         * r1 = C
         * r2 = D
         * r3 = E
         * r4 = F
         * r0.1 = G
         * r3.1 = T
         *
         * Final formula is:
         *
         * r0 = Z1^2
         * r1 = X1 * X2
         * r2 = Y1 * Y2
         * r3 = d * r1 * r2
         * r4 = r0 - r3
         * r0.1 = r0 + r3
         * r3.1 = X2 + Y2
         * X3 = Z1 * r4 * ((X1 + Y1) * r3.1 - r1 - r2)
         * Y3 = Z1 * r0.1 * (r2 - r1)
         * Z3 = r4 * r0.1
         */

        final S r0 = scratch.r0;
        final S r1 = scratch.r1;
        final S r2 = scratch.r2;
        final S r3 = scratch.r3;
        final S r4 = scratch.r4;

        /* r0 = Z1^2 */
        r0.set(z);
        r0.square();

        /* r1 = X1 * X2 */
        r1.set(x);
        r1.mul(point.x);

        /* r2 = Y1 * Y2 */
        r2.set(y);
        r2.mul(point.y);

        /* r3 = d * r1 * r2 */
        r3.set(r1);
        r3.mul(r2);
        r3.mul(edwardsD());

        /* r4 = r0 - r3 */
        r4.set(r0);
        r4.sub(r3);

        /* r0.1 = r0 + r3 */
        r0.add(r3);

        /* r3.1 = X2 + Y2 */
        r3.set(point.x);
        r3.add(point.y);

        /* X3 = Z1 * r4 * ((X1 + Y1) * r3.1 - r1 - r2) */
        x.add(y);
        x.mul(r3);
        x.sub(r1);
        x.sub(r2);
        x.mul(r4);
        x.mul(z);

        /* Y3 = Z1 * r0.1 * (r2 - r1) */
        y.set(r2);
        y.sub(r1);
        y.mul(r0);
        y.mul(z);

        /* Z3 = r4 * r0.1 */
        z.set(r4);
        z.mul(r0);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void mmadd(final P point,
                            final T scratch) {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#addition-mmadd-2007-bl
         *
         * C = X1 * X2
         * D = Y1 * Y2
         * E = d * C * D
         * X3 = (1 - E) * ((X1 + Y1) * (X2 + Y2) - C - D)
         * Y3 = (1 + E) * (D - C)
         * Z3 = 1 - E^2
         *
         * Rewritten as:
         *
         * C = X1 * X2
         * D = Y1 * Y2
         * E = d * C * D
         * T1 = 1 - E
         * T2 = X2 + Y2
         * X3 = T1 * ((X1 + Y1) * T2 - C - D)
         * T3 = 1 + E
         * Y3 = T3 * (D - C)
         * T4 = E^2
         * Z3 = 1 - T4
         *
         * Manual register allocation produces the following assignments:
         *
         * r0 = C
         * r1 = D
         * r2 = E
         * r3 = T1
         * r4 = T2
         * r3.1 = T3
         * r2.1 = T4
         *
         * Final formula is:
         *
         * r0 = X1 * X2
         * r1 = Y1 * Y2
         * r2 = d * r0 * r1
         * r3 = 1 - r2
         * r4 = X2 + Y2
         * X3 = r3 * ((X1 + Y1) * r4 - r0 - r1)
         * r3.1 = 1 + r2
         * Y3 = r3.1 * (r1 - r0)
         * r2.1 = r2^2
         * Z3 = 1 - r2.1
         */

        final S r0 = scratch.r0;
        final S r1 = scratch.r1;
        final S r2 = scratch.r2;
        final S r3 = scratch.r3;
        final S r4 = scratch.r4;

        /* r0 = X1 * X2 */
        r0.set(x);
        r0.mul(point.x);

        /* r1 = Y1 * Y2 */
        r1.set(y);
        r1.mul(point.y);

        /* r2 = d * r0 * r1 */
        r2.set(r0);
        r2.mul(r1);
        r2.mul(edwardsD());

        /* r3 = 1 - r2 */
        r3.set(1);
        r3.sub(r2);

        /* r4 = X2 + Y2 */
        r4.set(point.x);
        r4.add(point.y);

        /* X3 = r3 * ((X1 + Y1) * r4 - r0 - r1) */
        x.add(y);
        x.mul(r4);
        x.sub(r0);
        x.sub(r1);
        x.mul(r3);

        /* r3.1 = 1 + r2 */
        r3.set(r2);
        r3.add(1);

        /* Y3 = r3.1 * (r1 - r0) */
        y.set(r1);
        y.sub(r0);
        y.mul(r3);

        /* r2.1 = r2^2 */
        r2.square();

        /* Z3 = 1 - r2.1 */
        z.set(1);
        z.sub(r2);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void dbl(final T scratch) {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#doubling-dbl-2007-bl
         *
         * B = (X1 + Y1)^2
         * C = X1^2
         * D = Y1^2
         * E = C + D
         * H = Z1^2
         * J = E - 2 * H
         * X3 = (B - E) * J
         * Y3 = E * (C - D)
         * Z3 = E * J
         *
         * Rewritten slightly as:
         *
         * B = (X1 + Y1)^2
         * C = X1^2
         * D = Y1^2
         * E = C + D
         * Y3 = E * (C - D)
         * H = 2 * Z1^2
         * J = E - H
         * X3 = (B - E) * J
         * Z3 = E * J
         *
         * Manual register allocation produces the following assignments:
         *
         * r0 = B
         * r1 = C
         * r2 = D
         * r3 = E
         * r2.1 = H
         * r1.1 = J
         *
         * Final formula:
         *
         * r0 = (X1 + Y1)^2
         * r1 = X1^2
         * r2 = Y1^2
         * r3 = r1 + r2
         * Y3 = r3 * (r1 - r2)
         * r2.1 = 2 * Z1^2
         * r1.1 = r3 - r2.1
         * X3 = (r0 - r3) * r1.1
         * Z3 = r3 * r1.1
         */

        final S r0 = scratch.r0;
        final S r1 = scratch.r1;
        final S r2 = scratch.r2;
        final S r3 = scratch.r3;

        /* r0 = (X1 + Y1)^2 */
        r0.set(x);
        r0.add(y);
        r0.square();

        /* r1 = X1^2 */
        r1.set(x);
        r1.square();

        /* r2 = Y1^2 */
        r2.set(y);
        r2.square();

        /* r3 = r1 + r2 */
        r3.set(r1);
        r3.add(r2);

        /* Y3 = (r1 - r2) * r3,
         * r1, r2 dead
         */
        y.set(r1);
        y.sub(r2);
        y.mul(r3);

        /* r2.1 = 2 * Z1^2 */
        r2.set(z);
        r2.square();
        r2.mul(2);

        /* r1.1 = r3 - r2.1,
         * r2.1 dead
         */
        r1.set(r3);
        r1.sub(r2);

        /* X3 = (r0 - r3) * r1.1,
         * r0 dead
         */
        x.set(r0);
        x.sub(r3);
        x.mul(r1);

        /* Z3 = r3 * r1.1,
         * r3, r1.1 dead
         */
        z.set(r3);
        z.mul(r1);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void mdbl(final T scratch) {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#doubling-mdbl-2007-bl
         *
         * B = (X1 + Y1)^2
         * C = X1^2
         * D = Y1^2
         * E = C + D
         * J = E - 2
         * X3 = (B - E) * J
         * Y3 = E * (C - D)
         * Z3 = E * J
         *
         * Manual register alloctaion produces the following assignments:
         *
         * r0 = B
         * r1 = C
         * r2 = D
         * r3 = E
         * r4 = J
         *
         * Final formula:
         *
         * r0 = (X1 + Y1)^2
         * r1 = X1^2
         * r2 = Y1^2
         * r3 = r1 + r2
         * r4 = r3 - 2
         * X3 = (r0 - r3) * r4
         * Y3 = r3 * (r1 - r2)
         * Z3 = r3 * r4
         */

        final S r0 = scratch.r0;
        final S r1 = scratch.r1;
        final S r2 = scratch.r2;
        final S r3 = scratch.r3;
        final S r4 = scratch.r4;

        /* r0 = (X1 + Y1)^2 */
        r0.set(x);
        r0.add(y);
        r0.square();

        /* r1 = X1^2 */
        r1.set(x);
        r1.square();

        /* r2 = Y1^2 */
        r2.set(y);
        r2.square();

        /* r3 = r1 + r2 */
        r3.set(r1);
        r3.add(r2);

        /* r4 = r3 - 2 */
        r4.set(r3);
        r4.sub(2);

        /* X = (r0 - r3) * r4
         * r0 dead
         */
        x.set(r0);
        x.sub(r3);
        x.mul(r4);

        /* Y = (r1 - r2) * r3
         * r1 r2, dead
         */
        y.set(r1);
        y.sub(r2);
        y.mul(r3);

        /* Z = r3 * r4
         * r3, r4 dead
         */
        z.set(r3);
        z.mul(r4);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void tpl(final T scratch) {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#tripling-tpl-2007-bblp:
         *
         * XX = X1^2
         * YY = Y1^2
         * ZZ = Z1^2
         * ZZ4 = 4*ZZ
         * D = XX + YY
         * DD = D2
         * H = 2 * D *(XX - YY)
         * P = DD - YY * ZZ4
         * Q = DD - XX * ZZ4
         * T = H + Q
         * TT = T^2
         * U = H - P
         * X3 = 2 * P * U * X1
         * Y3 = Q * ((T + Y1)^2 - TT - YY)
         * Z3 = U * ((T + Z1)^2 - TT - ZZ)
         *
         * Rewritten slightly as:
         *
         * XX = X1^2
         * YY = Y1^2
         * ZZ = Z1^2
         * D = XX + YY
         * H = 2 * D *(XX - YY)
         * DD = D^2
         * ZZ4 = -4 * ZZ
         * P = DD + YY * ZZ4
         * Q = DD + XX * ZZ4
         * T = H + Q
         * TT = T^2
         * U = H - P
         * X3 = 2 * P * U * X1
         * Y3 = Q * ((T + Y1)^2 - TT - YY)
         * Z3 = U * ((T + Z1)^2 - TT - ZZ)
         *
         * (P and Q can exploit commutativity of addition to eliminate
         * a temporary)
         *
         * Manual register allocation produces the following assignments:
         *
         * r0 = XX
         * r1 = YY
         * r2 = ZZ
         * r3 = D
         * r4 = H
         * r3.1 = DD
         * r5 = ZZ4
         * r6 = P
         * r5.1 = Q
         * r0.1 = T
         * r3.2 = TT
         * r4.1 = U
         *
         * Final formula is:
         *
         * r0 = X1^2
         * r1 = Y1^2
         * r2 = Z1^2
         * r3 = r0 + r1
         * r4 = 2 * r3 *(r0 - r1)
         * r3.1 = r3^2
         * r5 = -4 * r2
         * r6 = r3.1 + r1 * r5
         * r5.1 = r3.1 + r0 * r5
         * r0.1 = r4 + r5.1
         * r3.2 = r0.1^2
         * r4.1 = r4 - r6
         * X3 = 2 * r6 * r4.1 * X1
         * Y3 = r5.1 * ((r0.1 + Y1)^2 - r3.2 - r1)
         * Z3 = r4.1 * ((r0.1 + Z1)^2 - r3.2 - r2)
         */

        final S r0 = scratch.r0;
        final S r1 = scratch.r1;
        final S r2 = scratch.r2;
        final S r3 = scratch.r3;
        final S r4 = scratch.r4;
        final S r5 = scratch.r5;
        final S r6 = scratch.r6;

        /* r0 = X1^2 */
        r0.set(x);
        r0.square();

        /* r1 = Y1^2 */
        r1.set(y);
        r1.square();

        /* r2 = Z1^2 */
        r2.set(z);
        r2.square();

        /* r3 = r0 + r1 */
        r3.set(r0);
        r3.add(r1);

        /* r4 = 2 * r3 * (r0 - r1) */
        r4.set(r0);
        r4.sub(r1);
        r4.mul(r3);
        r4.mul(2);

        /* r3.1 = r3^2,
         * r3 dead
         */
        r3.square();

        /* r5 = -4 * r2 */
        r5.set(r2);
        r5.mul(-4);

        /* r6 = r3.1 + r1 * r5 */
        r6.set(r5);
        r6.mul(r1);
        r6.add(r3);

        /* r5.1 = r3.1 + r0 * r5,
         * r0, r3.1, r5 dead
         */
        r5.mul(r0);
        r5.add(r3);

        /* r0.1 = r4 + r5.1 */
        r0.set(r4);
        r0.add(r5);

        /* r3.2 = r0.1^2 */
        r3.set(r0);
        r3.square();

        /* r4.1 = r4 - r6,
         * r4 dead
         */
        r4.sub(r6);

        /* X3 = 2 * r6 * r4.1 * X1,
         * r6 dead
         */
        x.mul(r4);
        x.mul(r6);
        x.mul(2);

        /* Y3 = r5.1 * ((r0.1 + Y1)^2 - r3.2 - r1),
         * r5.1, r1 dead
         */
        y.add(r0);
        y.square();
        y.sub(r3);
        y.sub(r1);
        y.mul(r5);

        /* Z3 = r4.1 * ((r0.1 + Z1)^2 - r3.2 - r2),
         * r0.1, r4.1, r3.2, r2 dead
         */
        z.add(r0);
        z.square();
        z.sub(r3);
        z.sub(r2);
        z.mul(r4);
    }
}
