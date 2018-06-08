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

import net.metricspace.crypto.math.ec.MontgomeryLadder;
import net.metricspace.crypto.math.ec.curve.TwistedEdwardsCurve;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * Projective twisted Edwards curve points, as described by Bernstein,
 * Birkner, Lange, and Peters in their paper, <a
 * href="https://eprint.iacr.org/2008/013.pdf">"Twisted Edwards
 * Curves"</a>.  Curve points are represented as a triple, {@code (X,
 * Y, Z)}, where {@code X = x/Z}, {@code Y = y/Z}, where {@code x} and
 * {@code y} are the original curve coordinates.
 *
 * @param <S> Scalar values.
 * @param <P> Point type used as an argument.
 */
public abstract class
    ProjectiveTwistedEdwardsPoint<
        S extends PrimeField<S>,
        P extends ProjectiveTwistedEdwardsPoint<S, P, T>,
        T extends ProjectiveTwistedEdwardsPoint.Scratchpad<S>
    >
    extends ProjectivePoint<S, P, T>
    implements MontgomeryLadder<S, P, T>,
               TwistedEdwardsPoint<S, P, T> {

    /**
     * Superclass of scratchpads for projective twisted Edwards points.
     */
    public static abstract class Scratchpad<S extends PrimeField<S>>
        implements ECPoint.Scratchpad {
        protected final S r0;
        protected final S r1;
        protected final S r2;
        protected final S r3;
        protected final S r4;
        protected final S r5;

        /**
         * Initialize a {@code Scratchpad}.
         */
        protected Scratchpad(final S r0,
                             final S r1,
                             final S r2,
                             final S r3,
                             final S r4,
                             final S r5) {
            this.r0 = r0;
            this.r1 = r1;
            this.r2 = r2;
            this.r3 = r3;
            this.r4 = r4;
            this.r5 = r5;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void destroy() {
            r0.destroy();
            r1.destroy();
            r2.destroy();
            r3.destroy();
            r4.destroy();
            r5.destroy();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean isDestroyed() {
            return r0.isDestroyed() && r1.isDestroyed() && r2.isDestroyed() &&
                   r3.isDestroyed() && r4.isDestroyed() && r5.isDestroyed();
        }
    }

    /**
     * Initialize an {@code ProjectiveEdwardsPoint} with three scalar
     * objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     */
    protected ProjectiveTwistedEdwardsPoint(final S x,
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
         * https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-add-2008-bbjlp
         *
         * A = Z1 * Z2
         * B = A^2
         * C = X1 * X2
         * D = Y1 * Y2
         * E = d * C * D
         * F = B - E
         * G = B + E
         * X3 = A * F * ((X1 + Y1) * (X2 + Y2) - C - D)
         * Y3 = A * G * (D - a * C)
         * Z3 = F * G
         *
         * Rewritten slightly as:
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
         * Y3 = A * G * (D - a * C)
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
         * Final formula:
         *
         * r0 = Z1 * Z2
         * r1 = r0^2
         * r2 = X1 * X2
         * r3 = Y1 * Y2
         * r4 = d * r2 * r3
         * r5 = r1 - r4
         * r1.1 = r1 + r4
         * r4.1 = X2 + Y2
         * X3 = r0 * r5 * ((X1 + Y1) * r4.1 - r2 - r3)
         * Y3 = r0 * r1.1 * (r3 - a * r2)
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
        r4.set(r2);
        r4.mul(edwardsD());
        r4.mul(r3);

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

        /* X3 = ((X1 + Y1) * r4.1 - r2 - r3) * r0 * r5,
         * r4.1 dead
         */
        x.add(y);
        x.mul(r4);
        x.sub(r2);
        x.sub(r3);
        x.mul(r0);
        x.mul(r5);

        /* Y3 = (r3 - a * r2) * r0 * r1.1,
         * r0, r2, r3, r4.2 dead
         */
        y.set(r2);
        y.mul(-edwardsA());
        y.add(r3);
        y.mul(r0);
        y.mul(r1);

        /* Z3 = r5 * r1.1,
         * r1.1 dead
         */
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
         * https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-madd-2008-bbjlp
         *
         * B = Z1^2
         * C = X1 * X2
         * D = Y1 * Y2
         * E = d * C * D
         * F = B - E
         * G = B + E
         * X3 = Z1 * F * ((X1 + Y1) * (X2 + Y2) - C - D)
         * Y3 = Z1 * G * (D - a * C)
         * Z3 = F * G
         *
         * Rewritten slightly as:
         *
         * B = Z1^2
         * C = X1 * X2
         * D = Y1 * Y2
         * E = d * C * D
         * F = B - E
         * G = B + E
         * T = X2 + Y2
         * X3 = Z1 * F * ((X1 + Y1) * T - C - D)
         * Y3 = Z1 * G * (D - a * C)
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
         * Final formula:
         *
         * r0 = Z1^2
         * r1 = X1 * X2
         * r2 = Y1 * Y2
         * r3 = d * r1 * r2
         * r4 = r0 - r3
         * r0.1 = r0 + r3
         * r3.1 = X2 + Y2
         * X3 = Z1 * r4 * ((X1 + Y1) * r3.1 - r1 - r2)
         * Y3 = Z1 * r0.1 * (r2 - a * r1)
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
        r3.mul(edwardsD());
        r3.mul(r2);

        /* r4 = r0 - r3 */
        r4.set(r0);
        r4.sub(r3);

        /* r0.1 = r0 + r3,
         * r0, r3 dead
         */
        r0.add(r3);

        /* r3.1 = X2 + Y2 */
        r3.set(point.x);
        r3.add(point.y);

        /* X3 = ((X1 + Y1) * r3.1 - r1 - r2) * Z1 * r4,
         * r3.1 dead
         */
        x.add(y);
        x.mul(r3);
        x.sub(r1);
        x.sub(r2);
        x.mul(z);
        x.mul(r4);

        /* Y3 = (r2 - r1 * a) * Z1 * r0.1,
         * r1, r2, r3.2 dead
         */
        y.set(r1);
        y.mul(-edwardsA());
        y.add(r2);
        y.mul(z);
        y.mul(r0);

        /* Z3 = r4 * r0.1,
         * r4 dead
         */
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
         * https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-mmadd-2008-bbjlp
         *
         * C = X1 * X2
         * D = Y1 * Y2
         * E = d * C * D
         * X3 = (1 - E) * ((X1 + Y1) * (X2 + Y2) - C - D)
         * Y3 = (1 + E) * (D - a * C)
         * Z3 = 1 - E^2
         *
         * Rewritten slightly as:
         *
         * C = X1 * X2
         * D = Y1 * Y2
         * E = d * C * D
         * T1 = X2 + Y2
         * T2 = 1 - E
         * X3 = T2 * ((X1 + Y1) * T1 - C - D)
         * T3 = 1 + E
         * Y3 = T3 * (D - a * C)
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
         *
         * Final formula:
         *
         * r0 = X1 * X2
         * r1 = Y1 * Y2
         * r2 = d * r0 * r1
         * r3 = X2 + Y2
         * r4 = 1 - r2
         * X3 = r4 * ((X1 + Y1) * r3 - r0 - r1)
         * r3.1 = 1 + r2
         * Y3 = r3.1 * (r1 - a * r0)
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
        r2.mul(edwardsD());
        r2.mul(r1);

        /* r3 = X2 + Y2 */
        r3.set(point.x);
        r3.add(point.y);

        /* r4 = 1 - r2 */
        r4.set(1);
        r4.sub(r2);

        /* X3 = ((X1 + Y1) * r3 - r0 - r1) * r4,
         * r3, r4 dead
         */
        x.add(y);
        x.mul(r3);
        x.sub(r0);
        x.sub(r1);
        x.mul(r4);

        /* r3.1 = 1 + r2 */
        r3.set(r2);
        r3.add(1);

        /* Y3 = (r1 - r0 * a) * r3.1,
         * r0, r1, r3.1 dead
         */
        y.set(r0);
        y.mul(-edwardsA());
        y.add(r1);
        y.mul(r3);

        /* r2.1 = r2^2 */
        r2.square();

        /* Z3 = 1 - r2.1,
         * r2.1 dead
         */
        z.set(1);
        z.sub(r2);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void dbl(final T scratch) {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#doubling-dbl-2008-bbjlp
         *
         * B = (X1 + Y1)^2
         * C = X1^2
         * D = Y1^2
         * E = a * C
         * F = E + D
         * H = Z1^2
         * J = F - 2 * H
         * X3 = (B - C - D) * J
         * Y3 = F * (E - D)
         * Z3 = F * J
         *
         * Manual register allocation produces the following substitutions:
         *
         * r0 = B
         * r1 = C
         * r2 = D
         * r3 = E
         * r4 = F
         * r5 = H
         * r5.1 = J
         *
         * Final formula:
         *
         * r0 = (X1 + Y1)^2
         * r1 = X1^2
         * r2 = Y1^2
         * r3 = a * r1
         * r4 = r3 + r2
         * r5 = Z1^2
         * r5.1 = r4 - 2 * r5
         * X3 = (r0 - r1 - r2) * r5.1
         * Y3 = r4 * (r3 - r2)
         * Z3 = r4 * r5.1
         */

        final S r0 = scratch.r0;
        final S r1 = scratch.r1;
        final S r2 = scratch.r2;
        final S r3 = scratch.r3;
        final S r4 = scratch.r4;
        final S r5 = scratch.r5;

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

        /* r3 = a * r1 */
        r3.set(r1);
        r3.mul(edwardsA());

        /* r4 = r3 + r2 */
        r4.set(r3);
        r4.add(r2);

        /* r5 = Z1^2 */
        r5.set(z);
        r5.square();

        /* r5.1 = r4 - 2 * r5,
         * r5 dead
         */
        r5.mul(-2);
        r5.add(r4);

        /* X3 = (r0 - r1 - r2) * r5.1,
         * r0, r1 dead
         */
        x.set(r0);
        x.sub(r1);
        x.sub(r2);
        x.mul(r5);

        /* Y3 = (r3 - r2) * r4,
         * r2, r3 dead
         */
        y.set(r3);
        y.sub(r2);
        y.mul(r4);

        /* Z3 = r4 * r5.1,
         * r4 dead
         */
        z.set(r4);
        z.mul(r5);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void mdbl(final T scratch) {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#doubling-mdbl-2008-bbjlp
         *
         * B = (X1 + Y1)^2
         * C = X1^2
         * D = Y1^2
         * E = a * C
         * F = E + D
         * X3 = (B - C - D) * (F - 2)
         * Y3 = F * (E - D)
         * Z3 = F^2 - 2 * F
         *
         * Rewritten slightly as
         *
         * B = (X1 + Y1)^2
         * C = X1^2
         * D = Y1^2
         * E = a * C
         * F = E + D
         * T1 = B - C - D
         * X3 = T1 * (F - 2)
         * Y3 = F * (E - D)
         * T2 = 2 * F
         * Z3 = F^2 - T2
         *
         * Manual register allocation produces the following subsitutions:
         *
         * r0 = B
         * r1 = C
         * r2 = D
         * r3 = E
         * r4 = F
         * r0.1 = T1
         * r0.2 = T2
         *
         * Final formula:
         *
         * r0 = (X1 + Y1)^2
         * r1 = X1^2
         * r2 = Y1^2
         * r3 = a * r1
         * r4 = r3 + r2
         * r0.1 = r0 - r1 - r2
         * X3 = r0.1 * (r4 - 2)
         * Y3 = r4 * (r3 - r2)
         * r0.2 = 2 * r4
         * Z3 = r4^2 - r0.2
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

        /* r3 = a * r1 */
        r3.set(r1);
        r3.mul(edwardsA());

        /* r4 = r3 + r2 */
        r4.set(r3);
        r4.add(r2);

        /* r0.1 = r0 - r1 - r2,
         * r0, r1 dead
         */
        r0.sub(r1);
        r0.sub(r2);

        /* X3 = r0.1 * (r4 - 2),
         * r0.1 dead
         */
        x.set(r4);
        x.sub(2);
        x.mul(r0);

        /* Y3 = (r3 - r2) * r4,
         * r2, r3 dead
         */
        y.set(r3);
        y.sub(r2);
        y.mul(r4);

        /* r0.2 = r4 * 2 */
        r0.set(r4);
        r0.mul(2);

        /* Z3 = r4^2 - r0.2,
         * r4 dead
         */
        z.set(r4);
        z.square();
        z.sub(r0);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void tpl(final T scratch) {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#tripling-tpl-2015-c
         *
         * YY = Y1^2
         * aXX = a * X1^2
         * Ap = YY + aXX
         * B = 2 * (2 * Z1^2 - Ap)
         * xB = aXX * B
         * yB = YY * B
         * AA = Ap * (YY - aXX)
         * F = AA - yB
         * G = AA + xB
         * X3 = X1 * (yB + AA) * F
         * Y3 = Y1 * (xB - AA) * G
         * Z3 = Z1 * F * G
         *
         * Rewritten slightly as:
         *
         * YY = Y1^2
         * aXX = a * X1^2
         * Ap = YY + aXX
         * B = 2 * (2 * Z1^2 - Ap)
         * xB = aXX * B
         * yB = YY * B
         * AA = Ap * (YY - aXX)
         * F = AA - yB
         * G = AA + xB
         * T1 = yB + AA
         * X3 = X1 * T1 * F
         * T2 = xB - AA
         * Y3 = Y1 * T2 * G
         * Z3 = Z1 * F * G
         *
         * Manual register allocation produces the following substitutions:
         *
         * r0 = YY
         * r1 = aXX
         * r2 = Ap
         * r3 = B
         * r4 = xB
         * r3.1 = yB
         * r0.1 = AA
         * r1.1 = F
         * r2.1 = G
         * r3.2 = T1
         * r4.1 = T2
         *
         * Final formula:
         *
         * r0 = Y1^2
         * r1 = a * X1^2
         * r2 = r0 + r1
         * r3 = 2 * (2 * Z1^2 - r2)
         * r4 = r1 * r3
         * r3.1 = r0 * r3
         * r0.1 = r2 * (r0 - r1)
         * r1.1 = r0.1 - r3.1
         * r2.1 = r0.1 + r4
         * r3.2 = r3.1 + r0.1
         * X3 = X1 * r3.2 * r1.1
         * r4.1 = r4 - r0.1
         * Y3 = Y1 * r4.1 * r2.1
         * Z3 = Z1 * r1.1 * r2.1
         */

        final S r0 = scratch.r0;
        final S r1 = scratch.r1;
        final S r2 = scratch.r2;
        final S r3 = scratch.r3;
        final S r4 = scratch.r4;

        /* r0 = Y1^2 */
        r0.set(y);
        r0.square();

        /* r1 = a * X1^2 */
        r1.set(x);
        r1.square();
        r1.mul(edwardsA());

        /* r2 = r0 + r1 */
        r2.set(r0);
        r2.add(r1);

        /* r3 = 2 * (2 * Z1^2 - r2) */
        r3.set(z);
        r3.square();
        r3.mul(2);
        r3.sub(r2);
        r3.mul(2);

        /* r4 = r1 * r3 */
        r4.set(r1);
        r4.mul(r3);

        /* r3.1 = r0 * r3 */
        r3.mul(r0);

        /* r0.1 = r2 * (r0 - r1) */
        r0.sub(r1);
        r0.mul(r2);

        /* r1.1 = r0.1 - r3.1 */
        r1.set(r0);
        r1.sub(r3);

        /* r2.1 = r0.1 + r4 */
        r2.set(r0);
        r2.add(r4);

        /* r3.2 = r3.1 + r0.1 */
        r3.add(r0);

        /* X3 = X1 * r3.2 * r1.1 */
        x.mul(r3);
        x.mul(r1);

        /* r4.1 = r4 - r0.1 */
        r4.sub(r0);

        /* Y3 = Y1 * r4.1 * r2.1 */
        y.mul(r4);
        y.mul(r2);

        /* Z3 = Z1 * r1.1 * r2.1 */
        z.mul(r1);
        z.mul(r2);
    }
}
