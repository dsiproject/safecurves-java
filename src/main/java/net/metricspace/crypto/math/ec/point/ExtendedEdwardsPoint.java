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

import net.metricspace.crypto.math.ec.MontgomeryLadder;
import net.metricspace.crypto.math.ec.curve.EdwardsCurve;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * Extended twisted Edwards curve points, as described in Hisil,
 * Koon-Ho, Carter, and Dawson in their paper, <a
 * href="https://eprint.iacr.org/2008/522.pdf">"Twisted Edwards Curves
 * Revisited"</a>.  Curve points are represented as a quad, {@code (X,
 * Y, Z, T)}, where {@code X = x/Z}, {@code Y = y/Z}, and {@code T = X
 * * Y}, where {@code x} and {@code y} are the original curve
 * coordinates.
 *
 * @param <S> Scalar values.
 * @param <P> Point type used as an argument.
 */
public abstract class
    ExtendedEdwardsPoint<S extends PrimeField<S>,
                         P extends ExtendedEdwardsPoint<S, P>>
    extends ExtendedPoint<S, P>
    implements MontgomeryLadder<S, P>,
               EdwardsCurve<S> {
    /**
     * Initialize an {@code ExtendedPoint} with three scalar objects.
     * This constructor takes possession of the parameters, which are
     * used as the coordinate objects.  This constructor does
     * <i>not</i> scale the parameters.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     * @param t The scalar object for t.
     */
    protected ExtendedEdwardsPoint(final S x,
                                   final S y,
                                   final S z,
                                   final S t) {
        super(x, y, z, t);
    }

    /**
     * Initialize an {@code ExtendedEdwardsPoint} with two scalar objects.
     * This constructor takes possession of the parameters, which are
     * used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     */
    protected ExtendedEdwardsPoint(final S x,
                                   final S y) {
        super(x, y);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void suadd(final P point) {
        add(point);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void add(final P point) {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
         *
         * A = X1 * X2
         * B = Y1 * Y2
         * C = T1 * d * T2
         * D = Z1 * Z2
         * E = (X1 + Y1) * (X2 + Y2) - A - B
         * F = D - C
         * G = D + C
         * H = B - a * A
         * X3 = E * F
         * Y3 = G * H
         * T3 = E * H
         * Z3 = F * G
         *
         * Rewritten slightly to:
         *
         * A = X1 * X2
         * B = Y1 * Y2
         * C = T1 * d * T2
         * D = Z1 * Z2
         * S = X2 + Y2
         * E = (X1 + Y1) * S - A - B
         * H = B - A
         * F = D - C
         * G = D + C
         * X3 = E * F
         * Y3 = G * H
         * T3 = E * H
         * Z3 = F * G
         *
         * Manual register allocation produces the following assignments:
         *
         * r0 = A
         * r1 = B
         * r2 = C
         * r3 = D
         * r4 = S
         * r5 = E
         * r1.1 = H
         * r0.1 = F
         * r3.1 = G
         *
         * Final formula:
         *
         * r0 = X1 * X2
         * r1 = Y1 * Y2
         * r2 = T1 * d * T2
         * r3 = Z1 * Z2
         * r4 = X2 + Y2
         * r5 = (X1 + Y1) * r4 - r0 - r1
         * r1.1 = r1 - r0
         * r0.1 = r3 - r2
         * r3.1 = r3 + r2
         * X3 = r5 * r0.1
         * Y3 = r3.1 * r1.1
         * T3 = r5 * r1.1
         * Z3 = r0.1 * r3.1
         */

        /* r0 = X1 * X2 */
        final S r0 = x.clone();

        r0.mul(point.x);

        /* r1 = Y1 * Y2 */
        final S r1 = y.clone();

        r1.mul(point.y);

        /* r2 = T1 * d * T2 */
        final S r2 = t.clone();

        r2.mul(edwardsD());
        r2.mul(point.t);

        /* r3 = Z1 * Z2 */
        final S r3 = z.clone();

        r3.mul(point.z);

        /* r4 = X2 + Y2 */
        final S r4 = point.x.clone();

        r4.add(point.y);

        /* r5 = (X1 + Y1) * r4 - r0 - r1 */
        final S r5 = x.clone();

        r5.add(y);
        r5.mul(r4);
        r5.sub(r0);
        r5.sub(r1);

        /* r1.1 = r1 - r0 */
        r1.sub(r0);

        /* r0.1 = r3 - r2 */
        r0.set(r3);
        r0.sub(r2);

        /* r3.1 = r3 + r2 */
        r3.add(r2);

        /* X3 = r5 * r0.1 */
        x.set(r5);
        x.mul(r0);

        /* Y3 = r3.1 * r1.1 */
        y.set(r3);
        y.mul(r1);

        /* T3 = r5 * r1.1 */
        t.set(r5);
        t.mul(r1);

        /* Z3 = r0.1 * r3.1 */
        z.set(r0);
        z.mul(r3);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void madd(final P point) {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-madd-2008-hwcd-2
         *
         * A = X1 * X2
         * B = Y1 * Y2
         * C = T1 * d * T2
         * D = Z1
         * E = (X1 + Y1) * (X2 + Y2) - A - B
         * F = D - C
         * G = D + C
         * H = B - a * A
         * X3 = E * F
         * Y3 = G * H
         * T3 = E * H
         * Z3 = F * G
         *
         * Rewritten slightly as:
         *
         * A = X1 * X2
         * B = Y1 * Y2
         * C = T1 * d * T2
         * S = X2 + Y2
         * E = (X1 + Y1) * S - A - B
         * H = B - A
         * F = Z1 - C
         * G = Z1 + C
         * X3 = E * F
         * Y3 = G * H
         * T3 = E * H
         * Z3 = F * G
         *
         * Manual register allocation produces the following assignments:
         *
         * r0 = A
         * r1 = B
         * r2 = C
         * r3 = S
         * r4 = E
         * r1.1 = H
         * r0.1 = F
         * r2.1 = G
         *
         * Final formula:
         *
         * r0 = X1 * X2
         * r1 = Y1 * Y2
         * r2 = T1 * d * T2
         * r3 = X2 + Y2
         * r4 = (X1 + Y1) * r3 - r0 - r1
         * r1.1 = r1 - r0
         * r0.1 = Z1 - r2
         * r2.1 = Z1 + r2
         * X3 = r4 * r0.1
         * Y3 = r2.1 * r1.1
         * T3 = r4 * r1.1
         * Z3 = r0.1 * r2.1
         */

        /* r0 = X1 * X2 */
        final S r0 = x.clone();

        r0.mul(point.x);

        /* r1 = Y1 * Y2 */
        final S r1 = y.clone();

        r1.mul(point.y);

        /* r2 = T1 * d * T2 */
        final S r2 = t.clone();

        r2.mul(edwardsD());
        r2.mul(point.t);

        /* r3 = X2 + Y2 */
        final S r3 = point.x.clone();

        r3.add(point.y);

        /* r4 = (X1 + Y1) * r3 - r0 - r1 */
        final S r4 = x.clone();

        r4.add(y);
        r4.mul(r3);
        r4.sub(r0);
        r4.sub(r1);

        /* r1.1 = r1 - r0 */
        r1.sub(r0);

        /* r0.1 = Z1 - r2 */
        r0.set(z);
        r0.sub(r2);

        /* r2.1 = Z1 + r2 */
        r2.add(z);

        /* X3 = r4 * r0.1 */
        x.set(r4);
        x.mul(r0);

        /* Y3 = r2.1 * r1.1 */
        y.set(r2);
        y.mul(r1);

        /* T3 = r4 * r1.1 */
        t.set(r4);
        t.mul(r1);

        /* Z3 = r0.1 * r2.1 */
        z.set(r0);
        z.mul(r2);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void mmadd(final P point) {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-mmadd-2008-hwcd-2
         *
         * A = X1 * X2
         * B = Y1 * Y2
         * C = T1* d * T2
         * E = (X1 + Y1) * (X2 + Y2) - A - B
         * F = 1 - C
         * G = 1 + C
         * H = B - A
         * X3 = E * F
         * Y3 = G * H
         * T3 = E * H
         * Z3 = 1 - C^2
         *
         * Rewritten slightly as:
         *
         * A = X1 * X2
         * B = Y1 * Y2
         * C = T1* d * T2
         * S = X2 + Y2
         * E = (X1 + Y1) * S - A - B
         * H = B - A
         * F = 1 - C
         * G = 1 + C
         * X3 = E * F
         * Y3 = G * H
         * T3 = E * H
         * Z3 = 1 - C^2
         *
         * Manual register allocation produces the following assignments:
         *
         * r0 = A
         * r1 = B
         * r2 = C
         * r3 = S
         * r4 = E
         * r1.1 = H
         * r0.1 = F
         * r3.1 = G
         * r2.1 = CC
         *
         * Final formula:
         *
         * r0 = X1 * X2
         * r1 = Y1 * Y2
         * r2 = T1* d * T2
         * r3 = X2 + Y2
         * r4 = (X1 + Y1) * r3 - r0 - r1
         * r1.1 = r1 - r0
         * r0.1 = 1 - r2
         * r3.1 = 1 + r2
         * X3 = r4 * r0.1
         * Y3 = r3.1 * r1.1
         * T3 = r4 * r1.1
         * r2.1 = r2^2
         * Z3 = 1 - r2.1
         */

        /* r0 = X1 * X2 */
        final S r0 = x.clone();

        r0.mul(point.x);

        /* r1 = Y1 * Y2 */
        final S r1 = y.clone();

        r1.mul(point.y);

        /* r2 = T1 * d * T2 */
        final S r2 = t.clone();

        r2.mul(edwardsD());
        r2.mul(point.t);

        /* r3 = X2 + Y2 */
        final S r3 = point.x.clone();

        r3.add(point.y);

        /* r4 = (X1 + Y1) * r3 - r0 - r1 */
        final S r4 = x.clone();

        r4.add(y);
        r4.mul(r3);
        r4.sub(r0);
        r4.sub(r1);

        /* r1.1 = r1 - r0 */
        r1.sub(r0);

        /* r0.1 = 1 - r2 */
        r0.set(1);
        r0.sub(r2);

        /* r3.1 = 1 + r2 */
        r3.set(1);
        r3.add(r2);

        /* X3 = r4 * r0.1 */
        x.set(r4);
        x.mul(r0);

        /* Y3 = r3.1 * r1.1 */
        y.set(r3);
        y.mul(r1);

        /* T3 = r4 * r1.1 */
        t.set(r4);
        t.mul(r1);

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
    public final void dbl() {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
         *
         * A = X1^2
         * B = Y1^2
         * C = 2 * Z1^2
         * D = a * A
         * E = (X1 + Y1)^2 - A - B
         * G = D + B
         * F = G - C
         * H = D - B
         * X3 = E * F
         * Y3 = G * H
         * T3 = E * H
         * Z3 = F * G
         *
         * Rewritten slightly as
         *
         * A = X1^2
         * B = Y1^2
         * C = -2 * Z1^2
         * E = (X1 + Y1)^2 - A - B
         * G = A + B
         * F = G + C
         * H = A - B
         * X3 = E * F
         * Y3 = G * H
         * T3 = E * H
         * Z3 = F * G
         *
         * Manual register allocation produces the following substitutions:
         *
         * r0 = A
         * r1 = B
         * r2 = C
         * r3 = E
         * r4 = G
         * r2.1 = F
         * r0.1 = H
         *
         * Final formula:
         *
         * r0 = X1^2
         * r1 = Y1^2
         * r2 = -2 * Z1^2
         * r3 = (X1 + Y1)^2 - r0 - r1
         * r4 = r0 + r1
         * r2.1 = r4 + r2
         * r0.1 = r0 - r1
         * X3 = r3 * r2.1
         * Y3 = r4 * r0.1
         * T3 = r3 * r0.1
         * Z3 = r2.1 * r4
         */

        /* r0 = X1^2 */
        final S r0 = x.clone();

        r0.square();

        /* r1 = Y1^2 */
        final S r1 = y.clone();

        r1.square();

        /* r2 = Z1^2 * -2 */
        final S r2 = z.clone();

        r2.square();
        r2.mul(-2);

        /* r3 = (X1 + Y1)^2 - r0 - r1 */
        final S r3 = x.clone();

        r3.add(y);
        r3.square();
        r3.sub(r0);
        r3.sub(r1);

        /* r4 = r0 + r1 */
        final S r4 = r0.clone();

        r4.add(r1);

        /* r2.1 = r4 + r2,
         * r2 dead
         */
        r2.add(r4);

        /* r0.1 = r0 - r1,
         * r0, r1 dead
         */
        r0.sub(r1);

        /* X3 = r3 * r2.1 */
        x.set(r3);
        x.mul(r2);

        /* Y3 = r4 * r0.1 */
        y.set(r4);
        y.mul(r0);

        /* T3 = r3 * r0.1,
         * r3 dead
         */
        t.set(r3);
        t.mul(r0);

        /* Z3 = r2.1 * r4,
         * r2.1, r4 dead
         */
        z.set(r2);
        z.mul(r4);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void mdbl() {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-mdbl-2008-hwcd
         *
         * A = X1^2
         * B = Y1^2
         * D = a * A
         * E = (X1 + Y1)^2 - A - B
         * G = D + B
         * H = D - B
         * X3 = E * (G - 2)
         * Y3 = G * H
         * T3 = E * H
         * Z3 = G^2 - 2 * G
         *
         * Rewritten slightly as
         *
         * A = X1^2
         * B = Y1^2
         * E = (X1 + Y1)^2 - A - B
         * G = A + B
         * H = A - B
         * X3 = E * (G - 2)
         * Y3 = G * H
         * T3 = E * H
         * S = 2 * G
         * Z3 = G^2 - S
         *
         * Manual register allocation produces the following substitutions:
         *
         * r0 = A
         * r1 = B
         * r2 = E
         * r3 = G
         * r0.1 = H
         * r0.2 = S
         *
         * Final formula:
         *
         * r0 = X1^2
         * r1 = Y1^2
         * r2 = (X1 + Y1)^2 - r0 - r1
         * r3 = r0 + r1
         * r0.1 = r0 - r1
         * X3 = r2 * (r3 - 2)
         * Y3 = r3 * r0.1
         * T3 = r2 * r0.1
         * r0.2 = 2 * r3
         * Z3 = r3^2 - r0.2
         */
        /* r0 = X1^2 */
        final S r0 = x.clone();

        r0.square();

        /* r1 = Y1^2 */
        final S r1 = y.clone();

        r1.square();

        /* r2 = (X1 + Y1)^2 - r0 - r1 */
        final S r2 = x.clone();

        r2.add(y);
        r2.square();
        r2.sub(r0);
        r2.sub(r1);

        /* r3 = r0 + r1 */
        final S r3 = r0.clone();

        r3.add(r1);

        /* r0.1 = r0 - r1,
         * r0, r1 dead
         */
        r0.sub(r1);

        /* X3 = (r3 - 2) * r2 */
        x.set(r3);
        x.sub(2);
        x.mul(r2);

        /* Y3 = r3 * r0.1 */
        y.set(r3);
        y.mul(r0);

        /* T3 = r2 * r0.1,
         * r0.1, r2 dead
         */
        t.set(r2);
        t.mul(r0);

        /* r0.2 = 2 * r3 */
        r0.set(r3);
        r0.mul(2);

        /* Z3 = r3^2 - r0.2 */
        z.set(r3);
        z.square();
        z.sub(r0);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void tpl() {
        /* Formula from
         * https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#tripling-tpl-2015-c
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
         * xE = X1 * (yB + AA)
         * yH = Y1 * (xB - AA)
         * zF = Z1 * F
         * zG = Z1 * G
         * X3 = xE * zF
         * Y3 = yH * zG
         * Z3 = zF * zG
         * T3 = xE * yH
         *
         * Rewritten slightly as:
         *
         * YY = Y1^2
         * XX = X1^2
         * Ap = YY + XX
         * B = 2 * (2 * Z1^2 - Ap)
         * xB = XX * B
         * yB = YY * B
         * AA = Ap * (YY - XX)
         * F = AA - yB
         * G = AA + xB
         * xE = X1 * (yB + AA)
         * yH = Y1 * (xB - AA)
         * zF = Z1 * F
         * zG = Z1 * G
         * X3 = xE * zF
         * Y3 = yH * zG
         * Z3 = zF * zG
         * T3 = xE * yH
         *
         * Manual register allocation produces the following substitutions:
         *
         * r0 = YY
         * r1 = XX
         * r2 = Ap
         * r3 = B
         * r4 = xB
         * r3.1 = yB
         * r0.1 = AA
         * r1.1 = F
         * r2.1 = G
         * r3.2 = xE
         * r4.1 = yH
         * r0.2 = zF
         * r2.2 = zG
         *
         * Final formula:
         *
         * r0 = Y1^2
         * r1 = X1^2
         * r2 = r0 + r1
         * r3 = 2 * (2 * Z1^2 - r2)
         * r4 = r1 * r3
         * r3.1 = r0 * r3
         * r0.1 = r2 * (r0 - r1)
         * r1.1 = r0.1 - r3.1
         * r2.1 = r0.1 + r4
         * r3.2 = X1 * (r3.1 + r0.1)
         * r4.1 = Y1 * (r4 - r0.1)
         * r0.2 = Z1 * r1.1
         * r2.2 = Z1 * r2.1
         * X3 = r3.2 * r0.2
         * Y3 = r4.1 * r2.2
         * Z3 = r0.2 * r2.2
         * T3 = r3.2 * r4.1
         */

        /* r0 = Y1^2 */
        final S r0 = y.clone();

        r0.square();

        /* r1 = X1^2 */
        final S r1 = x.clone();

        r1.square();

        /* r2 = r0 + r1 */
        final S r2 = r0.clone();

        r2.add(r1);

        /* r3 = (Z1^2 * 2 - r2) * 2 */
        final S r3 = z.clone();

        r3.square();
        r3.mul(2);
        r3.sub(r2);
        r3.mul(2);

        /* r4 = r1 * r3 */
        final S r4 = r1.clone();

        r4.mul(r3);

        /* r3.1 = r3 * r0,
         * r3 dead
         */
        r3.mul(r0);

        /* r0.1 = (r0 - r1) * r2,
         * r0, r1, r2 dead
         */
        r0.sub(r1);
        r0.mul(r2);

        /* r1.1 = r0.1 - r3.1 */
        r1.set(r0);
        r1.sub(r3);

        /* r2.1 = r0.1 + r4 */
        r2.set(r0);
        r2.add(r4);

        /* r3.2 = (r3.1 + r0.1) * X1,
         * r3.1 dead
         */
        r3.add(r0);
        r3.mul(x);

        /* r4.1 = (r4 - r0.1) * Y1,
         * r0.1, r4 dead
         */
        r4.sub(r0);
        r4.mul(y);

        /* r0.2 = Z1 * r1.1,
         * r1.1 dead
         */
        r0.set(z);
        r0.mul(r1);

        /* r2.2 = Z1 * r2.1,
         * r2.1 dead
         */
        r2.mul(z);

        /* X3 = r3.2 * r0.2 */
        x.set(r3);
        x.mul(r0);

        /* Y3 = r4.1 * r2.2 */
        y.set(r4);
        y.mul(r2);

        /* Z3 = r0.2 * r2.2,
         * r0.2, r2.2 dead
         */
        z.set(r0);
        z.mul(r2);

        /* T3 = r3.2 * r4.1,
         * r3.2, r4.1 dead
         */
        t.set(r3);
        t.add(r4);
    }
}
