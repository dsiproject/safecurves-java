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
import net.metricspace.crypto.math.ec.point.EdwardsPoint;
import net.metricspace.crypto.math.field.PrimeField;

public final class EdwardsUtils {
    private EdwardsUtils() {}

    private static <S extends PrimeField<S>> S addScalars(final S a,
                                                          final S b) {
        final S out = a.clone();

        out.add(b);

        return out;
    }

    private static <S extends PrimeField<S>> S subScalars(final S a,
                                                          final S b) {
        final S out = a.clone();

        out.sub(b);

        return out;
    }

    private static <S extends PrimeField<S>> S mulScalars(final S a,
                                                          final S b) {
        final S out = a.clone();

        out.mul(b);

        return out;
    }

    private static <S extends PrimeField<S>> S divScalars(final S a,
                                                          final S b) {
        final S out = a.clone();

        out.div(b);

        return out;
    }

    private static <S extends PrimeField<S>> S scalarTimesD(final S s,
                                                            final int dvalue) {
        final S out = s.clone();

        out.mul(dvalue);

        return out;
    }

    private static <S extends PrimeField<S>> S onePlusScalar(final S s) {
        final S out = s.clone();

        out.add(1);

        return out;
    }

    private static <S extends PrimeField<S>> S oneMinusScalar(final S s) {
        final S out = s.clone();

        out.neg();
        out.add(1);

        return out;
    }

    public static <S extends PrimeField<S>, P extends EdwardsPoint<S, P>>
        S additionX(final P a,
                    final P b,
                    final int dvalue) {
        final S x1 = a.edwardsX();
        final S x2 = b.edwardsX();
        final S y1 = a.edwardsY();
        final S y2 = b.edwardsY();

        return additionXscalars(x1, x2, y1, y2, dvalue);
    }

    private static <S extends PrimeField<S>>
        S additionXscalars(final S x1,
                           final S x2,
                           final S y1,
                           final S y2,
                           final int dvalue) {
        final S x1y2 = mulScalars(x1, y2);
        final S x2y1 = mulScalars(x2, y1);
        final S x1x2y1y2 = mulScalars(x1y2, x2y1);
        final S dx1x2y1y2 = scalarTimesD(x1x2y1y2, dvalue);
        final S x1y2plusx2y1 = addScalars(x1y2, x2y1);
        final S oneplusdx1x2y1y2 = onePlusScalar(dx1x2y1y2);

        return divScalars(x1y2plusx2y1, oneplusdx1x2y1y2);
    }

    public static <S extends PrimeField<S>, P extends EdwardsPoint<S, P>>
        S additionY(final P a,
                    final P b,
                    final int dvalue) {
        final S x1 = a.edwardsX();
        final S x2 = b.edwardsX();
        final S y1 = a.edwardsY();
        final S y2 = b.edwardsY();

        return additionYscalars(x1, x2, y1, y2, dvalue);
    }

    private static <S extends PrimeField<S>>
        S additionYscalars(final S x1,
                           final S x2,
                           final S y1,
                           final S y2,
                           final int dvalue) {
        final S x1x2 = mulScalars(x1, x2);
        final S y1y2 = mulScalars(y1, y2);
        final S x1x2y1y2 = mulScalars(x1x2, y1y2);
        final S dx1x2y1y2 = scalarTimesD(x1x2y1y2, dvalue);
        final S y1y2minusx1x2 = subScalars(y1y2, x1x2);
        final S oneminusdx1x2y1y2 = oneMinusScalar(dx1x2y1y2);

        return divScalars(y1y2minusx1x2, oneminusdx1x2y1y2);
    }

    public static <S extends PrimeField<S>, P extends EdwardsPoint<S, P>>
        S doubleX(final P p,
                  final int dvalue) {
        final S x = p.edwardsX();
        final S y = p.edwardsY();

        return doubleXscalars(x, y, dvalue);
    }

    private static <S extends PrimeField<S>>
        S doubleXscalars(final S x,
                         final S y,
                         final int dvalue) {
        return additionXscalars(x, x, y, y, dvalue);
    }

    public static <S extends PrimeField<S>, P extends EdwardsPoint<S, P>>
        S doubleY(final P p,
                  final int dvalue) {
        final S x = p.edwardsX();
        final S y = p.edwardsY();

        return doubleYscalars(x, y, dvalue);
    }

    private static <S extends PrimeField<S>>
        S doubleYscalars(final S x,
                         final S y,
                         final int dvalue) {
        return additionYscalars(x, x, y, y, dvalue);
    }

    public static <S extends PrimeField<S>, P extends EdwardsPoint<S, P>>
        S tripleX(final P p,
                  final int dvalue) {
        final S x = p.edwardsX();
        final S y = p.edwardsY();

        return tripleXscalars(x, y, dvalue);
    }

    private static <S extends PrimeField<S>>
        S tripleXscalars(final S x,
                         final S y,
                         final int dvalue) {
        return additionXscalars(x, doubleXscalars(x, y, dvalue),
                                y, doubleYscalars(x, y, dvalue),
                                dvalue);
    }

    public static <S extends PrimeField<S>, P extends EdwardsPoint<S, P>>
        S tripleY(final P p,
                  final int dvalue) {
        final S x = p.edwardsX();
        final S y = p.edwardsY();

        return tripleYscalars(x, y, dvalue);
    }

    private static <S extends PrimeField<S>>
        S tripleYscalars(final S x,
                         final S y,
                         final int dvalue) {
        return additionYscalars(x, doubleXscalars(x, y, dvalue),
                                y, doubleYscalars(x, y, dvalue),
                                dvalue);
    }

    public static <S extends PrimeField<S>, P extends EdwardsPoint<S, P>>
        void mulPoint(final P p,
                      final S s,
                      final S r0x,
                      final S r0y,
                      final int dvalue) {
        final S r1x = p.getX();
        final S r1y = p.getY();

        r0x.set(0);
        r0y.set(1);

        for(int i = s.numBits() - 1; i >= 0; i--) {
            final long bit = s.bit(i);

            if (bit == 0) {
                final S newr1x = additionXscalars(r0x, r1x, r0y, r1y, dvalue);
                final S newr1y = additionYscalars(r0x, r1x, r0y, r1y, dvalue);
                final S newr0x = doubleXscalars(r0x, r0y, dvalue);
                final S newr0y = doubleYscalars(r0x, r0y, dvalue);

                r1x.set(newr1x);
                r1y.set(newr1y);
                r0x.set(newr0x);
                r0y.set(newr0y);
            } else {
                final S newr0x = additionXscalars(r0x, r1x, r0y, r1y, dvalue);
                final S newr0y = additionYscalars(r0x, r1x, r0y, r1y, dvalue);
                final S newr1x = doubleXscalars(r1x, r1y, dvalue);
                final S newr1y = doubleYscalars(r1x, r1y, dvalue);

                r0x.set(newr0x);
                r0y.set(newr0y);
                r1x.set(newr1x);
                r1y.set(newr1y);
            }
        }
    }
}
