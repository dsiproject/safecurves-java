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
import net.metricspace.crypto.math.ec.point.MontgomeryPoint;
import net.metricspace.crypto.math.field.PrimeField;

public final class MontgomeryUtils {
    private MontgomeryUtils() {}

    public static <S extends PrimeField<S>, P extends MontgomeryPoint<S, P, ?>>
        boolean additionInf(final P a,
                            final P b) {
        return additionInfScalars(a.montgomeryX(), b.montgomeryX());
    }

    public static <S extends PrimeField<S>>
        boolean additionInfScalars(final S x1,
                                   final S x2) {
        return x1.equals(x2);
    }

    public static <S extends PrimeField<S>, P extends MontgomeryPoint<S, P, ?>>
        S additionX(final P a,
                    final P b,
                    final S avalue,
                    final P zeroPoint) {
        if (!a.equals(zeroPoint)) {
            if (!b.equals(zeroPoint)) {
                if (!a.equals(b)) {
                    final S x1 = a.montgomeryX();
                    final S x2 = b.montgomeryX();
                    final S y1 = a.montgomeryY();
                    final S y2 = b.montgomeryY();

                    return additionXscalars(x1, x2, y1, y2, avalue);
                } else {
                    final S x = a.montgomeryX();
                    final S y = a.montgomeryY();

                    return doubleXscalars(x, y, avalue);
                }
            } else {
                return a.montgomeryX();
            }
        } else {
            return b.montgomeryX();
        }
    }

    private static <S extends PrimeField<S>>
        S additionXscalars(final S x1,
                           final S x2,
                           final S y1,
                           final S y2,
                           final S avalue) {
        if (x1.equals(x2) && y1.equals(y2)) {
            return doubleXscalars(x1, y1, avalue);
        }

        final S y2my1 = y2.clone();

        y2my1.sub(y1);

        final S x2mx1 = x2.clone();

        x2mx1.sub(x1);

        final S y2my1sq = y2my1.clone();

        y2my1sq.square();

        final S x2mx1sq = x2mx1.clone();

        x2mx1sq.square();

        final S fracsq = y2my1sq.clone();

        fracsq.div(x2mx1sq);

        final S out = fracsq.clone();

        out.sub(avalue);
        out.sub(x1);
        out.sub(x2);

        return out;
    }

    public static <S extends PrimeField<S>, P extends MontgomeryPoint<S, P, ?>>
        S additionY(final P a,
                    final P b,
                    final S avalue,
                    final P zeroPoint) {
        if (!a.equals(zeroPoint)) {
            if (!b.equals(zeroPoint)) {
                if (!a.equals(b)) {
                    final S x1 = a.montgomeryX();
                    final S x2 = b.montgomeryX();
                    final S y1 = a.montgomeryY();
                    final S y2 = b.montgomeryY();

                    return additionYscalars(x1, x2, y1, y2, avalue);
                } else {
                    final S x = a.montgomeryX();
                    final S y = a.montgomeryY();

                    return doubleYscalars(x, y, avalue);
                }
            } else {
                return a.montgomeryY();
            }
        } else {
            return b.montgomeryY();
        }
    }

    private static <S extends PrimeField<S>>
        S additionYscalars(final S x1,
                           final S x2,
                           final S y1,
                           final S y2,
                           final S avalue) {
        if (x1.equals(x2) && y1.equals(y2)) {
            return doubleYscalars(x1, y1, avalue);
        }

        final S y2my1 = y2.clone();

        y2my1.sub(y1);

        final S x2mx1 = x2.clone();

        x2mx1.sub(x1);

        final S y2my1cu = y2my1.clone();

        y2my1cu.mul(y2my1);
        y2my1cu.mul(y2my1);

        final S x2mx1cu = x2mx1.clone();

        x2mx1cu.mul(x2mx1);
        x2mx1cu.mul(x2mx1);

        final S frac = y2my1.clone();

        frac.div(x2mx1);

        final S fraccu = y2my1cu.clone();

        fraccu.div(x2mx1cu);

        final S ysum = x1.clone();

        ysum.mul(2);
        ysum.add(x2);
        ysum.add(avalue);

        final S ysumfrac = frac.clone();

        ysumfrac.mul(ysum);

        final S out = ysumfrac.clone();

        out.sub(fraccu);
        out.sub(y1);

        return out;
    }

    public static <S extends PrimeField<S>, P extends MontgomeryPoint<S, P, ?>>
        S doubleX(final P p,
                  final S avalue,
                  final P zeroPoint) {
        if (!p.equals(zeroPoint)) {
            final S x = p.montgomeryX().clone();
            final S y = p.montgomeryY().clone();

            return doubleXscalars(x, y, avalue);
        } else {
            return p.montgomeryX();
        }
    }

    private static <S extends PrimeField<S>>
        S doubleXscalars(final S x,
                         final S y,
                         final S avalue) {
        final S xsq = x.clone();

        xsq.square();

        final S x2a = x.clone();

        x2a.mul(avalue);
        x2a.mul(2);

        final S numer = xsq.clone();

        numer.mul(3);
        numer.add(x2a);
        numer.add(1);

        final S numersq = numer.clone();

        numersq.square();

        final S denomsq = y.clone();

        denomsq.mul(2);
        denomsq.square();

        final S xfrac = numersq.clone();

        xfrac.div(denomsq);

        final S out = xfrac.clone();

        out.sub(avalue);
        out.sub(x);
        out.sub(x);

        return out;
    }

    public static <S extends PrimeField<S>, P extends MontgomeryPoint<S, P, ?>>
        S doubleY(final P p,
                  final S avalue,
                  final P zeroPoint) {
        if (!p.equals(zeroPoint)) {
            final S x = p.montgomeryX();
            final S y = p.montgomeryY();

            return doubleYscalars(x, y, avalue);
        } else {
            return p.montgomeryY();
        }
    }

    private static <S extends PrimeField<S>>
        S doubleYscalars(final S x,
                         final S y,
                         final S avalue) {
        final S xsq = x.clone();

        xsq.square();

        final S x2a = x.clone();

        x2a.mul(avalue);
        x2a.mul(2);

        final S numer = xsq.clone();

        numer.mul(3);
        numer.add(x2a);
        numer.add(1);

        final S denom = y.clone();

        denom.mul(2);

        final S numercu = numer.clone();

        numercu.mul(numer);
        numercu.mul(numer);

        final S denomcu = denom.clone();

        denomcu.mul(denom);
        denomcu.mul(denom);

        final S cufrac = numercu.clone();

        cufrac.div(denomcu);

        final S prod = x.clone();

        prod.mul(3);
        prod.add(avalue);

        final S numerprod = prod.clone();

        numerprod.mul(numer);

        final S frac = numerprod.clone();

        frac.div(denom);

        final S out = frac.clone();

        out.sub(cufrac);
        out.sub(y);

        return out;
    }

    public static <S extends PrimeField<S>, P extends MontgomeryPoint<S, P, ?>>
        boolean tripleInf(final P p,
                          final S avalue) {
        final S x = p.montgomeryX();
        final S y = p.montgomeryY();

        return tripleInfScalars(x, y, avalue);
    }

    private static <S extends PrimeField<S>>
        boolean tripleInfScalars(final S x,
                                 final S y,
                                 final S avalue) {
        final S dx = doubleXscalars(x, y, avalue);
        final S dy = doubleYscalars(x, y, avalue);

        return dx.equals(x);
    }

    public static <S extends PrimeField<S>, P extends MontgomeryPoint<S, P, ?>>
        S tripleX(final P p,
                  final S avalue) {
        final S x = p.montgomeryX();
        final S y = p.montgomeryY();

        return tripleXscalars(x, y, avalue);
    }

    private static <S extends PrimeField<S>>
        S tripleXscalars(final S x,
                         final S y,
                         final S avalue) {
        return additionXscalars(x, doubleXscalars(x, y, avalue),
                                y, doubleYscalars(x, y, avalue),
                                avalue);
    }

    public static <S extends PrimeField<S>, P extends MontgomeryPoint<S, P, ?>>
        S tripleY(final P p,
                  final S avalue) {
        final S x = p.montgomeryX();
        final S y = p.montgomeryY();

        return tripleYscalars(x, y, avalue);
    }

    private static <S extends PrimeField<S>>
        S tripleYscalars(final S x,
                         final S y,
                         final S avalue) {
        return additionYscalars(x, doubleXscalars(x, y, avalue),
                                y, doubleYscalars(x, y, avalue),
                                avalue);
    }

    public static <S extends PrimeField<S>, P extends MontgomeryPoint<S, P, ?>>
        void mulPoint(final P p,
                      final S s,
                      final S r0x,
                      final S r0y,
                      final S avalue) {
        final S r1x = p.getX();
        final S r1y = p.getY();
        boolean r0zero = true;

        for(int i = s.numBits() - 1; i >= 0; i--) {
            final long bit = s.bit(i);

            if (bit == 0) {
                if (!r0zero) {
                    final S newr1x = additionXscalars(r0x, r1x, r0y, r1y,
                                                      avalue);
                    final S newr1y = additionYscalars(r0x, r1x, r0y, r1y,
                                                      avalue);
                    final S newr0x = doubleXscalars(r0x, r0y, avalue);
                    final S newr0y = doubleYscalars(r0x, r0y, avalue);

                    r1x.set(newr1x);
                    r1y.set(newr1y);
                    r0x.set(newr0x);
                    r0y.set(newr0y);
                }
            } else {
                if (!r0zero) {
                    final S newr0x = additionXscalars(r0x, r1x, r0y, r1y,
                                                      avalue);
                    final S newr0y = additionYscalars(r0x, r1x, r0y, r1y,
                                                      avalue);
                    final S newr1x = doubleXscalars(r1x, r1y, avalue);
                    final S newr1y = doubleYscalars(r1x, r1y, avalue);

                    r0x.set(newr0x);
                    r0y.set(newr0y);
                    r1x.set(newr1x);
                    r1y.set(newr1y);

                } else {
                    final S newr1x = doubleXscalars(r1x, r1y, avalue);
                    final S newr1y = doubleYscalars(r1x, r1y, avalue);

                    r0x.set(r1x);
                    r0y.set(r1y);
                    r1x.set(newr1x);
                    r1y.set(newr1y);
                }
                r0zero = false;
            }
        }
    }
}
