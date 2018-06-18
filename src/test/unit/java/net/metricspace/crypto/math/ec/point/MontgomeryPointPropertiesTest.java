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

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import net.metricspace.crypto.math.ec.MontgomeryUtils;
import net.metricspace.crypto.math.ec.group.MontgomeryCurveGroup;
import net.metricspace.crypto.math.ec.point.MontgomeryPoint;
import net.metricspace.crypto.math.field.PrimeField;

public abstract class
    MontgomeryPointPropertiesTest<S extends PrimeField<S>,
                                  P extends MontgomeryPoint<S, P>,
                                  G extends MontgomeryCurveGroup<S, P>>
    extends ECPointPropertiesTest<S, P> {
    private final int avalue;

    protected MontgomeryPointPropertiesTest(final S[] coefficients,
                                            final P[] points,
                                            final G group) {
        super(coefficients, points, group.zeroPoint());

        this.avalue = group.montgomeryA();
    }

    @Test(dataProvider = "pairs",
          description = "Test addition against base Montgomery formula")
    public void addControlTest(final P a,
                               final P b) {
        final P testpoint = a.clone();

        testpoint.add(b);

        if (!a.equals(zeroPoint)) {
            if (!b.equals(zeroPoint)) {
                final S controlX;
                final S controlY;

                if (!a.equals(b)) {
                    controlX = MontgomeryUtils.additionX(a, b, avalue,
                                                         zeroPoint);
                    controlY = MontgomeryUtils.additionY(a, b, avalue,
                                                         zeroPoint);
                } else {
                    controlX = MontgomeryUtils.doubleX(a, avalue, zeroPoint);
                    controlY = MontgomeryUtils.doubleY(a, avalue, zeroPoint);
                }

                Assert.assertEquals(testpoint.getX(), controlX);
                Assert.assertEquals(testpoint.getY(), controlY);
            } else {
                Assert.assertEquals(testpoint, a);
            }
        } else {
            Assert.assertEquals(testpoint, b);
        }
    }

    @Test(dataProvider = "pairs",
          description = "Test scaled addition against base Montgomery formula")
    public void maddControlTest(final P a,
                               final P b) {
        final P testpoint = a.clone();

        testpoint.madd(b);

        if (!a.equals(zeroPoint)) {
            if (!b.equals(zeroPoint)) {
                final S controlX;
                final S controlY;

                if (!a.equals(b)) {
                    controlX = MontgomeryUtils.additionX(a, b, avalue,
                                                         zeroPoint);
                    controlY = MontgomeryUtils.additionY(a, b, avalue,
                                                         zeroPoint);
                } else {
                    controlX = MontgomeryUtils.doubleX(a, avalue, zeroPoint);
                    controlY = MontgomeryUtils.doubleY(a, avalue, zeroPoint);
                }

                Assert.assertEquals(testpoint.getX(), controlX);
                Assert.assertEquals(testpoint.getY(), controlY);
            } else {
                Assert.assertEquals(testpoint, a);
            }
        } else {
            Assert.assertEquals(testpoint, b);
        }
    }

    @Test(dataProvider = "pairs",
          description = "Test addition against base Montgomery formula")
    public void mmaddControlTest(final P a,
                                 final P b) {
        final P testpoint = a.clone();

        testpoint.mmadd(b);

        if (!a.equals(zeroPoint)) {
            if (!b.equals(zeroPoint)) {
                final S controlX;
                final S controlY;

                if (!a.equals(b)) {
                    controlX = MontgomeryUtils.additionX(a, b, avalue,
                                                         zeroPoint);
                    controlY = MontgomeryUtils.additionY(a, b, avalue,
                                                         zeroPoint);
                } else {
                    controlX = MontgomeryUtils.doubleX(a, avalue, zeroPoint);
                    controlY = MontgomeryUtils.doubleY(a, avalue, zeroPoint);
                }

                Assert.assertEquals(testpoint.getX(), controlX);
                Assert.assertEquals(testpoint.getY(), controlY);
            } else {
                Assert.assertEquals(testpoint, a);
            }
        } else {
            Assert.assertEquals(testpoint, b);
        }
    }

    @Test(dataProvider = "points",
          description = "Test double against base Montgomery formula")
    public void dblControlTest(final P p) {
        final P testpoint = p.clone();

        testpoint.dbl();

        if (!p.equals(zeroPoint)) {
            final S controlX = MontgomeryUtils.doubleX(p, avalue, zeroPoint);
            final S controlY = MontgomeryUtils.doubleY(p, avalue, zeroPoint);

            Assert.assertEquals(testpoint.getX(), controlX);
            Assert.assertEquals(testpoint.getY(), controlY);
        } else {
            testpoint.equals(zeroPoint);
        }
    }

    @Test(dataProvider = "points",
          description = "Test scaled double against base Montgomery formula")
    public void mdblControlTest(final P p) {
        final P testpoint = p.clone();

        testpoint.mdbl();

        if (!p.equals(zeroPoint)) {
            final S controlX = MontgomeryUtils.doubleX(p, avalue, zeroPoint);
            final S controlY = MontgomeryUtils.doubleY(p, avalue, zeroPoint);

            Assert.assertEquals(testpoint.getX(), controlX);
            Assert.assertEquals(testpoint.getY(), controlY);
        } else {
            testpoint.equals(zeroPoint);
        }
    }

    @Test(dataProvider = "points",
          description = "Test triple against base Montgomery formula")
    public void tplControlTest(final P p) {
        final P testpoint = p.clone();

        testpoint.tpl();

        if (!p.equals(zeroPoint)) {
            final S controlX = MontgomeryUtils.tripleX(p, avalue);
            final S controlY = MontgomeryUtils.tripleY(p, avalue);

            Assert.assertEquals(testpoint.getX(), controlX);
            Assert.assertEquals(testpoint.getY(), controlY);
        } else {
            testpoint.equals(zeroPoint);
        }
    }

    @Test(dataProvider = "mulpoints",
          description = "Test multiply against base Montgomery formula")
    public void mulControlTest(final S ninput,
                               final P input) {
        final P mulpoint = input.clone();
        final S n = ninput.clone();

        mulpoint.mul(n);

        if (!input.equals(zeroPoint)) {
            final S x = input.getX();
            final S y = input.getY();

            MontgomeryUtils.mulPoint(input, ninput, x, y, avalue);
            Assert.assertEquals(mulpoint.getX(), x);
            Assert.assertEquals(mulpoint.getY(), y);
        } else {
            Assert.assertEquals(mulpoint, zeroPoint);
        }
    }

    @Test(dataProvider = "points",
          description = "Sanity check for control addition")
    public void doubleSanity(final P p) {
        final S doubledX = MontgomeryUtils.doubleX(p, avalue, zeroPoint);
        final S doubledY = MontgomeryUtils.doubleY(p, avalue, zeroPoint);
        final S addedX = MontgomeryUtils.additionX(p, p, avalue, zeroPoint);
        final S addedY = MontgomeryUtils.additionY(p, p, avalue, zeroPoint);

        Assert.assertEquals(doubledX, addedX);
        Assert.assertEquals(doubledY, addedY);
    }
}
