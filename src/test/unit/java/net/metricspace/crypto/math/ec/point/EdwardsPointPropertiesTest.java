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

import net.metricspace.crypto.math.ec.EdwardsUtils;
import net.metricspace.crypto.math.ec.group.EdwardsCurveGroup;
import net.metricspace.crypto.math.ec.point.EdwardsPoint;
import net.metricspace.crypto.math.field.PrimeField;

public abstract class
    EdwardsPointPropertiesTest<S extends PrimeField<S>,
                               P extends EdwardsPoint<S, P>,
                               G extends EdwardsCurveGroup<S, P>>
    extends ECPointPropertiesTest<S, P> {
    protected final int dvalue;

    protected EdwardsPointPropertiesTest(final S[] coefficients,
                                         final P[] points,
                                         final G group) {
        super(coefficients, points, group.zeroPoint());

        this.dvalue = group.edwardsD();
    }

    @Test(dataProvider = "pairs",
          description = "Test addition against base Edwards formula")
    public void addControlTest(final P a,
                               final P b) {
        final S controlX = EdwardsUtils.additionX(a, b, dvalue);
        final S controlY = EdwardsUtils.additionY(a, b, dvalue);
        final P testpoint = a.clone();

        testpoint.add(b);

        Assert.assertEquals(testpoint.getX(), controlX);
        Assert.assertEquals(testpoint.getY(), controlY);
    }

    @Test(dataProvider = "pairs",
          description = "Test scaled addition against base Edwards formula")
    public void maddControlTest(final P a,
                                final P b) {
        final S controlX = EdwardsUtils.additionX(a, b, dvalue);
        final S controlY = EdwardsUtils.additionY(a, b, dvalue);
        final P testpoint = a.clone();

        testpoint.madd(b);

        Assert.assertEquals(testpoint.getX(), controlX);
        Assert.assertEquals(testpoint.getY(), controlY);
    }

    @Test(dataProvider = "pairs",
          description = "Test scaled addition against base Edwards formula")
    public void mmaddControlTest(final P a,
                                final P b) {
        final S controlX = EdwardsUtils.additionX(a, b, dvalue);
        final S controlY = EdwardsUtils.additionY(a, b, dvalue);
        final P testpoint = a.clone();

        testpoint.mmadd(b);

        Assert.assertEquals(testpoint.getX(), controlX);
        Assert.assertEquals(testpoint.getY(), controlY);
    }

    @Test(dataProvider = "points",
          description = "Test double against base Edwards formula")
    public void dblControlTest(final P p) {
        final S controlX = EdwardsUtils.doubleX(p, dvalue);
        final S controlY = EdwardsUtils.doubleY(p, dvalue);
        final P testpoint = p.clone();

        testpoint.dbl();

        Assert.assertEquals(testpoint.getX(), controlX);
        Assert.assertEquals(testpoint.getY(), controlY);
    }

    @Test(dataProvider = "points",
          description = "Test double against base Edwards formula")
    public void mdblControlTest(final P p) {
        final S controlX = EdwardsUtils.doubleX(p, dvalue);
        final S controlY = EdwardsUtils.doubleY(p, dvalue);
        final P testpoint = p.clone();

        testpoint.mdbl();

        Assert.assertEquals(testpoint.getX(), controlX);
        Assert.assertEquals(testpoint.getY(), controlY);
    }

    @Test(dataProvider = "points",
          description = "Test triple against base Edwards formula")
    public void tplControlTest(final P p) {
        final S controlX = EdwardsUtils.tripleX(p, dvalue);
        final S controlY = EdwardsUtils.tripleY(p, dvalue);
        final P testpoint = p.clone();

        testpoint.tpl();

        Assert.assertEquals(testpoint.getX(), controlX);
        Assert.assertEquals(testpoint.getY(), controlY);
    }

    @Test(dataProvider = "mulpoints",
          description = "Test multiply against base Edwards formula")
    public void mulControlTest(final S ninput,
                               final P input) {
        final S x = input.getX();
        final S y = input.getY();
        final P mulpoint = input.clone();
        final S n = ninput.clone();

        mulpoint.mul(n);
        EdwardsUtils.mulPoint(input, ninput, x, y, dvalue);
        Assert.assertEquals(mulpoint.getX(), x);
        Assert.assertEquals(mulpoint.getY(), y);
    }

    @Test(dataProvider = "points",
          description = "Sanity check for control addition")
    public void doubleSanity(final P p) {
        final S doubledX = EdwardsUtils.doubleX(p, dvalue);
        final S doubledY = EdwardsUtils.doubleY(p, dvalue);
        final S addedX = EdwardsUtils.additionX(p, p, dvalue);
        final S addedY = EdwardsUtils.additionY(p, p, dvalue);

        Assert.assertEquals(doubledX, addedX);
        Assert.assertEquals(doubledY, addedY);
    }
}
