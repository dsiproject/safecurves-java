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

import net.metricspace.crypto.math.ec.group.ECGroup;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.PrimeField;

@Test(groups = "unit")
public abstract class ECPointPropertiesTest<S extends PrimeField<S>,
                                            P extends ECPoint<S, P, ?>> {
    protected final P zeroPoint;

    /**
     * Single-argument arrays of points of type {@code P}
     */
    private final Object[][] points;
    /**
     * Two-argument array, the first being a scalar value of type
     * {@code S}, the second a point of type {@code P}
     */
    private final Object[][] mulpoints;
    /**
     * Two-argument array, both points of type {@code P}.
     */
    private final Object[][] pairs;
    /**
     * Two-argument array, both points of type {@code P}, which are
     * not equal to each other.
     */
    private final Object[][] diffpairs;

    protected ECPointPropertiesTest(final S[] coefficients,
                                    final P[] points,
                                    final P zeroPoint) {
        final int npoints = points.length;
        final int nmulpoints = npoints * coefficients.length;
        final int npairs = npoints * npoints;
        final int ndiffpairs = npoints * (npoints - 1);

        this.zeroPoint = zeroPoint;
        this.points = new Object[npoints][1];
        this.mulpoints = new Object[nmulpoints][2];
        this.pairs = new Object[npairs][2];
        this.diffpairs = new Object[ndiffpairs][2];

        for(int i = 0; i < npoints; i++) {
            this.points[i][0] = points[i];
        }

        for(int i = 0; i < coefficients.length; i++) {
            for(int j = 0; j < npoints; j++) {
                this.mulpoints[(i * npoints) + j][0] = coefficients[i];
                this.mulpoints[(i * npoints) + j][1] = points[j];
            }
        }

        for(int i = 0; i < npoints; i++) {
            for(int j = 0; j < npoints; j++) {
                this.pairs[(i * npoints) + j][0] = points[i];
                this.pairs[(i * npoints) + j][1] = points[j];
            }
        }

        int idx = 0;

        for(int i = 0; i < npoints; i++) {
            for(int j = 0; j < npoints; j++) {
                if (i != j) {
                    this.diffpairs[idx][0] = points[i];
                    this.diffpairs[idx][1] = points[j];
                    idx++;
                }
            }
        }
    }

    @DataProvider(name = "points")
    public Object[][] getPoints() {
        return points;
    }

    @DataProvider(name = "pairs")
    public Object[][] getPairs() {
        return pairs;
    }

    @DataProvider(name = "mulpoints")
    public Object[][] getMulPoints() {
        return mulpoints;
    }

    @Test(dataProvider = "points",
          description = "Test that reset produces a zero point")
    public void resetTest(final P input) {
        final P resetpoint = input.clone();

        resetpoint.reset();

        Assert.assertEquals(resetpoint, zeroPoint);
    }

    @Test(dataProvider = "points",
          description = "Test that double and adding to itself are the same")
    public void addDblTest(final P input) {
        final P addpoint = input.clone();
        final P dblpoint = input.clone();

        addpoint.suadd(input);
        dblpoint.dbl();

        Assert.assertEquals(dblpoint, addpoint);
    }

    @Test(dataProvider = "points",
          description = "Test that triple and adding to itself twice " +
          "are the same")
    public void addTplTest(final P input) {
        final P addpoint = input.clone();
        final P tplpoint = input.clone();

        addpoint.suadd(input);
        addpoint.suadd(input);
        tplpoint.tpl();

        Assert.assertEquals(tplpoint, addpoint);
    }

    @Test(dataProvider = "points",
          description = "Test that triple and doubling and adding to itself " +
          "are the same")
    public void dblAddTplTest(final P input) {
        final P addpoint = input.clone();
        final P tplpoint = input.clone();

        addpoint.dbl();
        addpoint.suadd(input);
        tplpoint.tpl();

        Assert.assertEquals(tplpoint, addpoint);
    }

    @Test(dataProvider = "mulpoints",
          description = "Test that scalar multiplication and repeated "+
          "addition are the same")
    public void addMulTest(final S ninput,
                           final P input) {
        final P addpoint = input.clone();
        final P mulpoint = input.clone();
        final S n = ninput.clone();

        mulpoint.mul(n);
        n.sub(1);

        while(!n.isZero()) {
            addpoint.suadd(input);
            n.sub(1);
        }

        Assert.assertEquals(mulpoint, addpoint);
    }
}
