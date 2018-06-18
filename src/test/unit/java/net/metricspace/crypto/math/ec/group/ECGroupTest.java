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
package net.metricspace.crypto.math.ec.group;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.PrimeField;

@Test(groups = "unit")
public abstract class ECGroupTest<S extends PrimeField<S>,
                                  P extends ECPoint<S, P>,
                                  G extends ECGroup<S, P>> {
    protected final S primeOrder;
    protected final P basePoint;
    protected final P zeroPoint;
    private final G group;
    private final String baseXString;
    private final String baseYString;
    private final String primeOrderString;

    protected ECGroupTest(final G group,
                          final String baseXString,
                          final String baseYString,
                          final String primeOrderString) {
        this.group = group;
        this.baseXString = baseXString;
        this.baseYString = baseYString;
        this.primeOrderString = primeOrderString;
        this.basePoint = group.basePoint();
        this.zeroPoint = group.zeroPoint();
        this.primeOrder = group.primeOrder();
    }

    @Test(description = "Test the base point X coordinate")
    public void baseXTest() {
        Assert.assertEquals(basePoint.getX().toString(), baseXString);
    }

    @Test(description = "Test the base point Y coordinate")
    public void baseYTest() {
        Assert.assertEquals(basePoint.getY().toString(), baseYString);
    }

    @Test(description = "Test the prime order")
    public void primeOrderTest() {
        Assert.assertEquals(primeOrder.toString(), primeOrderString);
    }

    @Test(description = "Test multiplication by the prime order")
    public void primeOrderMulTest() {
        final P point = basePoint.clone();

        point.mul(primeOrder);

        Assert.assertEquals(point, zeroPoint);
    }
}
