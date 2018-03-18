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
package net.metricspace.crypto.math.ec.hash;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.PrimeField;

@Test(groups = "unit")
public abstract class ElligatorTest<S extends PrimeField<S>,
                                    P extends Elligator<S, P>> {
    private final Object[][] pointsData;

    public ElligatorTest(final S[] encoded,
                         final P[] points) {
        pointsData = new Object[encoded.length][2];

        for(int i = 0; i < encoded.length; i++) {
            pointsData[i][0] = encoded[i];
            pointsData[i][1] = points[i];
        }
    }

    @DataProvider(name = "points")
    public Object[][] getPoints() {
        return pointsData;
    }

    @Test(dataProvider = "points",
          description = "Test that points encode to the expected hash")
    public void testEncode(final P point,
                           final S expected) {
        final S actual = point.encodeHash();

        Assert.assertEquals(expected, actual);
    }

    @Test(dataProvider = "points",
          description = "Test that points decode as expected")
    public void testDecode(final S encoded,
                           final P expected) {
        final P actual = expected.clone();

        actual.zero();
        actual.decodeHash(encoded);

        Assert.assertEquals(expected, actual);
    }
}
