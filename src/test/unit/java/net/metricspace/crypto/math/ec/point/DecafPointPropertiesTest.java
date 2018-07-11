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

import net.metricspace.crypto.math.ec.point.DecafPoint;
import net.metricspace.crypto.math.ec.point.EdwardsPoint;
import net.metricspace.crypto.math.ec.group.EdwardsCurveGroup;
import net.metricspace.crypto.math.field.PrimeField;

public abstract class
    DecafPointPropertiesTest<S extends PrimeField<S>,
                             P extends EdwardsDecafPoint<S, P, ?>,
                             G extends EdwardsCurveGroup<S, P, ?>>
    extends EdwardsPointPropertiesTest<S, P, G> {
    private final Object[][] compressedPoints;

    protected DecafPointPropertiesTest(final S[] coefficients,
                                       final P[] points,
                                       final S[] compressed,
                                       final G group) {
        super(coefficients, points, group);

        compressedPoints = new Object[points.length][2];

        for(int i = 0; i < points.length; i++) {
            compressedPoints[i][0] = points[i];
            compressedPoints[i][1] = compressed[i];
        }
    }

    @Test(dataProvider = "points",
          description = "Test point compression/decompression")
    public void compressDecompressTest(final P expected) {
        final P actual = expected.clone();
        final S compressed = expected.compress();

        actual.reset();
        actual.decompress(compressed);
        Assert.assertEquals(actual, expected);
    }

    @DataProvider(name = "compress")
    public Object[][] getCompressPoints() {
        return compressedPoints;
    }

    @Test(dataProvider = "compress",
          description = "Test point compression against known values")
    public void compressSanity(final P point,
                               final S expected) {
        final S actual = point.compress();

        Assert.assertEquals(actual, expected);
    }
}
