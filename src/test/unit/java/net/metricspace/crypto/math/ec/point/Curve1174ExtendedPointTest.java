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

import net.metricspace.crypto.math.ec.group.Curve1174;
import net.metricspace.crypto.math.ec.group.Curve1174Extended;
import net.metricspace.crypto.math.ec.point.Curve1174ExtendedPoint;
import net.metricspace.crypto.math.field.ModE251M9;

public class Curve1174ExtendedPointTest
    extends EdwardsPointPropertiesTest<ModE251M9, Curve1174ExtendedPoint,
                                       Curve1174Extended> {
    private static final Curve1174ExtendedPoint BASE_POINT =
        Curve1174ExtendedPoint.fromEdwards(Curve1174.baseX(),
                                           Curve1174.baseY());

    private static final Curve1174ExtendedPoint POINT_TWO =
        BASE_POINT.clone();

    private static final Curve1174ExtendedPoint POINT_THREE =
        BASE_POINT.clone();

    static {
        POINT_TWO.add(BASE_POINT);
        POINT_TWO.scale();
        POINT_THREE.add(POINT_TWO);
        POINT_THREE.scale();
    };

    private static final Curve1174ExtendedPoint[] points =
        new Curve1174ExtendedPoint[] {
            Curve1174ExtendedPoint.zero(),
            BASE_POINT,
            POINT_TWO,
            POINT_THREE
        };

    private static final ModE251M9[] coefficients =
        new ModE251M9[] {
             new ModE251M9(1),
             new ModE251M9(2),
             new ModE251M9(3),
             new ModE251M9(4),
             new ModE251M9(5),
             new ModE251M9(7),
             new ModE251M9(9),
             new ModE251M9(16),
             new ModE251M9(19),
             new ModE251M9(20)
        };

    public Curve1174ExtendedPointTest() {
        super(coefficients, points, new Curve1174Extended());
    }
}
