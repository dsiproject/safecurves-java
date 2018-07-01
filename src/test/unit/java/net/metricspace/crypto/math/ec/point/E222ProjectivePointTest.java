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

import net.metricspace.crypto.math.ec.group.E222;
import net.metricspace.crypto.math.ec.group.E222Projective;
import net.metricspace.crypto.math.ec.point.E222ProjectivePoint;
import net.metricspace.crypto.math.field.ModE222M117;

public class E222ProjectivePointTest
    extends EdwardsPointPropertiesTest<ModE222M117,
                                       E222ProjectivePoint,
                                       E222Projective> {
    private static final E222ProjectivePoint BASE_POINT =
        E222ProjectivePoint.fromEdwards(E222.baseX(), E222.baseY());

    private static final E222ProjectivePoint POINT_TWO =
        BASE_POINT.clone();

    private static final E222ProjectivePoint POINT_THREE =
        BASE_POINT.clone();

    static {
        POINT_TWO.add(BASE_POINT);
        POINT_TWO.scale();
        POINT_THREE.add(POINT_TWO);
        POINT_THREE.scale();
    };

    private static final E222ProjectivePoint[] points =
        new E222ProjectivePoint[] {
            E222ProjectivePoint.zero(),
            BASE_POINT,
            POINT_TWO,
            POINT_THREE
        };

    private static final ModE222M117[] coefficients =
        new ModE222M117[] {
             new ModE222M117(1),
             new ModE222M117(2),
             new ModE222M117(3),
             new ModE222M117(4),
             new ModE222M117(5),
             new ModE222M117(7),
             new ModE222M117(9),
             new ModE222M117(16),
             new ModE222M117(19),
             new ModE222M117(20)
        };

    public E222ProjectivePointTest() {
        super(coefficients, points, new E222Projective());
    }
}
