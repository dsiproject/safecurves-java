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

import net.metricspace.crypto.math.ec.group.Curve41417;
import net.metricspace.crypto.math.ec.group.Curve41417Projective;
import net.metricspace.crypto.math.ec.point.Curve41417ProjectivePoint;
import net.metricspace.crypto.math.field.ModE414M17;

public class Curve41417ProjectivePointTest
    extends EdwardsPointPropertiesTest<ModE414M17, Curve41417ProjectivePoint,
                                       Curve41417Projective> {
    private static final Curve41417ProjectivePoint[] points =
        new Curve41417ProjectivePoint[] {
            Curve41417ProjectivePoint.zero(),
            Curve41417ProjectivePoint.fromEdwards(Curve41417.baseX(),
                                                  Curve41417.baseY())
        };

    private static final ModE414M17[] coefficients =
        new ModE414M17[] {
             new ModE414M17(1),
             new ModE414M17(2),
             new ModE414M17(3),
             new ModE414M17(4),
             new ModE414M17(5),
             new ModE414M17(7),
             new ModE414M17(9),
             new ModE414M17(16),
             new ModE414M17(19),
             new ModE414M17(20)
        };

    public Curve41417ProjectivePointTest() {
        super(coefficients, points, new Curve41417Projective());
    }
}
