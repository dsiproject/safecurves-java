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

import net.metricspace.crypto.math.ec.group.Curve25519;
import net.metricspace.crypto.math.ec.group.Curve25519Extended;
import net.metricspace.crypto.math.ec.point.Curve25519ExtendedPoint;
import net.metricspace.crypto.math.field.ModE255M19;

public class Curve25519ExtendedPointTest
    extends MontgomeryPointPropertiesTest<ModE255M19, Curve25519ExtendedPoint,
                                          Curve25519Extended> {
    private static final Curve25519ExtendedPoint[] points =
        new Curve25519ExtendedPoint[] {
            Curve25519ExtendedPoint.zero(),
            Curve25519ExtendedPoint.fromMontgomery(Curve25519.baseX(),
                                                   Curve25519.baseY())
        };

    private static final ModE255M19[] coefficients =
        new ModE255M19[] {
             new ModE255M19(1),
             new ModE255M19(2),
             new ModE255M19(3),
             new ModE255M19(4),
             new ModE255M19(5),
             new ModE255M19(7),
             new ModE255M19(9),
             new ModE255M19(16),
             new ModE255M19(19),
             new ModE255M19(20)
        };

    public Curve25519ExtendedPointTest() {
        super(coefficients, points, new Curve25519Extended());
    }
}
