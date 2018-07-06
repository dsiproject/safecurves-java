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

import net.metricspace.crypto.math.ec.curve.Curve1174Curve;
import net.metricspace.crypto.math.ec.group.Curve1174Projective;
import net.metricspace.crypto.math.ec.point.Curve1174ProjectivePoint;
import net.metricspace.crypto.math.field.ModE251M9;

public class Curve1174Elligator1Test
    extends Elligator1Test<ModE251M9, Curve1174ProjectivePoint> {
    private static final Curve1174Projective group =
        new Curve1174Projective();

    private static final Curve1174ProjectivePoint BASE_POINT =
        group.basePoint();

    private static final Curve1174ProjectivePoint TWO_POINT =
        group.basePoint();

    private static final Curve1174ProjectivePoint THREE_POINT =
        group.basePoint();

    private static final Curve1174ProjectivePoint SEVEN_POINT =
        group.basePoint();

    static {
        TWO_POINT.add(BASE_POINT);
        THREE_POINT.add(TWO_POINT);
        SEVEN_POINT.add(THREE_POINT);
        SEVEN_POINT.add(THREE_POINT);
    };

    private static final ModE251M9[] encoded =
        new ModE251M9[] {
            new ModE251M9(new byte[] {
                    (byte)0xb5, (byte)0x8a, (byte)0x4e, (byte)0x2e,
                    (byte)0x85, (byte)0x15, (byte)0x33, (byte)0xbe,
                    (byte)0x5c, (byte)0x77, (byte)0xb9, (byte)0xfe,
                    (byte)0x0c, (byte)0x41, (byte)0x77, (byte)0x45,
                    (byte)0x82, (byte)0x0e, (byte)0x63, (byte)0xb9,
                    (byte)0x56, (byte)0x3f, (byte)0x30, (byte)0x3b,
                    (byte)0x57, (byte)0x24, (byte)0xa6, (byte)0x8a,
                    (byte)0x22, (byte)0x79, (byte)0x55, (byte)0x03
                }),
            null,
            null,
            new ModE251M9(new byte[] {
                    (byte)0x9a, (byte)0xf2, (byte)0xcf, (byte)0xcd,
                    (byte)0x8b, (byte)0x16, (byte)0x23, (byte)0xea,
                    (byte)0xf1, (byte)0x5a, (byte)0x5d, (byte)0x95,
                    (byte)0xbd, (byte)0x05, (byte)0x66, (byte)0x86,
                    (byte)0x0a, (byte)0x6f, (byte)0x02, (byte)0xfc,
                    (byte)0x3d, (byte)0xa4, (byte)0x1f, (byte)0x76,
                    (byte)0x1c, (byte)0x1e, (byte)0x24, (byte)0xde,
                    (byte)0x28, (byte)0xd2, (byte)0x7e, (byte)0x01
                })
        };

    private static final Curve1174ProjectivePoint[] points =
        new Curve1174ProjectivePoint[] {
            BASE_POINT,
            TWO_POINT,
            THREE_POINT,
            SEVEN_POINT
        };

    public Curve1174Elligator1Test() {
        super(encoded, points, Curve1174Curve.EDWARDS_D_LONG,
              Curve1174Curve.ELLIGATOR_C,
              Curve1174Curve.ELLIGATOR_R,
              Curve1174Curve.ELLIGATOR_S);
    }
}
