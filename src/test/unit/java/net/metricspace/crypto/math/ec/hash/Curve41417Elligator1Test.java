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

import net.metricspace.crypto.math.ec.curve.Curve41417Curve;
import net.metricspace.crypto.math.ec.group.Curve41417Projective;
import net.metricspace.crypto.math.ec.point.Curve41417ProjectivePoint;
import net.metricspace.crypto.math.field.ModE414M17;

public class Curve41417Elligator1Test
    extends Elligator1Test<ModE414M17, Curve41417ProjectivePoint> {
    private static final Curve41417Projective group =
        new Curve41417Projective();

    private static final Curve41417ProjectivePoint BASE_POINT =
        group.basePoint();

    private static final Curve41417ProjectivePoint TWO_POINT =
        group.basePoint();

    private static final Curve41417ProjectivePoint THREE_POINT =
        group.basePoint();

    private static final Curve41417ProjectivePoint FOUR_POINT =
        group.basePoint();

    static {
        TWO_POINT.add(BASE_POINT);
        THREE_POINT.add(TWO_POINT);
        FOUR_POINT.add(THREE_POINT);
    };

    private static final ModE414M17[] encoded =
        new ModE414M17[] {
            null,
            new ModE414M17(new byte[] {
                    (byte)0xba, (byte)0x4d, (byte)0x56, (byte)0xe2,
                    (byte)0x6e, (byte)0x4a, (byte)0xc6, (byte)0xc8,
                    (byte)0x18, (byte)0x10, (byte)0xc4, (byte)0xac,
                    (byte)0xf6, (byte)0xd8, (byte)0x5c, (byte)0xd9,
                    (byte)0x81, (byte)0x15, (byte)0xaa, (byte)0x82,
                    (byte)0xc8, (byte)0x74, (byte)0x7b, (byte)0xae,
                    (byte)0x1a, (byte)0x13, (byte)0xe2, (byte)0xd2,
                    (byte)0x46, (byte)0x6e, (byte)0xc5, (byte)0x62,
                    (byte)0x44, (byte)0x5b, (byte)0x78, (byte)0xc0,
                    (byte)0xe7, (byte)0x6b, (byte)0x69, (byte)0x32,
                    (byte)0x9d, (byte)0x13, (byte)0x4f, (byte)0x23,
                    (byte)0x33, (byte)0xc0, (byte)0xd7, (byte)0x37,
                    (byte)0xbc, (byte)0x89, (byte)0xd7, (byte)0x19
                }),
            null,
            new ModE414M17(new byte[] {
                    (byte)0x7b, (byte)0x7b, (byte)0x25, (byte)0x1e,
                    (byte)0x50, (byte)0xa8, (byte)0x2b, (byte)0x10,
                    (byte)0x1f, (byte)0x7e, (byte)0x33, (byte)0x44,
                    (byte)0x33, (byte)0xda, (byte)0xe5, (byte)0x79,
                    (byte)0xb2, (byte)0xc6, (byte)0xb7, (byte)0x74,
                    (byte)0x9f, (byte)0x49, (byte)0x58, (byte)0xeb,
                    (byte)0x95, (byte)0xd1, (byte)0xde, (byte)0x4a,
                    (byte)0x85, (byte)0x83, (byte)0x6c, (byte)0x54,
                    (byte)0xc5, (byte)0xdc, (byte)0x40, (byte)0x96,
                    (byte)0xad, (byte)0x2c, (byte)0xbb, (byte)0x80,
                    (byte)0x73, (byte)0x56, (byte)0xb8, (byte)0xae,
                    (byte)0xcb, (byte)0xff, (byte)0x13, (byte)0x33,
                    (byte)0xd9, (byte)0x98, (byte)0xb0, (byte)0x06
                })
        };

    private static final Curve41417ProjectivePoint[] points =
        new Curve41417ProjectivePoint[] {
            BASE_POINT,
            TWO_POINT,
            THREE_POINT,
            FOUR_POINT
        };

    public Curve41417Elligator1Test() {
        super(encoded, points, Curve41417Curve.EDWARDS_D_LONG,
              Curve41417Curve.ELLIGATOR_C,
              Curve41417Curve.ELLIGATOR_R,
              Curve41417Curve.ELLIGATOR_S);
    }
}
