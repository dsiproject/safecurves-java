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

import net.metricspace.crypto.math.ec.curve.M383Curve;
import net.metricspace.crypto.math.ec.group.M383Projective;
import net.metricspace.crypto.math.ec.point.M383ProjectivePoint;
import net.metricspace.crypto.math.field.ModE383M187;

public class M383Elligator2Test
    extends Elligator2Test<ModE383M187, M383ProjectivePoint> {
    private static final M383Projective group =
        new M383Projective();

    private static final M383ProjectivePoint BASE_POINT =
        group.basePoint();

    private static final M383ProjectivePoint THREE_POINT =
        group.basePoint();

    private static final M383ProjectivePoint FOUR_POINT =
        group.basePoint();

    private static final M383ProjectivePoint SEVEN_POINT =
        group.basePoint();

    static {
        THREE_POINT.add(BASE_POINT);
        THREE_POINT.add(BASE_POINT);
        FOUR_POINT.add(THREE_POINT);
        SEVEN_POINT.add(THREE_POINT);
        SEVEN_POINT.add(THREE_POINT);
    };

    private static final ModE383M187[] encoded =
        new ModE383M187[] {
            new ModE383M187(new byte[] {
                    (byte)0xfa, (byte)0xd6, (byte)0x53, (byte)0xb5,
                    (byte)0x06, (byte)0x3b, (byte)0x40, (byte)0x4e,
                    (byte)0x24, (byte)0xc1, (byte)0x5c, (byte)0x4f,
                    (byte)0x50, (byte)0x0a, (byte)0x5c, (byte)0xd8,
                    (byte)0x4b, (byte)0xa2, (byte)0xad, (byte)0x5b,
                    (byte)0x2c, (byte)0x98, (byte)0x21, (byte)0x8b,
                    (byte)0x3b, (byte)0x5a, (byte)0xf5, (byte)0xd0,
                    (byte)0x37, (byte)0xdd, (byte)0xfc, (byte)0x51,
                    (byte)0x1a, (byte)0x31, (byte)0x9b, (byte)0xae,
                    (byte)0x0a, (byte)0x36, (byte)0xd9, (byte)0x3d,
                    (byte)0x2c, (byte)0x8d, (byte)0xe6, (byte)0x0b,
                    (byte)0xb8, (byte)0x6f, (byte)0x59, (byte)0x19
                }),
            null,
            new ModE383M187(new byte[] {
                    (byte)0x82, (byte)0xc5, (byte)0x55, (byte)0x76,
                    (byte)0xc2, (byte)0x0f, (byte)0xc5, (byte)0xc5,
                    (byte)0xc3, (byte)0x29, (byte)0x43, (byte)0x27,
                    (byte)0xe6, (byte)0x72, (byte)0x99, (byte)0x1d,
                    (byte)0x9b, (byte)0xe5, (byte)0xd5, (byte)0x01,
                    (byte)0xa4, (byte)0x9f, (byte)0x67, (byte)0x93,
                    (byte)0x14, (byte)0x1a, (byte)0x0e, (byte)0xac,
                    (byte)0xc0, (byte)0xd9, (byte)0xeb, (byte)0x6a,
                    (byte)0x03, (byte)0x42, (byte)0x82, (byte)0x5d,
                    (byte)0x11, (byte)0xf7, (byte)0xff, (byte)0x5b,
                    (byte)0x44, (byte)0xf9, (byte)0xfc, (byte)0xc1,
                    (byte)0x30, (byte)0x1b, (byte)0x57, (byte)0x4e
                }),
            null
        };

    private static final M383ProjectivePoint[] points =
        new M383ProjectivePoint[] {
            BASE_POINT,
            THREE_POINT,
            FOUR_POINT,
            SEVEN_POINT
        };

    public M383Elligator2Test() {
        super(encoded, points);
    }
}
