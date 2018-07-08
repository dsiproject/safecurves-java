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
import net.metricspace.crypto.math.ec.group.Curve1174DecafProjective;
import net.metricspace.crypto.math.ec.point.Curve1174DecafProjectivePoint;
import net.metricspace.crypto.math.field.ModE251M9;

public class Curve1174DecafElligatorDecafTest
    extends ElligatorDecafTest<ModE251M9, Curve1174DecafProjectivePoint> {
    private static final Curve1174DecafProjective group =
        new Curve1174DecafProjective();

    private static final Curve1174DecafProjectivePoint BASE_POINT =
        group.basePoint();

    private static final Curve1174DecafProjectivePoint TWO_POINT =
        group.basePoint();

    private static final Curve1174DecafProjectivePoint FOUR_POINT =
        group.basePoint();

    private static final Curve1174DecafProjectivePoint FIVE_POINT =
        group.basePoint();

    static {
        TWO_POINT.add(BASE_POINT);
        FOUR_POINT.add(TWO_POINT);
        FOUR_POINT.add(BASE_POINT);
        FIVE_POINT.add(FOUR_POINT);
    };

    private static final ModE251M9[] encoded =
        new ModE251M9[] {
            null,
            new ModE251M9(new byte[] {
                    (byte)0xa3, (byte)0xd1, (byte)0xe6, (byte)0x6c,
                    (byte)0xac, (byte)0xac, (byte)0x04, (byte)0x3e,
                    (byte)0xec, (byte)0x39, (byte)0x56, (byte)0xcc,
                    (byte)0x15, (byte)0xc1, (byte)0x11, (byte)0x23,
                    (byte)0xbb, (byte)0x5a, (byte)0x62, (byte)0x37,
                    (byte)0xd4, (byte)0x6b, (byte)0x75, (byte)0x3a,
                    (byte)0x69, (byte)0x82, (byte)0xcf, (byte)0x93,
                    (byte)0x73, (byte)0x51, (byte)0x1b, (byte)0x02
                }),
            new ModE251M9(new byte[] {
                    (byte)0xef, (byte)0x7d, (byte)0x54, (byte)0x72,
                    (byte)0x69, (byte)0x10, (byte)0x18, (byte)0xcb,
                    (byte)0x93, (byte)0xf4, (byte)0x38, (byte)0x92,
                    (byte)0xc0, (byte)0x1d, (byte)0x67, (byte)0xfc,
                    (byte)0xcc, (byte)0xac, (byte)0xad, (byte)0x16,
                    (byte)0xe3, (byte)0xac, (byte)0x91, (byte)0x0a,
                    (byte)0xf2, (byte)0x66, (byte)0xa1, (byte)0xf4,
                    (byte)0x18, (byte)0x2c, (byte)0x8b, (byte)0x01
                }),
            null
        };

    private static final Curve1174DecafProjectivePoint[] points =
        new Curve1174DecafProjectivePoint[] {
            BASE_POINT,
            TWO_POINT,
            FOUR_POINT,
            FIVE_POINT
        };

    public Curve1174DecafElligatorDecafTest() {
        super(encoded, points);
    }
}
