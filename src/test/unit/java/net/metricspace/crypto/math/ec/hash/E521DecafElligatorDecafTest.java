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

import net.metricspace.crypto.math.ec.curve.E521Curve;
import net.metricspace.crypto.math.ec.group.E521DecafProjective;
import net.metricspace.crypto.math.ec.point.E521DecafProjectivePoint;
import net.metricspace.crypto.math.field.ModE521M1;

public class E521DecafElligatorDecafTest
    extends ElligatorDecafTest<ModE521M1, E521DecafProjectivePoint> {
    private static final E521DecafProjective group =
        new E521DecafProjective();

    private static final E521DecafProjectivePoint BASE_POINT =
        group.basePoint();

    private static final E521DecafProjectivePoint THREE_POINT =
        group.basePoint();

    private static final E521DecafProjectivePoint FIVE_POINT =
        group.basePoint();

    private static final E521DecafProjectivePoint TWENTY_SEVEN_POINT =
        group.basePoint();

    static {
        THREE_POINT.add(BASE_POINT);
        THREE_POINT.add(BASE_POINT);
        FIVE_POINT.add(THREE_POINT);
        FIVE_POINT.add(BASE_POINT);
        TWENTY_SEVEN_POINT.add(FIVE_POINT);
        TWENTY_SEVEN_POINT.add(FIVE_POINT);
        TWENTY_SEVEN_POINT.add(FIVE_POINT);
        TWENTY_SEVEN_POINT.add(FIVE_POINT);
        TWENTY_SEVEN_POINT.add(FIVE_POINT);
        TWENTY_SEVEN_POINT.add(BASE_POINT);
    };

    private static final ModE521M1[] encoded =
        new ModE521M1[] {
            null,
            null,
            new ModE521M1(new byte[] {
                    (byte)0x71, (byte)0x4a, (byte)0x03, (byte)0x9d,
                    (byte)0x47, (byte)0x07, (byte)0xb1, (byte)0x2e,
                    (byte)0x38, (byte)0x59, (byte)0x5a, (byte)0x29,
                    (byte)0x96, (byte)0x12, (byte)0x16, (byte)0xbb,
                    (byte)0x3d, (byte)0xe0, (byte)0x5c, (byte)0xa2,
                    (byte)0xb2, (byte)0xd1, (byte)0xc0, (byte)0x08,
                    (byte)0x46, (byte)0xe2, (byte)0x56, (byte)0x0b,
                    (byte)0x7d, (byte)0x0c, (byte)0x6a, (byte)0xa3,
                    (byte)0xf8, (byte)0x8d, (byte)0x9f, (byte)0x4a,
                    (byte)0x31, (byte)0x66, (byte)0x5f, (byte)0x84,
                    (byte)0x5d, (byte)0x78, (byte)0x5f, (byte)0xc2,
                    (byte)0xdc, (byte)0x10, (byte)0x76, (byte)0x4c,
                    (byte)0x3c, (byte)0x55, (byte)0x4a, (byte)0x0b,
                    (byte)0xd7, (byte)0xd9, (byte)0xe5, (byte)0xfd,
                    (byte)0xad, (byte)0x64, (byte)0x93, (byte)0xe0,
                    (byte)0x6e, (byte)0xec, (byte)0xf5, (byte)0xef,
                    (byte)0x28, (byte)0x01
                }),
            new ModE521M1(new byte[] {
                    (byte)0xcb, (byte)0x7f, (byte)0x4a, (byte)0x87,
                    (byte)0x0c, (byte)0x4b, (byte)0xf9, (byte)0x4f,
                    (byte)0x0c, (byte)0x6b, (byte)0xba, (byte)0xb2,
                    (byte)0xe2, (byte)0x9f, (byte)0x15, (byte)0x16,
                    (byte)0x02, (byte)0xdc, (byte)0x8c, (byte)0xf9,
                    (byte)0x40, (byte)0x9e, (byte)0xe6, (byte)0xb9,
                    (byte)0x93, (byte)0x70, (byte)0x19, (byte)0x2a,
                    (byte)0x6c, (byte)0xcc, (byte)0x6c, (byte)0x01,
                    (byte)0xb8, (byte)0x56, (byte)0x9b, (byte)0x7e,
                    (byte)0xe5, (byte)0x30, (byte)0xe3, (byte)0x7b,
                    (byte)0xc4, (byte)0x55, (byte)0xa1, (byte)0xc1,
                    (byte)0x79, (byte)0xc5, (byte)0x25, (byte)0x31,
                    (byte)0x80, (byte)0xae, (byte)0x7e, (byte)0xc3,
                    (byte)0x57, (byte)0xdd, (byte)0x1d, (byte)0xee,
                    (byte)0xe8, (byte)0x62, (byte)0xd8, (byte)0xb2,
                    (byte)0x78, (byte)0xb9, (byte)0xf7, (byte)0x8d,
                    (byte)0x93, (byte)0x01
                })
        };

    private static final E521DecafProjectivePoint[] points =
        new E521DecafProjectivePoint[] {
            BASE_POINT,
            THREE_POINT,
            FIVE_POINT,
            TWENTY_SEVEN_POINT
        };

    public E521DecafElligatorDecafTest() {
        super(encoded, points);
    }
}
