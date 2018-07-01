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
import net.metricspace.crypto.math.ec.group.Curve1174DecafProjective;
import net.metricspace.crypto.math.ec.point.Curve1174DecafProjectivePoint;
import net.metricspace.crypto.math.field.ModE251M9;

public class Curve1174DecafProjectivePointTest
    extends DecafPointPropertiesTest<ModE251M9, Curve1174DecafProjectivePoint,
                                     Curve1174DecafProjective> {
    private static final Curve1174DecafProjectivePoint BASE_POINT =
        Curve1174DecafProjectivePoint.fromEdwards(Curve1174.baseX(),
                                                  Curve1174.baseY());

    private static final Curve1174DecafProjectivePoint POINT_TWO =
        BASE_POINT.clone();

    private static final Curve1174DecafProjectivePoint POINT_THREE =
        BASE_POINT.clone();

    static {
        POINT_TWO.add(BASE_POINT);
        POINT_TWO.scale();
        POINT_THREE.add(POINT_TWO);
        POINT_THREE.scale();
    };

    private static final Curve1174DecafProjectivePoint[] points =
        new Curve1174DecafProjectivePoint[] {
            Curve1174DecafProjectivePoint.zero(),
            BASE_POINT,
            POINT_TWO,
            POINT_THREE
        };

    private static final ModE251M9[] compressed =
        new ModE251M9[] {
            new ModE251M9(0),
            new ModE251M9(new byte[] {
                    (byte)0x51, (byte)0x0f, (byte)0x26, (byte)0xbb,
                    (byte)0x85, (byte)0x4b, (byte)0x15, (byte)0x17,
                    (byte)0x03, (byte)0x2e, (byte)0xc0, (byte)0xbc,
                    (byte)0x0e, (byte)0x80, (byte)0x84, (byte)0x46,
                    (byte)0x02, (byte)0x2c, (byte)0xc7, (byte)0x89,
                    (byte)0x7c, (byte)0xc6, (byte)0x0d, (byte)0xe0,
                    (byte)0x67, (byte)0xb3, (byte)0x58, (byte)0x0f,
                    (byte)0xcc, (byte)0xc8, (byte)0xdf, (byte)0x03
                }),
            new ModE251M9(new byte[] {
                    (byte)0x05, (byte)0x18, (byte)0xe2, (byte)0xd0,
                    (byte)0x0d, (byte)0x47, (byte)0x7b, (byte)0xf5,
                    (byte)0x26, (byte)0x99, (byte)0x40, (byte)0xb9,
                    (byte)0x06, (byte)0x55, (byte)0xce, (byte)0x78,
                    (byte)0x60, (byte)0x36, (byte)0x11, (byte)0xef,
                    (byte)0x32, (byte)0x79, (byte)0x89, (byte)0x54,
                    (byte)0x71, (byte)0x87, (byte)0x0d, (byte)0xfd,
                    (byte)0xc5, (byte)0x54, (byte)0x54, (byte)0x02
                }),
            new ModE251M9(new byte[] {
                    (byte)0xe8, (byte)0x97, (byte)0xcf, (byte)0x99,
                    (byte)0x10, (byte)0xb5, (byte)0x84, (byte)0x88,
                    (byte)0xd4, (byte)0xa9, (byte)0x28, (byte)0x67,
                    (byte)0xeb, (byte)0x5d, (byte)0x1f, (byte)0x2c,
                    (byte)0x07, (byte)0x79, (byte)0x9e, (byte)0x7d,
                    (byte)0xd0, (byte)0x57, (byte)0x2c, (byte)0xf1,
                    (byte)0x39, (byte)0x0d, (byte)0xb6, (byte)0x52,
                    (byte)0x4e, (byte)0x6b, (byte)0xe7, (byte)0x03
                })
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

    public Curve1174DecafProjectivePointTest() {
        super(coefficients, points, compressed, new Curve1174DecafProjective());
    }
}
