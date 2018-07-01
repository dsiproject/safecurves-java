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
import net.metricspace.crypto.math.ec.group.E222DecafProjective;
import net.metricspace.crypto.math.ec.point.E222DecafProjectivePoint;
import net.metricspace.crypto.math.field.ModE222M117;

public class E222DecafProjectivePointTest
    extends DecafPointPropertiesTest<ModE222M117, E222DecafProjectivePoint,
                                     E222DecafProjective> {
    private static final E222DecafProjectivePoint BASE_POINT =
        E222DecafProjectivePoint.fromEdwards(E222.baseX(), E222.baseY());

    private static final E222DecafProjectivePoint POINT_TWO =
        BASE_POINT.clone();

    private static final E222DecafProjectivePoint POINT_THREE =
        BASE_POINT.clone();

    static {
        POINT_TWO.add(BASE_POINT);
        POINT_TWO.scale();
        POINT_THREE.add(POINT_TWO);
        POINT_THREE.scale();
    };

    private static final E222DecafProjectivePoint[] points =
        new E222DecafProjectivePoint[] {
            E222DecafProjectivePoint.zero(),
            BASE_POINT,
            POINT_TWO,
            POINT_THREE
        };

    private static final ModE222M117[] compressed =
        new ModE222M117[] {
            new ModE222M117(0),
            new ModE222M117(new byte[] {
                    (byte)0x24, (byte)0x3d, (byte)0x61, (byte)0xb0,
                    (byte)0x4a, (byte)0x8c, (byte)0xe6, (byte)0x79,
                    (byte)0x6a, (byte)0x52, (byte)0x03, (byte)0x0c,
                    (byte)0x30, (byte)0x72, (byte)0x27, (byte)0x81,
                    (byte)0xb0, (byte)0x90, (byte)0x04, (byte)0x23,
                    (byte)0xb1, (byte)0xa6, (byte)0xd3, (byte)0x9f,
                    (byte)0x05, (byte)0xfe, (byte)0x44, (byte)0x02
                }),
            new ModE222M117(new byte[] {
                    (byte)0xa9, (byte)0x61, (byte)0x30, (byte)0xd9,
                    (byte)0x9d, (byte)0x79, (byte)0x97, (byte)0x29,
                    (byte)0x9e, (byte)0x53, (byte)0x59, (byte)0x4b,
                    (byte)0x64, (byte)0xce, (byte)0xe2, (byte)0xbf,
                    (byte)0x66, (byte)0x05, (byte)0xd6, (byte)0x85,
                    (byte)0xa5, (byte)0xdf, (byte)0xe7, (byte)0x3c,
                    (byte)0xde, (byte)0x19, (byte)0x15, (byte)0x0f
                }),
            new ModE222M117(new byte[] {
                    (byte)0xe2, (byte)0x33, (byte)0xec, (byte)0xe9,
                    (byte)0x28, (byte)0xcd, (byte)0xe4, (byte)0xe6,
                    (byte)0x5c, (byte)0x09, (byte)0x07, (byte)0xef,
                    (byte)0x07, (byte)0x82, (byte)0xfc, (byte)0xf5,
                    (byte)0x28, (byte)0x73, (byte)0x55, (byte)0x7f,
                    (byte)0x8b, (byte)0x4d, (byte)0xe9, (byte)0x3f,
                    (byte)0x58, (byte)0x4f, (byte)0xda, (byte)0x1d
                })
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

    public E222DecafProjectivePointTest() {
        super(coefficients, points, compressed, new E222DecafProjective());
    }
}
