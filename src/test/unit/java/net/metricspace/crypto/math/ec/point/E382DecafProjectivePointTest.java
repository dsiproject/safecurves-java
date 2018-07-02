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

import net.metricspace.crypto.math.ec.group.E382;
import net.metricspace.crypto.math.ec.group.E382DecafProjective;
import net.metricspace.crypto.math.ec.point.E382DecafProjectivePoint;
import net.metricspace.crypto.math.field.ModE382M105;

public class E382DecafProjectivePointTest
    extends DecafPointPropertiesTest<ModE382M105, E382DecafProjectivePoint,
                                     E382DecafProjective> {
    private static final E382DecafProjectivePoint BASE_POINT =
        E382DecafProjectivePoint.fromEdwards(E382.baseX(), E382.baseY());

    private static final E382DecafProjectivePoint POINT_TWO =
        BASE_POINT.clone();

    private static final E382DecafProjectivePoint POINT_THREE =
        BASE_POINT.clone();

    static {
        POINT_TWO.add(BASE_POINT);
        POINT_TWO.scale();
        POINT_THREE.add(POINT_TWO);
        POINT_THREE.scale();
    };

    private static final E382DecafProjectivePoint[] points =
        new E382DecafProjectivePoint[] {
            E382DecafProjectivePoint.zero(),
            BASE_POINT,
            POINT_TWO,
            POINT_THREE
        };

    private static final ModE382M105[] compressed =
        new ModE382M105[] {
            new ModE382M105(0),
            new ModE382M105(new byte[] {
                    (byte)0x45, (byte)0x5c, (byte)0xf9, (byte)0x95,
                    (byte)0x9c, (byte)0x78, (byte)0x69, (byte)0x6d,
                    (byte)0x73, (byte)0x23, (byte)0x0a, (byte)0x56,
                    (byte)0xb7, (byte)0xba, (byte)0x7c, (byte)0x7c,
                    (byte)0x4d, (byte)0x84, (byte)0xc4, (byte)0x38,
                    (byte)0x8d, (byte)0x2f, (byte)0x8b, (byte)0x17,
                    (byte)0xd6, (byte)0x99, (byte)0x6b, (byte)0xea,
                    (byte)0xd0, (byte)0xfe, (byte)0x5a, (byte)0x91,
                    (byte)0xc9, (byte)0xd4, (byte)0x35, (byte)0x5d,
                    (byte)0xea, (byte)0xd6, (byte)0x84, (byte)0xe4,
                    (byte)0x43, (byte)0x40, (byte)0x6a, (byte)0x9e,
                    (byte)0x46, (byte)0x05, (byte)0x0c, (byte)0x00
                }),
            new ModE382M105(new byte[] {
                    (byte)0x89, (byte)0x85, (byte)0x49, (byte)0x41,
                    (byte)0x69, (byte)0x5e, (byte)0xd8, (byte)0x1b,
                    (byte)0xeb, (byte)0x43, (byte)0x0d, (byte)0x2b,
                    (byte)0xb7, (byte)0x4b, (byte)0xf2, (byte)0xe9,
                    (byte)0xd6, (byte)0x70, (byte)0x0c, (byte)0x61,
                    (byte)0x60, (byte)0xbd, (byte)0xa3, (byte)0x53,
                    (byte)0x4d, (byte)0x79, (byte)0x0d, (byte)0x58,
                    (byte)0xfe, (byte)0x3e, (byte)0xdd, (byte)0xf9,
                    (byte)0xfc, (byte)0x90, (byte)0x3f, (byte)0x1b,
                    (byte)0x5e, (byte)0xad, (byte)0xca, (byte)0x31,
                    (byte)0x97, (byte)0x74, (byte)0xcf, (byte)0xb5,
                    (byte)0x0a, (byte)0x9a, (byte)0xce, (byte)0x1f
                }),
            new ModE382M105(new byte[] {
                    (byte)0x84, (byte)0xd0, (byte)0xd5, (byte)0xe1,
                    (byte)0xe8, (byte)0x9d, (byte)0xfe, (byte)0xe7,
                    (byte)0x69, (byte)0xac, (byte)0x3d, (byte)0x5a,
                    (byte)0x54, (byte)0x23, (byte)0xf4, (byte)0x6c,
                    (byte)0xed, (byte)0x00, (byte)0x24, (byte)0x35,
                    (byte)0x6c, (byte)0xc3, (byte)0x58, (byte)0x17,
                    (byte)0x12, (byte)0x99, (byte)0x14, (byte)0x5c,
                    (byte)0xc8, (byte)0x9f, (byte)0xa3, (byte)0x45,
                    (byte)0x28, (byte)0xad, (byte)0xdb, (byte)0xce,
                    (byte)0x59, (byte)0x8c, (byte)0xd9, (byte)0x55,
                    (byte)0xd2, (byte)0x00, (byte)0x5a, (byte)0x32,
                    (byte)0x89, (byte)0x66, (byte)0xdf, (byte)0x0a
                })
        };

    private static final ModE382M105[] coefficients =
        new ModE382M105[] {
             new ModE382M105(1),
             new ModE382M105(2),
             new ModE382M105(3),
             new ModE382M105(4),
             new ModE382M105(5),
             new ModE382M105(7),
             new ModE382M105(9),
             new ModE382M105(16),
             new ModE382M105(19),
             new ModE382M105(20)
        };

    public E382DecafProjectivePointTest() {
        super(coefficients, points, compressed, new E382DecafProjective());
    }
}
