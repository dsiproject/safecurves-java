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

import net.metricspace.crypto.math.ec.group.E521;
import net.metricspace.crypto.math.ec.group.E521DecafExtended;
import net.metricspace.crypto.math.ec.point.E521DecafExtendedPoint;
import net.metricspace.crypto.math.field.ModE521M1;

public class E521DecafExtendedPointTest
    extends DecafPointPropertiesTest<ModE521M1, E521DecafExtendedPoint,
                                     E521DecafExtended> {
    private static final E521DecafExtendedPoint BASE_POINT =
        E521DecafExtendedPoint.fromEdwards(E521.baseX(), E521.baseY());

    private static final E521DecafExtendedPoint POINT_TWO =
        BASE_POINT.clone();

    private static final E521DecafExtendedPoint POINT_THREE =
        BASE_POINT.clone();

    static {
        POINT_TWO.add(BASE_POINT);
        POINT_TWO.scale();
        POINT_THREE.add(POINT_TWO);
        POINT_THREE.scale();
    };

    private static final E521DecafExtendedPoint[] points =
        new E521DecafExtendedPoint[] {
            E521DecafExtendedPoint.zero(),
            BASE_POINT,
            POINT_TWO,
            POINT_THREE
        };

    private static final ModE521M1[] compressed =
        new ModE521M1[] {
            new ModE521M1(0),
            new ModE521M1(new byte[] {
                    (byte)0xd1, (byte)0x62, (byte)0xae, (byte)0xe0,
                    (byte)0x0b, (byte)0xb7, (byte)0x4a, (byte)0xf5,
                    (byte)0xb3, (byte)0x23, (byte)0x60, (byte)0xf9,
                    (byte)0x45, (byte)0x6e, (byte)0x4b, (byte)0x69,
                    (byte)0xe0, (byte)0x68, (byte)0x41, (byte)0x01,
                    (byte)0xbe, (byte)0xc1, (byte)0x00, (byte)0xdb,
                    (byte)0x9f, (byte)0x52, (byte)0xd9, (byte)0x4b,
                    (byte)0x26, (byte)0x6f, (byte)0x6d, (byte)0xeb,
                    (byte)0x5e, (byte)0xad, (byte)0x25, (byte)0x61,
                    (byte)0xe2, (byte)0xc1, (byte)0x3a, (byte)0x14,
                    (byte)0xf8, (byte)0x3c, (byte)0xd6, (byte)0xf4,
                    (byte)0xba, (byte)0x53, (byte)0x4a, (byte)0xc4,
                    (byte)0xbc, (byte)0x92, (byte)0x3d, (byte)0x7d,
                    (byte)0xb9, (byte)0xe4, (byte)0xed, (byte)0xfd,
                    (byte)0x61, (byte)0xe6, (byte)0xa9, (byte)0x90,
                    (byte)0x98, (byte)0xfc, (byte)0x96, (byte)0x6c,
                    (byte)0x8a, (byte)0x00
                }),
            new ModE521M1(new byte[] {
                    (byte)0xcc, (byte)0x85, (byte)0x68, (byte)0xd1,
                    (byte)0xa9, (byte)0x73, (byte)0xfc, (byte)0x7b,
                    (byte)0x9c, (byte)0x50, (byte)0xcf, (byte)0x10,
                    (byte)0x69, (byte)0x40, (byte)0xd9, (byte)0x4d,
                    (byte)0x4d, (byte)0x88, (byte)0x04, (byte)0x74,
                    (byte)0xe3, (byte)0xf2, (byte)0xc8, (byte)0x86,
                    (byte)0x46, (byte)0xa6, (byte)0x67, (byte)0xef,
                    (byte)0x2e, (byte)0x9a, (byte)0xc1, (byte)0x00,
                    (byte)0xe9, (byte)0xa5, (byte)0xd2, (byte)0x44,
                    (byte)0x85, (byte)0x04, (byte)0x01, (byte)0x9f,
                    (byte)0x41, (byte)0x53, (byte)0x6f, (byte)0xaf,
                    (byte)0xa6, (byte)0x2b, (byte)0x03, (byte)0xb0,
                    (byte)0x47, (byte)0x4b, (byte)0x67, (byte)0x8c,
                    (byte)0x7c, (byte)0x46, (byte)0x94, (byte)0x80,
                    (byte)0x9d, (byte)0x68, (byte)0xf4, (byte)0x4c,
                    (byte)0x4f, (byte)0xf8, (byte)0xf0, (byte)0xe6,
                    (byte)0xa0, (byte)0x00
                }),
            new ModE521M1(new byte[] {
                    (byte)0xa7, (byte)0x3c, (byte)0x5b, (byte)0xfc,
                    (byte)0xc9, (byte)0x6d, (byte)0x2f, (byte)0x5b,
                    (byte)0x9b, (byte)0xb6, (byte)0x37, (byte)0xd2,
                    (byte)0x92, (byte)0xd0, (byte)0x66, (byte)0xb5,
                    (byte)0x4c, (byte)0x94, (byte)0xc1, (byte)0x9f,
                    (byte)0x18, (byte)0xf0, (byte)0xdc, (byte)0x67,
                    (byte)0x80, (byte)0x9f, (byte)0xae, (byte)0x7e,
                    (byte)0xee, (byte)0x6a, (byte)0x14, (byte)0x0c,
                    (byte)0x1c, (byte)0x28, (byte)0x2e, (byte)0x27,
                    (byte)0x09, (byte)0xed, (byte)0x0c, (byte)0xeb,
                    (byte)0xf9, (byte)0xed, (byte)0x1c, (byte)0x66,
                    (byte)0xf0, (byte)0x75, (byte)0xba, (byte)0x6a,
                    (byte)0x12, (byte)0x0a, (byte)0xc7, (byte)0x98,
                    (byte)0x7d, (byte)0x86, (byte)0xce, (byte)0x54,
                    (byte)0x6b, (byte)0xdb, (byte)0x91, (byte)0x6c,
                    (byte)0x5d, (byte)0x4f, (byte)0x99, (byte)0x01,
                    (byte)0xca, (byte)0x00
                })
        };

    private static final ModE521M1[] coefficients =
        new ModE521M1[] {
             new ModE521M1(1),
             new ModE521M1(2),
             new ModE521M1(3),
             new ModE521M1(4),
             new ModE521M1(5),
             new ModE521M1(7),
             new ModE521M1(9),
             new ModE521M1(16),
             new ModE521M1(19),
             new ModE521M1(20)
        };

    public E521DecafExtendedPointTest() {
        super(coefficients, points, compressed, new E521DecafExtended());
    }
}
