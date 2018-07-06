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

import net.metricspace.crypto.math.ec.curve.M511Curve;
import net.metricspace.crypto.math.ec.group.M511Projective;
import net.metricspace.crypto.math.ec.point.M511ProjectivePoint;
import net.metricspace.crypto.math.field.ModE511M187;

public class M511Elligator2Test
    extends Elligator2Test<ModE511M187, M511ProjectivePoint> {
    private static final M511Projective group =
        new M511Projective();

    private static final M511ProjectivePoint BASE_POINT =
        group.basePoint();

    private static final M511ProjectivePoint THREE_POINT =
        group.basePoint();

    private static final M511ProjectivePoint SIX_POINT =
        group.basePoint();

    private static final M511ProjectivePoint NINE_POINT =
        group.basePoint();

    static {
        THREE_POINT.add(BASE_POINT);
        THREE_POINT.add(BASE_POINT);
        SIX_POINT.add(BASE_POINT);
        SIX_POINT.add(BASE_POINT);
        SIX_POINT.add(THREE_POINT);
        NINE_POINT.add(BASE_POINT);
        NINE_POINT.add(BASE_POINT);
        NINE_POINT.add(SIX_POINT);
    };

    private static final ModE511M187[] encoded =
        new ModE511M187[] {
            new ModE511M187(new byte[] {
                    (byte)0x67, (byte)0x9b, (byte)0x19, (byte)0x34,
                    (byte)0x17, (byte)0x48, (byte)0x1a, (byte)0xfb,
                    (byte)0x2f, (byte)0xf9, (byte)0x66, (byte)0x53,
                    (byte)0x7b, (byte)0xb6, (byte)0x4c, (byte)0xaa,
                    (byte)0x49, (byte)0x07, (byte)0x66, (byte)0x94,
                    (byte)0xdf, (byte)0x35, (byte)0x77, (byte)0x45,
                    (byte)0x77, (byte)0x1e, (byte)0xd3, (byte)0xa2,
                    (byte)0xc2, (byte)0x4e, (byte)0xf2, (byte)0xa9,
                    (byte)0x8a, (byte)0x8d, (byte)0xd9, (byte)0x35,
                    (byte)0x2b, (byte)0x56, (byte)0xf2, (byte)0x2d,
                    (byte)0x33, (byte)0x4b, (byte)0xdf, (byte)0x87,
                    (byte)0x12, (byte)0xe9, (byte)0xd0, (byte)0xdd,
                    (byte)0x05, (byte)0x35, (byte)0x59, (byte)0x24,
                    (byte)0xf7, (byte)0x1c, (byte)0xea, (byte)0xea,
                    (byte)0x6f, (byte)0xff, (byte)0x21, (byte)0x62,
                    (byte)0xb3, (byte)0xac, (byte)0xe9, (byte)0x06
                }),
            null,
            null,
            new ModE511M187(new byte[] {
                    (byte)0xd1, (byte)0xd1, (byte)0xcb, (byte)0xd6,
                    (byte)0xa1, (byte)0x96, (byte)0xe2, (byte)0x7a,
                    (byte)0x4d, (byte)0xd9, (byte)0x2b, (byte)0xac,
                    (byte)0x98, (byte)0x49, (byte)0x84, (byte)0xb5,
                    (byte)0xea, (byte)0x3a, (byte)0xc2, (byte)0xab,
                    (byte)0xa4, (byte)0x84, (byte)0x43, (byte)0x9a,
                    (byte)0x9b, (byte)0xbf, (byte)0x0f, (byte)0x13,
                    (byte)0x7e, (byte)0xa7, (byte)0xc4, (byte)0x28,
                    (byte)0x73, (byte)0x2f, (byte)0x4d, (byte)0xbf,
                    (byte)0xe1, (byte)0x24, (byte)0x28, (byte)0xe0,
                    (byte)0x64, (byte)0xf1, (byte)0x89, (byte)0x74,
                    (byte)0x0b, (byte)0xd4, (byte)0xa8, (byte)0xcb,
                    (byte)0xd9, (byte)0x80, (byte)0xe5, (byte)0xaf,
                    (byte)0x7e, (byte)0x23, (byte)0x0a, (byte)0xed,
                    (byte)0x7b, (byte)0x13, (byte)0x0d, (byte)0xee,
                    (byte)0x92, (byte)0xa4, (byte)0x08, (byte)0x66
                })
        };

    private static final M511ProjectivePoint[] points =
        new M511ProjectivePoint[] {
            BASE_POINT,
            THREE_POINT,
            SIX_POINT,
            NINE_POINT
        };

    public M511Elligator2Test() {
        super(encoded, points);
    }
}
