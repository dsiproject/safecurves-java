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

import net.metricspace.crypto.math.ec.curve.M221Curve;
import net.metricspace.crypto.math.ec.group.M221Projective;
import net.metricspace.crypto.math.ec.point.M221ProjectivePoint;
import net.metricspace.crypto.math.field.ModE221M3;

public class M221Elligator2Test
    extends Elligator2Test<ModE221M3, M221ProjectivePoint> {
    private static final M221Projective group =
        new M221Projective();

    private static final M221ProjectivePoint BASE_POINT =
        group.basePoint();

    private static final M221ProjectivePoint TWO_POINT =
        group.basePoint();

    private static final M221ProjectivePoint FOUR_POINT =
        group.basePoint();

    private static final M221ProjectivePoint FIVE_POINT =
        group.basePoint();

    private static final M221ProjectivePoint SIX_POINT =
        group.basePoint();

    static {
        TWO_POINT.add(BASE_POINT);
        FOUR_POINT.add(BASE_POINT);
        FOUR_POINT.add(TWO_POINT);
        FIVE_POINT.add(FOUR_POINT);
        SIX_POINT.add(FIVE_POINT);
    };

    private static final ModE221M3[] encoded =
        new ModE221M3[] {
            null,
            null,
            null,
            new ModE221M3(new byte[] {
                    (byte)0xb7, (byte)0xff, (byte)0x66, (byte)0xf3,
                    (byte)0x31, (byte)0xb6, (byte)0x19, (byte)0x9b,
                    (byte)0x73, (byte)0xfe, (byte)0x30, (byte)0x26,
                    (byte)0x69, (byte)0x83, (byte)0xe2, (byte)0x3b,
                    (byte)0x85, (byte)0x2b, (byte)0x2d, (byte)0x62,
                    (byte)0x55, (byte)0x96, (byte)0x39, (byte)0xa7,
                    (byte)0xc7, (byte)0x71, (byte)0x48, (byte)0x0c
                }),
            new ModE221M3(new byte[] {
                    (byte)0x78, (byte)0x50, (byte)0x9c, (byte)0xe7,
                    (byte)0x86, (byte)0xd6, (byte)0x45, (byte)0x9a,
                    (byte)0xdd, (byte)0xcc, (byte)0xdb, (byte)0x0d,
                    (byte)0xf8, (byte)0xb1, (byte)0x4f, (byte)0x1e,
                    (byte)0xc1, (byte)0x7b, (byte)0x4f, (byte)0x17,
                    (byte)0x27, (byte)0xa9, (byte)0x51, (byte)0x80,
                    (byte)0x96, (byte)0xba, (byte)0x04, (byte)0x03
                })
        };

    private static final M221ProjectivePoint[] points =
        new M221ProjectivePoint[] {
            BASE_POINT,
            TWO_POINT,
            FOUR_POINT,
            FIVE_POINT,
            SIX_POINT
        };

    public M221Elligator2Test() {
        super(encoded, points);
    }
}
