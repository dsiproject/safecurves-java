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

import net.metricspace.crypto.math.ec.curve.E382Curve;
import net.metricspace.crypto.math.ec.group.E382Projective;
import net.metricspace.crypto.math.ec.point.E382ProjectivePoint;
import net.metricspace.crypto.math.field.ModE382M105;

public class E382Elligator1Test
    extends Elligator1Test<ModE382M105, E382ProjectivePoint> {
    private static final E382Projective group =
        new E382Projective();

    private static final E382ProjectivePoint BASE_POINT =
        group.basePoint();

    private static final E382ProjectivePoint TWO_POINT =
        group.basePoint();

    private static final E382ProjectivePoint THREE_POINT =
        group.basePoint();

    private static final E382ProjectivePoint NINE_POINT =
        group.basePoint();

    static {
        TWO_POINT.add(BASE_POINT);
        THREE_POINT.add(BASE_POINT);
        NINE_POINT.add(THREE_POINT);
        NINE_POINT.add(THREE_POINT);
        NINE_POINT.add(TWO_POINT);
    };

    private static final ModE382M105[] encoded =
        new ModE382M105[] {
            new ModE382M105(new byte[] {
                    (byte)0x3b, (byte)0xf7, (byte)0x8c, (byte)0xca,
                    (byte)0xa1, (byte)0x88, (byte)0x31, (byte)0x29,
                    (byte)0x09, (byte)0xfc, (byte)0xdf, (byte)0x29,
                    (byte)0x5c, (byte)0x1b, (byte)0xab, (byte)0x1e,
                    (byte)0xa5, (byte)0xd1, (byte)0x67, (byte)0xee,
                    (byte)0xb0, (byte)0x8c, (byte)0xce, (byte)0xc9,
                    (byte)0x33, (byte)0x45, (byte)0x22, (byte)0x0d,
                    (byte)0xe9, (byte)0x10, (byte)0x0f, (byte)0x7b,
                    (byte)0x54, (byte)0xcf, (byte)0x2a, (byte)0x9d,
                    (byte)0x3d, (byte)0x95, (byte)0x2e, (byte)0x99,
                    (byte)0x85, (byte)0x7e, (byte)0x99, (byte)0x8d,
                    (byte)0xb1, (byte)0x85, (byte)0x0b, (byte)0x0a
                }),
            null,
            null,
            new ModE382M105(new byte[] {
                    (byte)0xbf, (byte)0xff, (byte)0xc5, (byte)0xb4,
                    (byte)0x14, (byte)0x19, (byte)0x27, (byte)0x8f,
                    (byte)0x6b, (byte)0xfe, (byte)0xf8, (byte)0x62,
                    (byte)0x37, (byte)0xb7, (byte)0x7e, (byte)0x4c,
                    (byte)0x3d, (byte)0xef, (byte)0x0e, (byte)0x8d,
                    (byte)0x6c, (byte)0xd5, (byte)0x55, (byte)0x00,
                    (byte)0x02, (byte)0xf8, (byte)0x63, (byte)0x85,
                    (byte)0xe0, (byte)0x6d, (byte)0x28, (byte)0x25,
                    (byte)0xb7, (byte)0x6e, (byte)0x49, (byte)0x86,
                    (byte)0x0b, (byte)0xef, (byte)0xbc, (byte)0xd0,
                    (byte)0xbd, (byte)0x48, (byte)0x56, (byte)0x56,
                    (byte)0x36, (byte)0xfa, (byte)0x49, (byte)0x05
                }),
        };

    private static final E382ProjectivePoint[] points =
        new E382ProjectivePoint[] {
            BASE_POINT,
            TWO_POINT,
            THREE_POINT,
            NINE_POINT
        };

    public E382Elligator1Test() {
        super(encoded, points, E382Curve.EDWARDS_D_LONG,
              E382Curve.ELLIGATOR_C,
              E382Curve.ELLIGATOR_R,
              E382Curve.ELLIGATOR_S);
    }
}
