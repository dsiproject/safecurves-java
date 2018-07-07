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
import net.metricspace.crypto.math.ec.group.E521Projective;
import net.metricspace.crypto.math.ec.point.E521ProjectivePoint;
import net.metricspace.crypto.math.field.ModE521M1;

public class E521Elligator1Test
    extends Elligator1Test<ModE521M1, E521ProjectivePoint> {
    private static final E521Projective group =
        new E521Projective();

    private static final E521ProjectivePoint BASE_POINT =
        group.basePoint();

    private static final E521ProjectivePoint TWO_POINT =
        group.basePoint();

    private static final E521ProjectivePoint THREE_POINT =
        group.basePoint();

    private static final E521ProjectivePoint FIVE_POINT =
        group.basePoint();

    static {
        TWO_POINT.add(BASE_POINT);
        THREE_POINT.add(BASE_POINT);
        FIVE_POINT.add(TWO_POINT);
        FIVE_POINT.add(TWO_POINT);
    };

    private static final ModE521M1[] encoded =
        new ModE521M1[] {
            new ModE521M1(new byte[] {
                    (byte)0xa3, (byte)0x6f, (byte)0xc0, (byte)0x53,
                    (byte)0x21, (byte)0xed, (byte)0xf4, (byte)0xf0,
                    (byte)0x42, (byte)0x28, (byte)0xd4, (byte)0x90,
                    (byte)0x36, (byte)0x68, (byte)0x65, (byte)0x5d,
                    (byte)0x0f, (byte)0xef, (byte)0x0b, (byte)0x8b,
                    (byte)0xdc, (byte)0x78, (byte)0xd9, (byte)0x4f,
                    (byte)0xcb, (byte)0x0b, (byte)0xcf, (byte)0xfc,
                    (byte)0x19, (byte)0x1c, (byte)0xcc, (byte)0x9d,
                    (byte)0x7e, (byte)0x52, (byte)0x08, (byte)0xbf,
                    (byte)0xef, (byte)0xdb, (byte)0x1a, (byte)0x9e,
                    (byte)0x4c, (byte)0xc0, (byte)0x35, (byte)0x60,
                    (byte)0xf2, (byte)0x54, (byte)0x63, (byte)0x9a,
                    (byte)0x0c, (byte)0x01, (byte)0x7f, (byte)0x32,
                    (byte)0x59, (byte)0x22, (byte)0x21, (byte)0x54,
                    (byte)0x00, (byte)0xbc, (byte)0x0c, (byte)0x38,
                    (byte)0x42, (byte)0xb2, (byte)0x20, (byte)0x31,
                    (byte)0x8e, (byte)0x00
                }),
            null,
            null,
            new ModE521M1(new byte[] {
                    (byte)0x60, (byte)0x88, (byte)0x7a, (byte)0x91,
                    (byte)0xfc, (byte)0xb2, (byte)0x06, (byte)0x04,
                    (byte)0x7d, (byte)0x88, (byte)0x40, (byte)0x97,
                    (byte)0x6c, (byte)0xa9, (byte)0x39, (byte)0x11,
                    (byte)0xb4, (byte)0x77, (byte)0xfc, (byte)0x6c,
                    (byte)0x96, (byte)0x14, (byte)0x59, (byte)0x68,
                    (byte)0xb5, (byte)0x34, (byte)0xb4, (byte)0x96,
                    (byte)0xa7, (byte)0x3a, (byte)0xbe, (byte)0x1c,
                    (byte)0xf5, (byte)0xf6, (byte)0xa3, (byte)0xc5,
                    (byte)0x01, (byte)0xe5, (byte)0x6f, (byte)0x95,
                    (byte)0xbf, (byte)0x68, (byte)0xe2, (byte)0x74,
                    (byte)0x54, (byte)0x47, (byte)0x78, (byte)0x1e,
                    (byte)0xfa, (byte)0xcb, (byte)0xea, (byte)0x97,
                    (byte)0x8a, (byte)0xa3, (byte)0x74, (byte)0x17,
                    (byte)0x1c, (byte)0x27, (byte)0x03, (byte)0xcb,
                    (byte)0x6b, (byte)0x58, (byte)0x40, (byte)0x8e,
                    (byte)0x50, (byte)0x00
                }),
        };

    private static final E521ProjectivePoint[] points =
        new E521ProjectivePoint[] {
            BASE_POINT,
            TWO_POINT,
            THREE_POINT,
            FIVE_POINT
        };

    public E521Elligator1Test() {
        super(encoded, points, E521Curve.EDWARDS_D_LONG,
              E521Curve.ELLIGATOR_C,
              E521Curve.ELLIGATOR_R,
              E521Curve.ELLIGATOR_S);
    }
}
