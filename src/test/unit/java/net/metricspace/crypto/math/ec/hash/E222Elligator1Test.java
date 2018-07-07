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

import net.metricspace.crypto.math.ec.curve.E222Curve;
import net.metricspace.crypto.math.ec.group.E222Projective;
import net.metricspace.crypto.math.ec.point.E222ProjectivePoint;
import net.metricspace.crypto.math.field.ModE222M117;

public class E222Elligator1Test
    extends Elligator1Test<ModE222M117, E222ProjectivePoint> {
    private static final E222Projective group =
        new E222Projective();

    private static final E222ProjectivePoint BASE_POINT =
        group.basePoint();

    private static final E222ProjectivePoint TWO_POINT =
        group.basePoint();

    private static final E222ProjectivePoint THREE_POINT =
        group.basePoint();

    private static final E222ProjectivePoint FIVE_POINT =
        group.basePoint();

    private static final E222ProjectivePoint FOURTEEN_POINT =
        group.basePoint();

    static {
        TWO_POINT.add(BASE_POINT);
        THREE_POINT.add(TWO_POINT);
        FIVE_POINT.add(TWO_POINT);
        FIVE_POINT.add(TWO_POINT);
        FOURTEEN_POINT.add(FIVE_POINT);
        FOURTEEN_POINT.add(FIVE_POINT);
        FOURTEEN_POINT.add(THREE_POINT);
    };

    private static final ModE222M117[] encoded =
        new ModE222M117[] {
            null,
            new ModE222M117(new byte[] {
                    (byte)0x95, (byte)0x25, (byte)0x5f, (byte)0x7c,
                    (byte)0xff, (byte)0x40, (byte)0x1f, (byte)0xf3,
                    (byte)0x62, (byte)0x07, (byte)0xfc, (byte)0x9e,
                    (byte)0x35, (byte)0xe1, (byte)0x7b, (byte)0xa7,
                    (byte)0xba, (byte)0xc0, (byte)0xd9, (byte)0x04,
                    (byte)0x82, (byte)0xb5, (byte)0x96, (byte)0x42,
                    (byte)0xdf, (byte)0x01, (byte)0xbd, (byte)0x0e
                }),
            null,
            new ModE222M117(new byte[] {
                    (byte)0xe3, (byte)0x9b, (byte)0x22, (byte)0x8c,
                    (byte)0x77, (byte)0xf5, (byte)0xda, (byte)0xcf,
                    (byte)0x07, (byte)0xbf, (byte)0x9f, (byte)0x6b,
                    (byte)0x3c, (byte)0xf3, (byte)0x95, (byte)0x79,
                    (byte)0x16, (byte)0x65, (byte)0x26, (byte)0xad,
                    (byte)0x4a, (byte)0x95, (byte)0xb1, (byte)0x89,
                    (byte)0x45, (byte)0x7f, (byte)0x91, (byte)0x13
                }),
            new ModE222M117(new byte[] {
                    (byte)0x07, (byte)0x27, (byte)0x2d, (byte)0x40,
                    (byte)0x19, (byte)0x5a, (byte)0x0c, (byte)0x30,
                    (byte)0xe0, (byte)0xa5, (byte)0x8e, (byte)0xb7,
                    (byte)0x40, (byte)0x56, (byte)0xb5, (byte)0xe9,
                    (byte)0x2b, (byte)0xa3, (byte)0xc8, (byte)0x52,
                    (byte)0x9e, (byte)0xaa, (byte)0xc4, (byte)0x96,
                    (byte)0xbc, (byte)0xee, (byte)0xdf, (byte)0x02
                }),
        };

    private static final E222ProjectivePoint[] points =
        new E222ProjectivePoint[] {
            BASE_POINT,
            TWO_POINT,
            THREE_POINT,
            FIVE_POINT,
            FOURTEEN_POINT
        };

    public E222Elligator1Test() {
        super(encoded, points, E222Curve.EDWARDS_D_LONG,
              E222Curve.ELLIGATOR_C,
              E222Curve.ELLIGATOR_R,
              E222Curve.ELLIGATOR_S);
    }
}
