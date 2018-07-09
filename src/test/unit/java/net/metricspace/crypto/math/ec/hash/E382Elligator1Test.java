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

    private static final E382ProjectivePoint FOUR_POINT =
        group.basePoint();

    static {
        TWO_POINT.add(BASE_POINT);
        THREE_POINT.add(TWO_POINT);
        FOUR_POINT.add(THREE_POINT);
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
            new ModE382M105(new byte[] {
                    (byte)0x85, (byte)0x9a, (byte)0x3e, (byte)0x08,
                    (byte)0x96, (byte)0x16, (byte)0x90, (byte)0x97,
                    (byte)0x9e, (byte)0x31, (byte)0x27, (byte)0x47,
                    (byte)0x24, (byte)0xc8, (byte)0x4a, (byte)0xa6,
                    (byte)0x29, (byte)0xcb, (byte)0xfe, (byte)0xc0,
                    (byte)0xb2, (byte)0xc1, (byte)0x12, (byte)0x48,
                    (byte)0xae, (byte)0x3b, (byte)0x66, (byte)0xe9,
                    (byte)0x70, (byte)0x5f, (byte)0x0c, (byte)0xa4,
                    (byte)0xa4, (byte)0x6e, (byte)0xcf, (byte)0x69,
                    (byte)0x3f, (byte)0x12, (byte)0x44, (byte)0x40,
                    (byte)0x54, (byte)0x0f, (byte)0xba, (byte)0x20,
                    (byte)0x49, (byte)0xac, (byte)0x81, (byte)0x01
                }),
            null
        };

    private static final E382ProjectivePoint[] points =
        new E382ProjectivePoint[] {
            BASE_POINT,
            TWO_POINT,
            THREE_POINT,
            FOUR_POINT
        };

    public E382Elligator1Test() {
        super(encoded, points, E382Curve.EDWARDS_D_LONG,
              E382Curve.ELLIGATOR_C,
              E382Curve.ELLIGATOR_R,
              E382Curve.ELLIGATOR_S);
    }
}
