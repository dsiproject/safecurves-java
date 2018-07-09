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

import net.metricspace.crypto.math.ec.curve.Curve25519Curve;
import net.metricspace.crypto.math.ec.group.Curve25519Projective;
import net.metricspace.crypto.math.ec.point.Curve25519ProjectivePoint;
import net.metricspace.crypto.math.field.ModE255M19;

public class Curve25519Elligator2Test
    extends Elligator2Test<ModE255M19, Curve25519ProjectivePoint> {
    private static final Curve25519Projective group =
        new Curve25519Projective();

    private static final Curve25519ProjectivePoint BASE_POINT =
        group.basePoint();

    private static final Curve25519ProjectivePoint TWO_POINT =
        group.basePoint();

    private static final Curve25519ProjectivePoint THREE_POINT =
        group.basePoint();

    private static final Curve25519ProjectivePoint FIVE_POINT =
        group.basePoint();

    private static final Curve25519ProjectivePoint TEN_POINT =
        group.basePoint();

    static {
        TWO_POINT.add(BASE_POINT);
        THREE_POINT.add(TWO_POINT);
        FIVE_POINT.add(TWO_POINT);
        FIVE_POINT.add(TWO_POINT);
        TEN_POINT.add(THREE_POINT);
        TEN_POINT.add(THREE_POINT);
        TEN_POINT.add(THREE_POINT);
    };

    private static final ModE255M19[] encoded =
        new ModE255M19[] {
            new ModE255M19(new byte[] {
                    (byte)0x88, (byte)0x72, (byte)0x7d, (byte)0x0d,
                    (byte)0xbc, (byte)0xff, (byte)0xdf, (byte)0x71,
                    (byte)0x8d, (byte)0x64, (byte)0xf5, (byte)0xd8,
                    (byte)0x9a, (byte)0x4f, (byte)0x31, (byte)0xe2,
                    (byte)0x83, (byte)0x50, (byte)0x92, (byte)0x71,
                    (byte)0xe0, (byte)0x21, (byte)0x56, (byte)0xc9,
                    (byte)0x39, (byte)0x87, (byte)0x6d, (byte)0x5d,
                    (byte)0x55, (byte)0xbe, (byte)0x7a, (byte)0x31
                }),
            null,
            new ModE255M19(new byte[] {
                    (byte)0xc5, (byte)0xa8, (byte)0x65, (byte)0xc3,
                    (byte)0x33, (byte)0xc5, (byte)0xba, (byte)0x87,
                    (byte)0x1a, (byte)0x0d, (byte)0x7a, (byte)0x89,
                    (byte)0x5f, (byte)0xec, (byte)0x0b, (byte)0x0b,
                    (byte)0xb8, (byte)0x62, (byte)0x0a, (byte)0x84,
                    (byte)0xec, (byte)0x33, (byte)0x32, (byte)0x51,
                    (byte)0xaa, (byte)0xbc, (byte)0x25, (byte)0xe3,
                    (byte)0x41, (byte)0xef, (byte)0xcf, (byte)0x1c
            }),
            null
        };

    private static final Curve25519ProjectivePoint[] points =
        new Curve25519ProjectivePoint[] {
            TWO_POINT,
            THREE_POINT,
            FIVE_POINT,
            TEN_POINT
        };

    public Curve25519Elligator2Test() {
        super(encoded, points);
    }
}
