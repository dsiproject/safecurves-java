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
import net.metricspace.crypto.math.ec.group.E382DecafProjective;
import net.metricspace.crypto.math.ec.point.E382DecafProjectivePoint;
import net.metricspace.crypto.math.field.ModE382M105;

public class E382DecafElligatorDecafTest
    extends ElligatorDecafTest<ModE382M105, E382DecafProjectivePoint> {
    private static final E382DecafProjective group =
        new E382DecafProjective();

    private static final E382DecafProjectivePoint BASE_POINT =
        group.basePoint();

    private static final E382DecafProjectivePoint TWO_POINT =
        group.basePoint();

    private static final E382DecafProjectivePoint THREE_POINT =
        group.basePoint();

    private static final E382DecafProjectivePoint FOUR_POINT =
        group.basePoint();

    static {
        TWO_POINT.add(BASE_POINT);
        THREE_POINT.add(TWO_POINT);
        FOUR_POINT.add(THREE_POINT);
    };

    private static final ModE382M105[] encoded =
        new ModE382M105[] {
            null,
            new ModE382M105(new byte[] {
                    (byte)0x6a, (byte)0xda, (byte)0x85, (byte)0xc8,
                    (byte)0x89, (byte)0x20, (byte)0xbc, (byte)0x14,
                    (byte)0xb6, (byte)0x36, (byte)0xf4, (byte)0x8c,
                    (byte)0x3f, (byte)0x40, (byte)0x20, (byte)0x1e,
                    (byte)0xec, (byte)0x52, (byte)0x89, (byte)0x33,
                    (byte)0xe7, (byte)0x46, (byte)0x1b, (byte)0xc2,
                    (byte)0x62, (byte)0xdf, (byte)0x81, (byte)0xee,
                    (byte)0x50, (byte)0x4c, (byte)0xde, (byte)0x13,
                    (byte)0xc8, (byte)0x55, (byte)0xb4, (byte)0xb7,
                    (byte)0x2c, (byte)0x06, (byte)0x2a, (byte)0x99,
                    (byte)0xae, (byte)0xd6, (byte)0x44, (byte)0x7e,
                    (byte)0xce, (byte)0x20, (byte)0xc8, (byte)0x39
                }),
            new ModE382M105(new byte[] {
                    (byte)0x48, (byte)0xd7, (byte)0x18, (byte)0x96,
                    (byte)0x62, (byte)0x3b, (byte)0xe0, (byte)0x3c,
                    (byte)0x8b, (byte)0x0d, (byte)0xc7, (byte)0x91,
                    (byte)0x48, (byte)0x8e, (byte)0x7f, (byte)0x7f,
                    (byte)0x62, (byte)0xce, (byte)0xbd, (byte)0xc8,
                    (byte)0xe2, (byte)0x38, (byte)0x4f, (byte)0xf8,
                    (byte)0x28, (byte)0xc2, (byte)0xd2, (byte)0x2b,
                    (byte)0xce, (byte)0xc2, (byte)0x4e, (byte)0x09,
                    (byte)0x3b, (byte)0x9b, (byte)0xd5, (byte)0xa4,
                    (byte)0xbc, (byte)0xbe, (byte)0x7f, (byte)0x2b,
                    (byte)0xe8, (byte)0x21, (byte)0xc9, (byte)0x49,
                    (byte)0x2d, (byte)0xc5, (byte)0xa5, (byte)0x3c
                }),
            null,
        };

    private static final E382DecafProjectivePoint[] points =
        new E382DecafProjectivePoint[] {
            BASE_POINT,
            TWO_POINT,
            THREE_POINT,
            FOUR_POINT
        };

    public E382DecafElligatorDecafTest() {
        super(encoded, points);
    }
}
