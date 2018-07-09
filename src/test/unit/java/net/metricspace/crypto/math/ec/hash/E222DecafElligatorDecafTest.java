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
import net.metricspace.crypto.math.ec.group.E222DecafProjective;
import net.metricspace.crypto.math.ec.point.E222DecafProjectivePoint;
import net.metricspace.crypto.math.field.ModE222M117;

public class E222DecafElligatorDecafTest
    extends ElligatorDecafTest<ModE222M117, E222DecafProjectivePoint> {
    private static final E222DecafProjective group =
        new E222DecafProjective();

    private static final E222DecafProjectivePoint BASE_POINT =
        group.basePoint();

    private static final E222DecafProjectivePoint TWO_POINT =
        group.basePoint();

    private static final E222DecafProjectivePoint THREE_POINT =
        group.basePoint();

    static {
        TWO_POINT.add(BASE_POINT);
        THREE_POINT.add(TWO_POINT);
    };

    private static final ModE222M117[] encoded =
        new ModE222M117[] {
            null,
            new ModE222M117(new byte[] {
                    (byte)0x75, (byte)0x34, (byte)0xb3, (byte)0x58,
                    (byte)0x91, (byte)0xe3, (byte)0x06, (byte)0x3f,
                    (byte)0x31, (byte)0x1a, (byte)0xf3, (byte)0x79,
                    (byte)0xc2, (byte)0x90, (byte)0x92, (byte)0xaf,
                    (byte)0x53, (byte)0xf4, (byte)0xd0, (byte)0xc0,
                    (byte)0x97, (byte)0xb4, (byte)0xfc, (byte)0xe6,
                    (byte)0xe0, (byte)0x7b, (byte)0x7d, (byte)0x3a
                }),
            new ModE222M117(new byte[] {
                    (byte)0x87, (byte)0xcd, (byte)0x7c, (byte)0x16,
                    (byte)0x98, (byte)0xbe, (byte)0x99, (byte)0x07,
                    (byte)0x44, (byte)0xf5, (byte)0x95, (byte)0x42,
                    (byte)0xc8, (byte)0xfd, (byte)0x5a, (byte)0x76,
                    (byte)0xa9, (byte)0x1d, (byte)0x1a, (byte)0xc1,
                    (byte)0xee, (byte)0x36, (byte)0x92, (byte)0xeb,
                    (byte)0x4a, (byte)0xd5, (byte)0xca, (byte)0x30
                }),
        };

    private static final E222DecafProjectivePoint[] points =
        new E222DecafProjectivePoint[] {
            BASE_POINT,
            TWO_POINT,
            THREE_POINT,
        };

    public E222DecafElligatorDecafTest() {
        super(encoded, points);
    }
}
