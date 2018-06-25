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

import net.metricspace.crypto.math.ec.curve.Curve1174Curve;
import net.metricspace.crypto.math.ec.group.Curve1174Projective;
import net.metricspace.crypto.math.ec.point.Curve1174ProjectivePoint;
import net.metricspace.crypto.math.field.ModE251M9;

public class Curve1174Elligator1Test
    extends Elligator1Test<ModE251M9, Curve1174ProjectivePoint> {
    private static final Curve1174Projective group =
        new Curve1174Projective();

    private static final ModE251M9[] encoded =
        new ModE251M9[] {
        new ModE251M9(new byte[] {
                (byte)0xc9, (byte)0x42, (byte)0xf8, (byte)0x6c,
                (byte)0x96, (byte)0x7b, (byte)0x67, (byte)0xf3,
                (byte)0xbd, (byte)0xb1, (byte)0x19, (byte)0xaf,
                (byte)0xc6, (byte)0x3a, (byte)0xce, (byte)0xd4,
                (byte)0x1b, (byte)0xd9, (byte)0x81, (byte)0xab,
                (byte)0x5b, (byte)0x3d, (byte)0xad, (byte)0x56,
                (byte)0x30, (byte)0xf0, (byte)0x85, (byte)0xd7,
                (byte)0x0d, (byte)0xff, (byte)0x1a, (byte)0x03
            })
    };

    private static final Curve1174ProjectivePoint[] points =
        new Curve1174ProjectivePoint[] {
        group.basePoint()
    };

    public Curve1174Elligator1Test() {
        super(encoded, points, Curve1174Curve.EDWARDS_D_LONG,
              Curve1174Curve.ELLIGATOR_C,
              Curve1174Curve.ELLIGATOR_R,
              Curve1174Curve.ELLIGATOR_S);
    }
}
