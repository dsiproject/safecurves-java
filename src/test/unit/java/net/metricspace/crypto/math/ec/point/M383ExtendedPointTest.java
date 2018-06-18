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
package net.metricspace.crypto.math.ec.point;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import net.metricspace.crypto.math.ec.group.M383;
import net.metricspace.crypto.math.ec.group.M383Extended;
import net.metricspace.crypto.math.ec.point.M383ExtendedPoint;
import net.metricspace.crypto.math.field.ModE383M187;

public class M383ExtendedPointTest
    extends MontgomeryPointPropertiesTest<ModE383M187, M383ExtendedPoint,
                                          M383Extended> {
    private static final M383ExtendedPoint[] points =
        new M383ExtendedPoint[] {
            M383ExtendedPoint.zero(),
            M383ExtendedPoint.fromMontgomery(M383.baseX(), M383.baseY())
        };

    private static final ModE383M187[] coefficients =
        new ModE383M187[] {
             new ModE383M187(1),
             new ModE383M187(2),
             new ModE383M187(3),
             new ModE383M187(4),
             new ModE383M187(5),
             new ModE383M187(7),
             new ModE383M187(9),
             new ModE383M187(16),
             new ModE383M187(19),
             new ModE383M187(20)
        };

    public M383ExtendedPointTest() {
        super(coefficients, points, new M383Extended());
    }
}
