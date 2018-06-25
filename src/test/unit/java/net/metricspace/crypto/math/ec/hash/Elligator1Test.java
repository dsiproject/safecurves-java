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

import net.metricspace.crypto.math.field.PrimeField;

public abstract class Elligator1Test<S extends PrimeField<S>,
                                     P extends Elligator1<S, P, ?>>
    extends ElligatorTest<S, P> {
    private final S edwardsD;
    private final S elligatorC;
    private final S elligatorR;
    private final S elligatorS;

    protected Elligator1Test(final S[] encoded,
                             final P[] points,
                             final S edwardsD,
                             final S elligatorC,
                             final S elligatorR,
                             final S elligatorS) {
        super(encoded, points);

        this.edwardsD = edwardsD;
        this.elligatorC = elligatorC;
        this.elligatorR = elligatorR;
        this.elligatorS = elligatorS;
    }

    @Test(description = "Check sanity of Elligator 1 C")
    public void elligatorCsanity() {
        final S numer = elligatorC.clone();

        numer.add(1);
        numer.square();
        numer.neg();

        final S denom = elligatorC.clone();

        denom.sub(1);
        denom.square();

        numer.div(denom);

        Assert.assertEquals(elligatorC.legendre(), 1);
        Assert.assertEquals(numer, edwardsD);
    }

    @Test(description = "Check sanity of Elligator 1 R")
    public void elligatorRsanity() {
        final S cinv = elligatorC.clone();

        cinv.inv();
        cinv.add(elligatorC);

        Assert.assertEquals(cinv, elligatorR);
    }

    @Test(description = "Check sanity of Elligator 1 S")
    public void elligatorSsanity() {
        final S sinv = elligatorS.clone();

        sinv.square();
        sinv.inv();
        sinv.mul(2);

        Assert.assertEquals(elligatorS.legendre(), 1);
        Assert.assertEquals(sinv, elligatorC);
    }
}
