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
package net.metricspace.crypto.math.ec.group;

import java.security.SecureRandom;

import org.testng.Assert;
import org.testng.annotations.Test;

import net.metricspace.crypto.math.ec.group.ECGroup;
import net.metricspace.crypto.math.ec.ladder.MontgomeryLadder;
import net.metricspace.crypto.math.field.PrimeField;

@Test(groups = "stress")
abstract class ECDHTest<S extends PrimeField<S>,
                        P extends MontgomeryLadder<S, P, ?>,
                        G extends ECGroup<S, P, ?>> {
    protected static final SecureRandom random = new SecureRandom();
    private static int NUM_TESTS = 1024;
    private G group;

    protected ECDHTest(final G group) {
        this.group = group;
    }

    protected abstract S generatePrivateKey();

    @Test(description = "Test that ECDH works")
    public void ecdhTest() {
        for(int i = 0; i < NUM_TESTS; i++) {
            final S private1 = generatePrivateKey();
            final P public1 = group.basePoint();

            public1.mul(private1);

            final S private2 = generatePrivateKey();
            final P public2 = group.basePoint();

            public2.mul(private2);

            final S secret1 = public1.mulX(private2);
            final S secret2 = public2.mulX(private1);

            Assert.assertEquals(secret1, secret2);
        }
    }
}
