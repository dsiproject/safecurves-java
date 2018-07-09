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
package net.metricspace.crypto.math.ec.curve;

import java.lang.StringBuilder;

import net.metricspace.crypto.math.field.PrimeField;

/**
 * Parameters for twisted Edwards curves.  Twisted Edwards curves are
 * of the form {@code a * x^2 + y^2 = 1 + d * x^2 * y^2}.  They were
 * introduced by Bernstein, Birkner, Joye, Lange, and Peters, in their
 * paper <a
 * href="https://cr.yp.to/newelliptic/twisted-20080108.pdf">"Twisted
 * Edwards Curves"</a>
 *
 * @param <F> The field underlying the Edwards curve.
 */
public interface TwistedEdwardsCurve<F extends PrimeField<F>> {
    /**
     * Get a fixed quadratic non-residue in the underlying field.
     * This is either {@code 2} or {@code -2}.
     */
    public int nonresidue();

    /**
     * Get the value of {@code a} in a twisted Edwards curve of the
     * form {@code a * x^2 + y^2 = 1 + d * x^2 * y^2}.
     *
     * @return The value of {@code d} in a twisted Edwards curve.
     */
    public int edwardsA();

    /**
     * Get the value of {@code d} in a twisted Edwards curve of the
     * form {@code a * x^2 + y^2 = 1 + d * x^2 * y^2}.
     *
     * @return The value of {@code d} in a twisted Edwards curve.
     */
    public int edwardsD();
}
