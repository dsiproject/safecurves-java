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
package net.metricspace.crypto.math.ec;

import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * Interface for the Elligator hash algorithms.  The Elligator hash
 * algorithms were introduced by Bernstein, Hamburg, Krasnova, and
 * Lange in their paper <a
 * href="https://elligator.cr.yp.to/elligator-20130828.pdf">"Elligator:
 * Elliptic-Curve Points Indistinguishable from Uniform Random
 * Strings"</a>.  It provides the ability to hash any scalar value to
 * a point on an elliptic curve.
 * <p>
 * This is <i>not</i> a cryptogrophic function.  In fact, Elligator
 * provides a preimage function which produces scalar values from
 * elliptic curve points with a uniform distribution.
 *
 * @param <S> Scalar type.
 * @param <P> Point type.
 */
public interface Elligator<S extends PrimeField<S>,
                           P extends Elligator<S, P>>
    extends ECPoint<S, P> {
    /**
     * Get the default hash parameter.
     *
     * @return The default hash parameter.
     */
    public int defaultHashParam();

    /**
     * Use the hash function from a single scalar value to a point to
     * set the value of this point.
     *
     * @param code The hash code from which to generate a point.
     */
    public default void decodeHash(final S code) {
        decodeHash(defaultHashParam(), code);
    }

    /**
     * Use the hash function from a single scalar value to a point to
     * set the value of this point.
     *
     * @param p Hash parameter as a small number.
     * @param code The hash code from which to generate a point.
     */
    public void decodeHash(final int p,
                            final S code);

    /**
     * Get a hash code that will re-create this point with {@link
     * decodeHash}.
     *
     * @return A hash code that will re-create this point with {@link
     *         decodeHash}.
     * @see decodeHash
     */
    public default S encodeHash() {
        return encodeHash(defaultHashParam());
    }

    /**
     * Get a hash code that will re-create this point with {@link
     * decodeHash}.
     *
     * @param p Hash parameter as a small number.
     * @return A hash code that will re-create this point with {@link
     *         decodeHash}.
     * @see decodeHash
     */
    public S encodeHash(final int p);
}
