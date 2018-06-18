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

import net.metricspace.crypto.math.ec.curve.EdwardsCurve;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * Points on an Edwards curve, which has the form {@code x^2 + y^2 = 1
 * + d * x^2 * y^2 }
 *
 * @param <S> The scalar field type.
 */
public interface EdwardsPoint<S extends PrimeField<S>,
                              P extends EdwardsPoint<S, P, T>,
                              T extends ECPoint.Scratchpad>
    extends ECPoint<S, P, T> {
    /**
     * Get the value of the X coordinate in the Edwards
     * representation.
     *
     * @return The value of the X coordinate in the Edwards
     * representation.
     */
    public S edwardsX();

    /**
     * Get the value of the Y coordinate in the Edwards
     * representation.
     *
     * @return The value of the Y coordinate in the Edwards
     * representation.
     */
    public S edwardsY();

    /**
     * Set the point from its Edwards coordinates.
     *
     * @param x The Edwards X coordinate.
     * @param y The Edwards Y coordinate.
     */
    public void setEdwards(final S x,
                           final S y);

    /**
     * Get the value of the X coordinate in the Edwards
     * representation.
     *
     * @return The value of the X coordinate in the Edwards
     * representation.
     */
    @Override
    public default S getX() {
        return edwardsX();
    }

    /**
     * Get the value of the Y coordinate in the Edwards
     * representation.
     *
     * @return The value of the Y coordinate in the Edwards
     * representation.
     */
    @Override
    public default S getY() {
        return edwardsY();
    }

    /**
     * Set the point from its Edwards coordinates.
     *
     * @param x The Edwards X coordinate.
     * @param y The Edwards Y coordinate.
     */
    @Override
    public default void set(final S x,
                            final S y) {
        setEdwards(x, y);
    }
}
