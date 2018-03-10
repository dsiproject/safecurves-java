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

import net.metricspace.crypto.math.field.PrimeField;

/**
 * Common superclass for point representations with a scaling factor.
 * These include projective coordinate, inverted coordinate, and
 * extended coordinate representations.
 *
 * @param <S> Scalar values.
 * @param <P> Point type used as an argument.
 */
public abstract class ScaledPoint<S extends PrimeField<S>,
                                  P extends ScaledPoint<S, P>>
    implements ECPoint<S, P> {
    /**
     * Inverted X coordinate.  This is {@code Z / x}, where {@code x}
     * is the X-coordinate on the original curve.
     */
    protected final S x;

    /**
     * Inverted Y coordinate.  This is {@code Z / y}, where {@code y}
     * is the Y-coordinate on the original curve.
     */
    protected final S y;

    /**
     * Scaling coordinate.
     */
    protected final S z;

    /**
     * Initialize an {@code InvertedPoint} with three scalar objects.
     * This constructor takes possession of the parameters, which are
     * used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     */
    protected ScaledPoint(final S x,
                          final S y,
                          final S z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void copyTo(final P target) {
        target.x.set(x);
        target.y.set(y);
        target.z.set(z);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public abstract P clone();
}
