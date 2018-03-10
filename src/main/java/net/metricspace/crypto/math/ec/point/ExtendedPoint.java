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
 * Extended twisted Edwards curve points, as described in Hisil,
 * Koon-Ho, Carter, and Dawson in their paper, <a
 * href="https://eprint.iacr.org/2008/522.pdf">"Twisted Edwards Curves
 * Revisited"</a>.  Curve points are represented as a quad, {@code
 * (X, Y, Z, T)}, where {@code X = x/Z}, {@code Y = y/Z}, and {@code T
 * = X * Y}, where {@code x} and {@code y} are the original curve
 * coordinates.
 *
 * @param <S> Scalar values.
 * @param <P> Point type used as an argument.
 */
public abstract class ExtendedPoint<S extends PrimeField<S>,
                                    P extends ExtendedPoint<S, P>>
    extends ProjectivePoint<S, P>
    implements EdwardsPoint<S, P> {
    /**
     * Cached value of {@code X * Y / Z}
     */
    public final S t;

    /**
     * Set {@code t} when {@code z == 1}.
     */
    private void setTScaled() {
        t.set(x);
        t.mul(y);
    }

    /**
     * Initialize an {@code ExtendedPoint} with three scalar objects.
     * This constructor takes possession of the parameters, which are
     * used as the coordinate objects.  This constructor does
     * <i>not</i> scale the parameters.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     * @param t The scalar object for t.
     */
    protected ExtendedPoint(final S x,
                            final S y,
                            final S z,
                            final S t) {
        super(x, y, z);

        this.t = t;
    }

    /**
     * Initialize an {@code ExtendedPoint} with two scalar objects.
     * This constructor takes possession of the parameters, which are
     * used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     */
    protected ExtendedPoint(final S x,
                            final S y) {
        this(x, y, x.clone(), x.clone());

        z.set(1);
        t.mul(y);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void scale() {
        super.scale();
        setTScaled();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void reset(final long bit) {
        super.reset(bit);

        t.mask(bit);
    }

    /**
     * {@inheritDoc}
     */
    public void set(final S x,
                    final S y) {
        super.set(x, y);
        setTScaled();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void set(final P point) {
        super.set(point);
        t.set(point.t);
    }

    /**
     * {@inheritDoc}
     */
    public void setEdwards(final S x,
                           final S y) {
        super.setEdwards(x, y);
        t.set(x);
        t.mul(y);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void copyTo(final P target) {
        super.copyTo(target);
        target.t.set(t);
    }

    /**
     * {@inheritDoc}
     */
    public abstract P clone();
}
