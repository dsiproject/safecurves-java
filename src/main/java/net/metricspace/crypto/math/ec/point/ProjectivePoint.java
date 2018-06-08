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

import java.lang.StringBuilder;

import net.metricspace.crypto.math.field.PrimeField;

/**
 * Common superclass for projective point representations.  Projective
 * points consist of {@code (X, Y, Z)}, where {@code X = x / Z},
 * {@code Y = y / Z}, where {@code x} and {@code y} are the
 * coordinates on the underlying curve.
 *
 * @param <S> Scalar values.
 * @param <P> Point type used as an argument.
 */
public abstract class ProjectivePoint<S extends PrimeField<S>,
                                      P extends ProjectivePoint<S, P, T>,
                                      T extends ECPoint.Scratchpad>
    extends ScaledPoint<S, P, T>
    implements EdwardsPoint<S, P, T> {
    /**
     * Initialize a {@code ProjectivePoint} with three scalar objects.
     * This constructor takes possession of the parameters, which are
     * used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     */
    protected ProjectivePoint(final S x,
                              final S y,
                              final S z) {
        super(x, y, z);
    }

    /**
     * Compare against a point, when both points are scaled.
     *
     * @param other The point against which to compare.
     * @return Whether this point is equal to {@code other}.
     */
    public boolean mmequals(final ProjectivePoint<S, P, T> other) {
        return x.equals(other.x) && y.equals(other.y);
    }

    /**
     * Compare against a point, when this point is scaled.
     *
     * @param other The point against which to compare.
     * @return Whether this point is equal to {@code other}.
     */
    public boolean mequals(final ProjectivePoint<S, P, T> other) {
        other.scale();

        return mmequals(other);
    }

    /**
     * {@inheritDoc}
     */
    public boolean equals(final ProjectivePoint<S, P, T> other) {
        this.scale();

        return mequals(other);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(final Object other) {
        if (other instanceof ProjectivePoint) {
            return equals((ProjectivePoint<S, P, T>)other);
        } else {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        final S xscale = x.clone();
        final S yscale = y.clone();
        final S zinv = z.clone();

        zinv.inv();
        xscale.mul(zinv);
        yscale.mul(zinv);
        sb.append('(');
        sb.append(xscale.toString());
        sb.append(", ");
        sb.append(yscale.toString());
        sb.append(')');

        return sb.toString();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void reset(final long bit) {
        final S one = x.clone();
        final long negbit = bit ^ 0x1;

        one.set(1);
        one.mask(negbit);
        x.mask(bit);
        y.mask(bit);
        y.or(one);
        z.mask(bit);
        z.or(one);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void scale() {
        final S a = z.clone();

        a.inv();

        x.mul(a);
        y.mul(a);
        z.set(1);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void set(final P point) {
        x.set(point.x);
        y.set(point.y);
        z.set(point.z);
    }

    /**
     * {@inheritDoc}
     */
    public void setEdwards(final S x,
                           final S y) {
        this.x.set(x);
        this.y.set(y);
        this.z.set(1);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public S edwardsX() {
        final S out = x.clone();

        out.div(z);

        return out;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public S edwardsY() {
        final S out = y.clone();

        out.div(z);

        return out;
    }

    /**
     * {@inheritDoc}
     */
    public abstract P clone();
}
