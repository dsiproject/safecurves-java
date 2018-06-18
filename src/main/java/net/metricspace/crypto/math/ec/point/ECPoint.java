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
 * Common interface for Elliptic-curve points.
 *
 * @param <S> Scalar values.
 * @param <P> Point type used as an argument.
 */
public interface ECPoint<S extends PrimeField<S>, P extends ECPoint<S, P>>
    extends Cloneable {
    /**
     * {@inheritDoc}
     */
    public P clone();

    /**
     * Set the value of this point from another point.
     *
     * @param point The point to copy.
     */
    public void set(final P point);

    /**
     * Set from a point on the underlying curve.
     *
     * @param x The X-coordinate.
     * @param y The Y-coordinate.
     */
    public void set(final S x,
                    final S y);

    /**
     * Copy this point to another.
     *
     * @param target The point to which to copy this one.
     */
    public abstract void copyTo(final P target);

    /**
     * Set this point to the zero point or not, depending on a
     * parameter.  In order to facilitate a branch-free
     * implementation, this is passed as an integer which is expected
     * to be {@code 0} or {@code 1} as opposed to a {@code boolean}.
     *
     * @param bool {@code 0} to zero this point, or {@code 1} to leave
     *             it as is.
     */
    public void reset(final long bool);

    /**
     * Set this point to the zero point.
     */
    public default void reset() {
        reset(0);
    }

    /**
     * Scale the point.  This is used in the context of {@link madd}
     * and {@link mmadd}.
     *
     * @see madd
     * @see mmadd
     */
    public void scale();

    /**
     * Add another point to this one.  The other point must not be
     * equal to this one, or else {@link suadd} or {@link dbl} must be
     * used.
     *
     * @param point The point to add.
     */
    public void add(final P point);

    /**
     * Add another point to this one, when this point has been scaled.
     * The other point must not be equal to this one, or else {@link
     * suadd} or {@link dbl} must be used.
     *
     * @param point The point to add.
     * @see scale
     */
    public void madd(final P point);

    /**
     * Add another point to this one, when both points have been
     * scaled.  The other point must not be equal to this one, or else
     * {@link suadd} or {@link dbl} must be used.
     *
     * @param point The point to add.
     * @see scale
     */
    public void mmadd(final P point);

    /**
     * Add another point to this one.  The other point can be the
     * equal to this one.
     *
     * @param point The point to add.
     */
    public void suadd(final P point);

    /**
     * Double this point.  This is mathematically equivalent to adding
     * this point to itself.
     */
    public void dbl();

    /**
     * Double this point, assuming that it has previously been scaled.
     *
     * @see scale
     */
    public void mdbl();

    /**
     * Triple this point.  This is mathematically equivalent to adding
     * this point to itself twice.
     */
    public void tpl();

    /**
     * Multiply this point by a scalar.  This is equivalent to adding
     * the point to itself .
     *
     * @param scalar The scalar by which to multiply.
     */
    public void mul(final S scalar);

    /**
     * Get the X coordinate.
     *
     * @return The X coordinate.
     */
    public S getX();

    /**
     * Get the Y coordinate.
     *
     * @return The Y coordinate.
     */
    public S getY();
}
