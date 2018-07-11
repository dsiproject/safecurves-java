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

import java.lang.AutoCloseable;

import javax.security.auth.Destroyable;
import javax.security.auth.DestroyFailedException;

import net.metricspace.crypto.math.field.PrimeField;

/**
 * Common interface for Elliptic-curve points.
 *
 * @param <S> Scalar values.
 * @param <P> Point type used as an argument.
 * @param <T> Scratchpad type.
 */
public interface ECPoint<S extends PrimeField<S>,
                         P extends ECPoint<S, P, T>,
                         T extends ECPoint.Scratchpad<S>>
    extends Cloneable, Destroyable, AutoCloseable {
    /**
     * Superclass of scratchpads for Montgomery ladders.
     *
     * @param <S> Scalar values.
     */
    public static abstract class Scratchpad<S extends PrimeField<S>>
        extends PrimeField.Scratchpad {
        public final S r0;
        public final S r1;
        public final S r2;

        /**
         * Initialize a {@code Scratchpad}.
         *
         * @param r0 A scalar object, to be owned by the scratchpad.
         * @param ndigits The number of digits in a scalar value.
         */
        protected Scratchpad(final S r0,
                             final S r1,
                             final S r2,
                             final int ndigits) {
            super(ndigits);

            this.r0 = r0;
            this.r1 = r1;
            this.r2 = r2;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void destroy() {
            super.destroy();

            r0.destroy();
            r1.destroy();
            r2.destroy();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean isDestroyed() {
            return super.isDestroyed() && r0.isDestroyed() &&
                   r1.isDestroyed() && r2.isDestroyed();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void destroy();

    /**
     * {@inheritDoc}
     */
    @Override
    public default void close() {
        destroy();
    }

    /**
     * {@inheritDoc}
     */
    public P clone();

    /**
     * Get a scratchpad.  This is a mechanism designed to avoid
     * repeated allocation of scalar values.  Sequences of operations
     * should obtain a scratchpad, pass it into all operations, then
     * destroy it when through.
     *
     * @return A scratchpad.
     */
    public T scratchpad();

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
     * @param bool {@code 1} to zero this point, or {@code 0} to leave
     *             it as is.
     */
    public void reset(final long bool);

    /**
     * Set this point to the zero point.
     */
    public default void reset() {
        reset(1);
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
    public default void add(final P point) {
        try(final T scratchpad = scratchpad()) {
            add(point, scratchpad);
        }
    }

    /**
     * Add another point to this one, when this point has been scaled.
     * The other point must not be equal to this one, or else {@link
     * suadd} or {@link dbl} must be used.
     *
     * @param point The point to add.
     * @see scale
     */
    public default void madd(final P point) {
        try(final T scratchpad = scratchpad()) {
            madd(point, scratchpad);
        }
    }

    /**
     * Add another point to this one, when both points have been
     * scaled.  The other point must not be equal to this one, or else
     * {@link suadd} or {@link dbl} must be used.
     *
     * @param point The point to add.
     * @see scale
     */
    public default void mmadd(final P point) {
        try(final T scratchpad = scratchpad()) {
            mmadd(point, scratchpad);
        }
    }


    /**
     * Add another point to this one.  The other point can be the
     * equal to this one.
     *
     * @param point The point to add.
     */
    public default void suadd(final P point) {
        try(final T scratchpad = scratchpad()) {
            suadd(point, scratchpad);
        }
    }

    /**
     * Double this point.  This is mathematically equivalent to adding
     * this point to itself.
     */
    public default void dbl() {
        try(final T scratchpad = scratchpad()) {
            dbl(scratchpad);
        }
    }

    /**
     * Double this point, assuming that it has previously been scaled.
     *
     * @see scale
     */
    public default void mdbl() {
        try(final T scratchpad = scratchpad()) {
            mdbl(scratchpad);
        }
    }


    /**
     * Triple this point.  This is mathematically equivalent to adding
     * this point to itself twice.
     */
    public default void tpl() {
        try(final T scratchpad = scratchpad()) {
            tpl(scratchpad);
        }
    }


    /**
     * Multiply this point by a scalar.  This is equivalent to adding
     * the point to itself .
     *
     * @param scalar The scalar by which to multiply.
     */
    public default void mul(final S scalar) {
        try(final T scratchpad = scratchpad()) {
            mul(scalar, scratchpad);
        }
    }

    /**
     * Add another point to this one.  The other point must not be
     * equal to this one, or else {@link suadd} or {@link dbl} must be
     * used.
     *
     * @param point The point to add.
     * @param scratchpad The scratchpad to use.
     */
    public void add(final P point,
                    final T scratchpad);

    /**
     * Add another point to this one, when this point has been scaled.
     * The other point must not be equal to this one, or else {@link
     * suadd} or {@link dbl} must be used.
     *
     * @param point The point to add.
     * @param scratchpad The scratchpad to use.
     * @see scale
     */
    public void madd(final P point,
                     final T scratchpad);

    /**
     * Add another point to this one, when both points have been
     * scaled.  The other point must not be equal to this one, or else
     * {@link suadd} or {@link dbl} must be used.
     *
     * @param point The point to add.
     * @param scratchpad The scratchpad to use.
     * @see scale
     */
    public void mmadd(final P point,
                      final T scratchpad);

    /**
     * Add another point to this one.  The other point can be the
     * equal to this one.
     *
     * @param point The point to add.
     */
    public void suadd(final P point,
                      final T scratchpad);

    /**
     * Double this point.  This is mathematically equivalent to adding
     * this point to itself.
     */
    public void dbl(final T scratchpad);

    /**
     * Double this point, assuming that it has previously been scaled.
     *
     * @see scale
     */
    public void mdbl(final T scratchpad);

    /**
     * Triple this point.  This is mathematically equivalent to adding
     * this point to itself twice.
     */
    public void tpl(final T scratchpad);

    /**
     * Multiply this point by a scalar.  This is equivalent to adding
     * the point to itself .
     *
     * @param scalar The scalar by which to multiply.
     */
    public void mul(final S scalar,
                    final T scratchpad);

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
