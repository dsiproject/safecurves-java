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

import net.metricspace.crypto.math.ec.curve.MontgomeryCurve;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * Points on a Montgomery curve, which has the form {@code a * y^2 =
 * x^3 + b * x^2 + x}.  Montgomery curves are birationally equivalent
 * to a twisted Edwards curve.
 *
 * @param <S> The scalar field type.
 * @param <P> Point type.
 */
public interface MontgomeryPoint<S extends PrimeField<S>,
                                 P extends MontgomeryPoint<S, P, T>,
                                 T extends ECPoint.Scratchpad<S>>
    extends ECPoint<S, P, T> {
    /**
     * Get the value of the X coordinate in the Montgomery
     * representation.
     *
     * @param scratch The scratchpad to use.
     * @return The value of the X coordinate in the Montgomery
     *         representation.
     */
    public default S montgomeryX() {
        try(final T scratch = scratchpad()) {
            return montgomeryX(scratch);
        }
    }

    /**
     * Get the value of the Y coordinate in the Montgomery
     * representation.
     *
     * @return The value of the Y coordinate in the Montgomery
     *         representation.
     */
    public default S montgomeryY() {
        try(final T scratch = scratchpad()) {
            return montgomeryY(scratch);
        }
    }

    /**
     * Get the value of the X coordinate in the Montgomery
     * representation.  This assumes the internal representation has
     * been scaled.
     *
     * @param scratch The scratchpad to use.
     * @return The value of the X coordinate in the Montgomery
     *         representation.
     * @see #scale()
     */
    public default S montgomeryXScaled() {
        try(final T scratch = scratchpad()) {
            return montgomeryXScaled(scratch);
        }
    }

    /**
     * Get the value of the Y coordinate in the Montgomery
     * representation.  This assumes the internal representation has
     * been scaled.
     *
     * @return The value of the Y coordinate in the Montgomery
     *         representation.
     * @see #scale()
     */
    public default S montgomeryYScaled() {
        try(final T scratch = scratchpad()) {
            return montgomeryYScaled(scratch);
        }
    }

    /**
     * Get the value of the X coordinate in the Montgomery
     * representation.  This assumes the internal representation has
     * been scaled.
     *
     * @param scratch The scratchpad to use.
     * @return The value of the X coordinate in the Montgomery
     *         representation.
     * @see #scale()
     */
    public default S montgomeryXScaledRef() {
        try(final T scratch = scratchpad()) {
            return montgomeryXScaledRef(scratch);
        }
    }

    /**
     * Get a direct reference to an object in the scratchpad holding
     * the value of the Y coordinate in the Montgomery representation.
     * This assumes the internal representation has been scaled.
     *
     * @return The value of the Y coordinate in the Montgomery
     *         representation.
     * @see #scale()
     */
    public default S montgomeryYScaledRef() {
        try(final T scratch = scratchpad()) {
            return montgomeryYScaledRef(scratch);
        }
    }

    /**
     * Get the value of the X coordinate in the Montgomery
     * representation.
     *
     * @param scratch The scratchpad to use.
     * @return The value of the X coordinate in the Montgomery
     *         representation.
     */
    public default S montgomeryX(final T scratch) {
        scale();

        return montgomeryXScaled(scratch);
    }

    /**
     * Get the value of the Y coordinate in the Montgomery
     * representation.
     *
     * @return The value of the Y coordinate in the Montgomery
     *         representation.
     */
    public default S montgomeryY(final T scratch) {
        scale();

        return montgomeryYScaled(scratch);
    }

    /**
     * Get the value of the X coordinate in the Montgomery
     * representation.  This assumes the internal representation has
     * been scaled.
     *
     * @param scratch The scratchpad to use.
     * @return The value of the X coordinate in the Montgomery
     *         representation.
     * @see #scale()
     */
    public default S montgomeryXScaled(final T scratch) {
        return montgomeryXScaledRef(scratch).clone();
    }

    /**
     * Get the value of the Y coordinate in the Montgomery
     * representation.  This assumes the internal representation has
     * been scaled.
     *
     * @return The value of the Y coordinate in the Montgomery
     *         representation.
     * @see #scale()
     */
    public default S montgomeryYScaled(final T scratch) {
        return montgomeryYScaledRef(scratch).clone();
    }

    /**
     * Get the value of the X coordinate in the Montgomery
     * representation.  This assumes the internal representation has
     * been scaled.
     *
     * @param scratch The scratchpad to use.
     * @return The value of the X coordinate in the Montgomery
     *         representation.
     * @see #scale()
     */
    public S montgomeryXScaledRef(final T scratch);

    /**
     * Get a direct reference to an object in the scratchpad holding
     * the value of the Y coordinate in the Montgomery representation.
     * This assumes the internal representation has been scaled.
     *
     * @return The value of the Y coordinate in the Montgomery
     *         representation.
     * @see #scale()
     */
    public S montgomeryYScaledRef(final T scratch);

    /**
     * Set the point from its Montgomery coordinates.
     *
     * @param x The Montgomery X coordinate.
     * @param y The Montgomery Y coordinate.
     * @param scratch The scratchpad to use.
     */
    public void setMontgomery(final S x,
                              final S y,
                              final T scratch);

    /**
     * Set the point from its Montgomery coordinates.
     *
     * @param x The Montgomery X coordinate.
     * @param y The Montgomery Y coordinate.
     */
    public default void setMontgomery(final S x,
                                      final S y) {
        try(final T scratch = scratchpad()) {
            setMontgomery(x, y, scratch);
        }
    }

    /**
     * Get the value of the X coordinate in the Montgomery
     * representation.
     *
     * @return The value of the X coordinate in the Montgomery
     * representation.
     */
    @Override
    public default S getX() {
        return montgomeryX();
    }

    /**
     * Get the value of the Y coordinate in the Montgomery
     * representation.
     *
     * @return The value of the Y coordinate in the Montgomery
     * representation.
     */
    @Override
    public default S getY() {
        return montgomeryY();
    }

    /**
     * Set the point from its Montgomery coordinates.
     *
     * @param x The Montgomery X coordinate.
     * @param y The Montgomery Y coordinate.
     */
    @Override
    public default void set(final S x,
                            final S y) {
        setMontgomery(x, y);
    }
}
