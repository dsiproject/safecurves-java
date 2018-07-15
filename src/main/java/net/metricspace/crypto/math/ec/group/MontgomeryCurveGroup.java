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

import net.metricspace.crypto.math.ec.curve.MontgomeryCurve;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * Elliptic-curve group parameters for Montgomery curves.
 *
 * @param <S> Type of scalar values.
 * @param <P> Type of points.
 */
public abstract class MontgomeryCurveGroup<S extends PrimeField<S>,
                                           P extends ECPoint<S, P, T>,
                                           T extends ECPoint.Scratchpad<S>>
    extends TwistedEdwardsCurveGroup<S, P, T>
    implements MontgomeryCurve<S> {
    /**
     * Create a point from its base Montgomery coordinates.
     *
     * @param x The Montgomery {@code x} coordinate.
     * @param y The Montgomery {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public P fromMontgomery(final S x,
                            final S y) {
        try(final T scratch = scratchpad()) {
            return fromMontgomery(x, y, scratch);
        }
    }

    /**
     * Create a point from its base Montgomery coordinates.
     *
     * @param x The Montgomery {@code x} coordinate.
     * @param y The Montgomery {@code y} coordinate.
     * @param scratch The scratchpad to use.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public abstract P fromMontgomery(final S x,
                                     final S y,
                                     final T scratch);

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(final Object other) {
        if (other instanceof MontgomeryCurve) {
            return equals((MontgomeryCurve) other);
        } else {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public P fromCoords(final S x,
                        final S y) {
        return fromMontgomery(x, y);
    }

    /**
     * Compare against another {@code MontgomeryCurve}s.
     *
     * @param other The {@code MontgomeryCurve} against which to compare.
     * @return Whether or not the two are equal.
     */
    public boolean equals(final MontgomeryCurve other) {
        return this.montgomeryA().equals(other.montgomeryA());
    }

    /**
     * String representation of the Montgomery equation.
     *
     * @return String representation of the Montgomery equation.
     */
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();

        appendMontgomeryForm(sb, montgomeryA());

        return sb.toString();
    }

    /**
     * Append the Montgomery form to a {@link StringBuilder}.
     *
     * @param <S> Type of scalar values.
     * @param sb {@link StringBuilder} to which to append the Montgomery form.
     * @param a The Montgomery {@code A} parameter.
     */
    public static <S extends PrimeField<S>>
        void appendMontgomeryForm(final StringBuilder sb,
                                  final S a) {
        sb.append("y^2 = x^3 + ");
        sb.append(a);
        sb.append(" * x^2 + x");
    }
}
