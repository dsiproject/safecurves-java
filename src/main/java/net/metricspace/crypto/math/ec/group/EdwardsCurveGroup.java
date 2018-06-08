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

import net.metricspace.crypto.math.ec.curve.EdwardsCurve;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * Elliptic-curve group parameters for Edwards Curves.
 *
 * @param <S> Type of scalar values.
 * @param <P> Type of points.
 */
public abstract class EdwardsCurveGroup<S extends PrimeField<S>,
                                        P extends ECPoint<S, P, ?>>
    implements ECGroup<S, P>, EdwardsCurve<S> {
    /**
     * Create a point from its base Edwards coordinates.
     *
     * @param x The Edwards {@code x} coordinate.
     * @param y The Edwards {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public abstract P fromEdwards(final S x,
                                  final S y);

    /**
     * {@inheritDoc}
     */
    @Override
    public P fromCoords(final S x,
                        final S y) {
        return fromEdwards(x, y);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(final Object other) {
        if (other instanceof EdwardsCurveGroup) {
            return equals((EdwardsCurveGroup) other);
        } else {
            return false;
        }
    }

    /**
     * Compare against another {@code EdwardsCurve}s.
     *
     * @param other The {@code EdwardsCurve} against which to compare.
     * @return Whether or not the two are equal.
     */
    private boolean equals(final EdwardsCurveGroup other) {
        return this.edwardsD() == other.edwardsD();
    }

    /**
     * String representation of the twisted Edwards equation.
     *
     * @return String representation of the twisted Edwards equation.
     */
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        final int d = edwardsD();

        sb.append("x^2 + y^2 = 1 ");

        if (d < 0) {
            sb.append("- ");
            sb.append(-d);
        } else {
            sb.append("+ ");
            sb.append(d);
        }

        sb.append(" * x^2 * y^2 ");

        return sb.toString();
    }
}
