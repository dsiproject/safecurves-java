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

import java.lang.ThreadLocal;

import net.metricspace.crypto.math.ec.curve.M511Curve;
import net.metricspace.crypto.math.ec.hash.Elligator2;
import net.metricspace.crypto.math.field.ModE511M187;

/**
 * Extended coordinates on the twisted Edwards curve birationally
 * equivalent to the Montgomery curve M-511.
 */
public class M511ExtendedPoint
    extends ExtendedTwistedEdwardsPoint<ModE511M187, M511ExtendedPoint,
                                        M511ExtendedPoint.Scratchpad>
    implements M511Curve,
               Elligator2<ModE511M187, M511ExtendedPoint,
                          M511ExtendedPoint.Scratchpad> {
    /**
     * Scratchpads for extended M-511 points.
     */
    public static final class Scratchpad
        extends ExtendedTwistedEdwardsPoint.Scratchpad<ModE511M187> {

        private static final ThreadLocal<Scratchpad> scratchpads =
            new ThreadLocal<Scratchpad>() {
                @Override
                public Scratchpad initialValue() {
                    return new Scratchpad();
                }
            };

        /**
         * Initialize an empty {@code Scratchpad}.
         */
        private Scratchpad() {
            super(new ModE511M187(0), new ModE511M187(0), new ModE511M187(0),
                  new ModE511M187(0), new ModE511M187(0), new ModE511M187(0));
        }

        protected static Scratchpad get() {
            return scratchpads.get();
        }
    }

    private static final M511ExtendedPoint ZERO = new M511ExtendedPoint();

    /**
     * Initialize a {@code M511ExtendedPoint} with zero
     * coordinates.
     */
    private M511ExtendedPoint() {
        this(new ModE511M187(0), new ModE511M187(1),
             new ModE511M187(1), new ModE511M187(0));
    }

    /**
     * Initialize an {@code M511ExtendedPoint} with raw
     * Edwards X and Y coordinates.  This constructor takes possession
     * of the parameters.
     *
     * @param x The X coordinate value.
     * @param y The Y coordinate value.
     */
    protected M511ExtendedPoint(final ModE511M187 x,
                                final ModE511M187 y) {
        super(x, y);
    }

    /**
     * Initialize an {@code M511ExtendedPoint} with three scalar
     * objects.  This constructor takes possession of the parameters,
     * which are used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     * @param t The scalar object for t.
     */
    protected M511ExtendedPoint(final ModE511M187 x,
                                final ModE511M187 y,
                                final ModE511M187 z,
                                final ModE511M187 t) {
        super(x, y, z, t);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Scratchpad scratchpad() {
        return Scratchpad.get();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public M511ExtendedPoint clone() {
        return new M511ExtendedPoint(x.clone(), y.clone(),
                                     z.clone(), t.clone());
    }

    /**
     * Create a {@code M511ExtendedPoint} initialized as the
     * zero-point on the M-511 curve in extended coordinates.
     *
     * @return A zero point on the M-511 curve in extended
     *         coordinates.
     */
    public static M511ExtendedPoint zero() {
        return new M511ExtendedPoint();
    }

    /**
     * Create a {@code M511ExtendedPoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Edwards {@code x} coordinate.
     * @param y The Edwards {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static M511ExtendedPoint fromEdwards(final ModE511M187 x,
                                                final ModE511M187 y) {
        return new M511ExtendedPoint(x.clone(), y.clone());
    }

    /**
     * Create a {@code M511ExtendedPoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Montgomery {@code x} coordinate.
     * @param y The Montgomery {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static M511ExtendedPoint fromMontgomery(final ModE511M187 x,
                                                   final ModE511M187 y) {
        final ModE511M187 edwardsX = new ModE511M187(0);
        final ModE511M187 edwardsY = new ModE511M187(0);

        TwistedEdwardsPoint.montgomeryToEdwards(x, y, edwardsX, edwardsY);

        return new M511ExtendedPoint(edwardsX, edwardsY);
    }

    /**
     * Create a {@code M511ExtendedPoint} from a hash.
     *
     * @param s The hash input.
     * @return A point initialized by hashing {@code s} to a point.
     * @throws IllegalArgumentException If the hash input is invalid.
     */
    public static M511ExtendedPoint fromHash(final ModE511M187 s)
        throws IllegalArgumentException {
        final M511ExtendedPoint p = zero();

        p.decodeHash(s);

        return p;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        if (!this.equals(ZERO)) {
            final StringBuilder sb = new StringBuilder();

            sb.append('(');
            sb.append(montgomeryX().toString());
            sb.append(", ");
            sb.append(montgomeryY().toString());
            sb.append(')');

            return sb.toString();
        } else {
            return "Inf";
        }
    }
}
