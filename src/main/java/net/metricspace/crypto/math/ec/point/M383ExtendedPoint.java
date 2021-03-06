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

import net.metricspace.crypto.math.ec.curve.M383Curve;
import net.metricspace.crypto.math.ec.hash.Elligator2;
import net.metricspace.crypto.math.field.ModE383M187;

/**
 * Extended coordinates on the twisted Edwards curve birationally
 * equivalent to the Montgomery curve M-383.
 */
public class M383ExtendedPoint
    extends ExtendedTwistedEdwardsPoint<ModE383M187, M383ExtendedPoint,
                                        M383ExtendedPoint.Scratchpad>
    implements M383Curve,
               Elligator2<ModE383M187, M383ExtendedPoint,
                          M383ExtendedPoint.Scratchpad> {
    /**
     * Scratchpads for extended M-383 points.
     */
    public static final class Scratchpad
        extends ExtendedTwistedEdwardsPoint.Scratchpad<ModE383M187> {

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
            super(new ModE383M187(0), new ModE383M187(0), new ModE383M187(0),
                  new ModE383M187(0), new ModE383M187(0), new ModE383M187(0),
                  ModE383M187.NUM_DIGITS);
        }

        /**
         * Get an instance of this {@code Scratchpad}.
         *
         * @return An instance of this {@code Scratchpad}.
         */
        public static Scratchpad get() {
            return scratchpads.get();
        }
    }

    private static final M383ExtendedPoint ZERO = new M383ExtendedPoint();

    /**
     * Initialize a {@code M383ExtendedPoint} with zero
     * coordinates.
     */
    private M383ExtendedPoint() {
        this(new ModE383M187(0), new ModE383M187(1),
             new ModE383M187(1), new ModE383M187(0));
    }

    /**
     * Initialize an {@code M383ExtendedPoint} with three scalar
     * objects.
     *
     * @param x The X coordinate value.
     * @param y The Y coordinate value.
     */
    protected M383ExtendedPoint(final ModE383M187 x,
                                final ModE383M187 y) {
        super(x, y);
    }

    /**
     * Initialize an {@code M383ExtendedPoint} with three scalar
     * objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     * @param t The scalar object for t.
     */
    protected M383ExtendedPoint(final ModE383M187 x,
                                final ModE383M187 y,
                                final ModE383M187 z,
                                final ModE383M187 t) {
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
    public M383ExtendedPoint clone() {
        return new M383ExtendedPoint(x.clone(), y.clone(),
                                     z.clone(), t.clone());
    }

    /**
     * Create a {@code M383ExtendedPoint} initialized as the
     * zero-point on the M-383 curve in extended coordinates.
     *
     * @return A zero point on the M-383 curve in extended
     *         coordinates.
     */
    public static M383ExtendedPoint zero() {
        return new M383ExtendedPoint();
    }

    /**
     * Create a {@code M383ExtendedPoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Edwards {@code x} coordinate.
     * @param y The Edwards {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static M383ExtendedPoint fromEdwards(final ModE383M187 x,
                                                final ModE383M187 y) {
        return new M383ExtendedPoint(x.clone(), y.clone());
    }

    /**
     * Create a {@code M383ExtendedPoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Montgomery {@code x} coordinate.
     * @param y The Montgomery {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static M383ExtendedPoint fromMontgomery(final ModE383M187 x,
                                                   final ModE383M187 y) {
        try(final Scratchpad scratch = Scratchpad.get()) {
            return fromMontgomery(x, y, scratch);
        }
    }

    /**
     * Create a {@code M383ExtendedPoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Montgomery {@code x} coordinate.
     * @param y The Montgomery {@code y} coordinate.
     * @param scratch The scratchpad to use.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static M383ExtendedPoint fromMontgomery(final ModE383M187 x,
                                                   final ModE383M187 y,
                                                   final Scratchpad scratch) {
        final ModE383M187 edwardsX = new ModE383M187(0);
        final ModE383M187 edwardsY = new ModE383M187(0);

        TwistedEdwardsPoint.montgomeryToEdwards(x, y, edwardsX,
                                                edwardsY, scratch);

        return new M383ExtendedPoint(edwardsX, edwardsY);
    }

    /**
     * Create a {@code M383ExtendedPoint} from a hash.
     *
     * @param r The hash input.
     * @return A point initialized by hashing {@code s} to a point.
     * @throws IllegalArgumentException If the hash input is invalid.
     */
    public static M383ExtendedPoint fromHash(final ModE383M187 r)
        throws IllegalArgumentException {
        try(final Scratchpad scratch = Scratchpad.get()) {
            return fromHash(r, scratch);
        }
    }

    /**
     * Create a {@code M383ExtendedPoint} from a hash.
     *
     * @param r The hash input.
     * @param scratch The scratchpad to use.
     * @return A point initialized by hashing {@code s} to a point.
     * @throws IllegalArgumentException If the hash input is invalid.
     */
    public static M383ExtendedPoint fromHash(final ModE383M187 r,
                                             final Scratchpad scratch)
        throws IllegalArgumentException {
        final M383ExtendedPoint p = zero();

        p.decodeHash(r, scratch);

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
