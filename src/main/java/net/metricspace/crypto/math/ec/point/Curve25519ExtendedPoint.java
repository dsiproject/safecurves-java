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

import net.metricspace.crypto.math.ec.curve.Curve25519Curve;
import net.metricspace.crypto.math.ec.hash.Elligator2;
import net.metricspace.crypto.math.field.ModE255M19;

/**
 * Extended coordinates on the twisted Edwards curve birationally
 * equivalent to the Montgomery curve Curve25519.
 */
public class Curve25519ExtendedPoint
    extends ExtendedTwistedEdwardsPoint<ModE255M19, Curve25519ExtendedPoint,
                                        Curve25519ExtendedPoint.Scratchpad>
    implements Curve25519Curve,
               Elligator2<ModE255M19, Curve25519ExtendedPoint,
                          Curve25519ExtendedPoint.Scratchpad> {
    /**
     * Scratchpads for extended Curve25519 points.
     */
    public static final class Scratchpad
        extends ExtendedTwistedEdwardsPoint.Scratchpad<ModE255M19> {

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
            super(new ModE255M19(0), new ModE255M19(0), new ModE255M19(0),
                  new ModE255M19(0), new ModE255M19(0), new ModE255M19(0),
                  ModE255M19.NUM_DIGITS);
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

    private static final Curve25519ExtendedPoint ZERO =
        new Curve25519ExtendedPoint();

    /**
     * Initialize a {@code Curve25519ExtendedPoint} with zero
     * coordinates.
     */
    private Curve25519ExtendedPoint() {
        this(new ModE255M19(0), new ModE255M19(1),
             new ModE255M19(1), new ModE255M19(0));
    }

    /**
     * Initialize an {@code Curve25519ExtendedPoint} with raw Edwards
     * X and Y coordinates.  This constructor takes possession
     * of the parameters.
     *
     * @param x The X coordinate value.
     * @param y The Y coordinate value.
     */
    protected Curve25519ExtendedPoint(final ModE255M19 x,
                                      final ModE255M19 y) {
        super(x, y);
    }

    /**
     * Initialize an {@code Curve25519ExtendedPoint} with four scalar
     * objects.  This constructor takes possession of the parameters,
     * which are used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     * @param t The scalar object for t.
     */
    protected Curve25519ExtendedPoint(final ModE255M19 x,
                                      final ModE255M19 y,
                                      final ModE255M19 z,
                                      final ModE255M19 t) {
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
    public Curve25519ExtendedPoint clone() {
        return new Curve25519ExtendedPoint(x.clone(), y.clone(),
                                           z.clone(), t.clone());
    }

    /**
     * Create a {@code Curve25519ExtendedPoint} initialized as the
     * zero-point on the Curve25519 curve in extended coordinates.
     *
     * @return A zero point on the Curve25519 curve in extended
     *         coordinates.
     */
    public static Curve25519ExtendedPoint zero() {
        return new Curve25519ExtendedPoint();
    }

    /**
     * Create a {@code Curve25519ExtendedPoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Edwards {@code x} coordinate.
     * @param y The Edwards {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static Curve25519ExtendedPoint fromEdwards(final ModE255M19 x,
                                                      final ModE255M19 y) {
        return new Curve25519ExtendedPoint(x.clone(), y.clone());
    }

    /**
     * Create a {@code Curve25519ExtendedPoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Montgomery {@code x} coordinate.
     * @param y The Montgomery {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static Curve25519ExtendedPoint fromMontgomery(final ModE255M19 x,
                                                         final ModE255M19 y) {
        try(final Scratchpad scratch = Scratchpad.get()) {
            return fromMontgomery(x, y, scratch);
        }
    }

    /**
     * Create a {@code Curve25519ExtendedPoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Montgomery {@code x} coordinate.
     * @param y The Montgomery {@code y} coordinate.
     * @param scratch The scratchpad to use.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static Curve25519ExtendedPoint
        fromMontgomery(final ModE255M19 x,
                       final ModE255M19 y,
                       final Scratchpad scratch) {
        final ModE255M19 edwardsX = new ModE255M19(0);
        final ModE255M19 edwardsY = new ModE255M19(0);

        TwistedEdwardsPoint.montgomeryToEdwards(x, y, edwardsX,
                                                edwardsY, scratch);

        return new Curve25519ExtendedPoint(edwardsX, edwardsY);
    }

    /**
     * Create a {@code Curve25519ExtendedPoint} from a hash.
     *
     * @param r The hash input.
     * @return A point initialized by hashing {@code s} to a point.
     * @throws IllegalArgumentException If the hash input is invalid.
     */
    public static Curve25519ExtendedPoint fromHash(final ModE255M19 r)
        throws IllegalArgumentException {
        try(final Scratchpad scratch = Scratchpad.get()) {
            return fromHash(r, scratch);
        }
    }

    /**
     * Create a {@code Curve25519ExtendedPoint} from a hash.
     *
     * @param r The hash input.
     * @param scratch The scratchpad to use.
     * @return A point initialized by hashing {@code s} to a point.
     * @throws IllegalArgumentException If the hash input is invalid.
     */
    public static Curve25519ExtendedPoint fromHash(final ModE255M19 s,
                                                   final Scratchpad scratch)
        throws IllegalArgumentException {
        final Curve25519ExtendedPoint p = zero();

        p.decodeHash(s, scratch);

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
