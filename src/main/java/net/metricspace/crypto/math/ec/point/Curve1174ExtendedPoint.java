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

import net.metricspace.crypto.math.ec.curve.Curve1174Curve;
import net.metricspace.crypto.math.ec.hash.Elligator1;
import net.metricspace.crypto.math.field.ModE251M9;

/**
 * Extended coordinates on the Edwards curve Curve1174.
 */
public class Curve1174ExtendedPoint
    extends ExtendedEdwardsPoint<ModE251M9, Curve1174ExtendedPoint,
                                 Curve1174ExtendedPoint.Scratchpad>
    implements Curve1174Curve,
               Elligator1<ModE251M9, Curve1174ExtendedPoint,
                          Curve1174ExtendedPoint.Scratchpad> {
    /**
     * Scratchpads for extended Curve1174 points.
     */
    public static final class Scratchpad
        extends ExtendedEdwardsPoint.Scratchpad<ModE251M9> {

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
            super(new ModE251M9(0), new ModE251M9(0), new ModE251M9(0),
                  new ModE251M9(0), new ModE251M9(0), new ModE251M9(0),
                  ModE251M9.NUM_DIGITS);
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

    /**
     * Initialize an {@code Curve1174ExtendedPoint} with zero
     * coordinates.
     */
    private Curve1174ExtendedPoint() {
        this(new ModE251M9(0), new ModE251M9(1),
             new ModE251M9(1), new ModE251M9(0));
    }

    /**
     * Initialize an {@code Curve1174ExtendedPoint} with raw Edwards X
     * and Y coordinates.  This constructor takes possession of the
     * parameters.
     *
     * @param x The X coordinate value.
     * @param y The Y coordinate value.
     */
    protected Curve1174ExtendedPoint(final ModE251M9 x,
                                     final ModE251M9 y) {
        super(x, y);
    }

    /**
     * Initialize an {@code Curve1174ExtendedPoint} with four scalar
     * objects.  This constructor takes possession of the parameters,
     * which are used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     * @param t The scalar object for t.
     */
    protected Curve1174ExtendedPoint(final ModE251M9 x,
                                     final ModE251M9 y,
                                     final ModE251M9 z,
                                     final ModE251M9 t) {
        super(x, y, z, t);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ModE251M9 elligatorS() {
        return Curve1174Curve.ELLIGATOR_S.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ModE251M9 elligatorR() {
        return Curve1174Curve.ELLIGATOR_R.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ModE251M9 elligatorC() {
        return Curve1174Curve.ELLIGATOR_C.clone();
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
    public Curve1174ExtendedPoint clone() {
        return new Curve1174ExtendedPoint(x.clone(), y.clone(),
                                          z.clone(), t.clone());
    }

    /**
     * Create a {@code Curve1174ExtendedPoint} initialized as the
     * zero-point on the Curve1174 curve in extended coordinates.
     *
     * @return A zero point on the Curve1174 curve in extended
     *         coordinates.
     */
    public static Curve1174ExtendedPoint zero() {
        return new Curve1174ExtendedPoint();
    }

    /**
     * Create a {@code Curve1174ExtendedPoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Edwards {@code x} coordinate.
     * @param y The Edwards {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static Curve1174ExtendedPoint fromEdwards(final ModE251M9 x,
                                                     final ModE251M9 y) {
        return new Curve1174ExtendedPoint(x.clone(), y.clone());
    }

    /**
     * Create a {@code Curve1174ExtendedPoint} from a hash.
     *
     * @param r The hash input.
     * @return A point initialized by hashing {@code s} to a point.
     * @throws IllegalArgumentException If the hash input is invalid.
     */
    public static Curve1174ExtendedPoint fromHash(final ModE251M9 r)
        throws IllegalArgumentException {
        try(final Scratchpad scratch = Scratchpad.get()) {
            return fromHash(r, scratch);
        }
    }

    /**
     * Create a {@code Curve1174ExtendedPoint} from a hash.
     *
     * @param r The hash input.
     * @param scratch The scratchpad to use.
     * @return A point initialized by hashing {@code r} to a point.
     * @throws IllegalArgumentException If the hash input is invalid.
     */
    public static Curve1174ExtendedPoint fromHash(final ModE251M9 r,
                                                  final Scratchpad scratch)
        throws IllegalArgumentException {
        final Curve1174ExtendedPoint p = zero();

        p.decodeHash(r, scratch);

        return p;
    }
}
