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

import net.metricspace.crypto.math.ec.curve.Curve41417Curve;
import net.metricspace.crypto.math.ec.hash.Elligator1;
import net.metricspace.crypto.math.field.ModE414M17;

/**
 * Extended coordinates on the Edwards curve Curve41417.
 */
public class Curve41417ExtendedPoint
    extends ExtendedEdwardsPoint<ModE414M17, Curve41417ExtendedPoint,
                                 Curve41417ExtendedPoint.Scratchpad>
    implements Curve41417Curve,
               Elligator1<ModE414M17, Curve41417ExtendedPoint,
                          Curve41417ExtendedPoint.Scratchpad> {
    /**
     * Scratchpads for extended Curve41417 points.
     */
    public static final class Scratchpad
        extends ExtendedEdwardsPoint.Scratchpad<ModE414M17> {

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
            super(new ModE414M17(0), new ModE414M17(0), new ModE414M17(0),
                  new ModE414M17(0), new ModE414M17(0), new ModE414M17(0));
        }

        protected static Scratchpad get() {
            return scratchpads.get();
        }
    }

    /**
     * Initialize an {@code Curve41417ExtendedPoint} with zero
     * coordinates.
     */
    private Curve41417ExtendedPoint() {
        this(new ModE414M17(0), new ModE414M17(1),
             new ModE414M17(1), new ModE414M17(0));
    }

    /**
     * Initialize an {@code Curve41417ExtendedPoint} with raw Edwards
     * X and Y coordinates.  This constructor takes possession of the
     * parameters.
     *
     * @param x The X coordinate value.
     * @param y The Y coordinate value.
     */
    protected Curve41417ExtendedPoint(final ModE414M17 x,
                                      final ModE414M17 y) {
        super(x, y);
    }

    /**
     * Initialize an {@code Curve41417ExtendedPoint} with four scalar
     * objects.  This constructor takes possession of the parameters,
     * which are used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     * @param t The scalar object for t.
     */
    protected Curve41417ExtendedPoint(final ModE414M17 x,
                                      final ModE414M17 y,
                                      final ModE414M17 z,
                                      final ModE414M17 t) {
        super(x, y, z, t);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ModE414M17 elligatorS() {
        return Curve41417Curve.ELLIGATOR_S.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ModE414M17 elligatorR() {
        return Curve41417Curve.ELLIGATOR_R.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ModE414M17 elligatorC() {
        return Curve41417Curve.ELLIGATOR_C.clone();
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
    public Curve41417ExtendedPoint clone() {
        return new Curve41417ExtendedPoint(x.clone(), y.clone(),
                                           z.clone(), t.clone());
    }

    /**
     * Create a {@code Curve41417ExtendedPoint} initialized as the
     * zero-point on the Curve41417 curve in extended coordinates.
     *
     * @return A zero point on the Curve41417 curve in extended
     *         coordinates.
     */
    public static Curve41417ExtendedPoint zero() {
        return new Curve41417ExtendedPoint();
    }

    /**
     * Create a {@code Curve41417ExtendedPoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Edwards {@code x} coordinate.
     * @param y The Edwards {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static Curve41417ExtendedPoint fromEdwards(final ModE414M17 x,
                                                      final ModE414M17 y) {
        return new Curve41417ExtendedPoint(x.clone(), y.clone());
    }

    /**
     * Create a {@code Curve41417ExtendedPoint} from a hash.
     *
     * @param s The hash input.
     * @return A point initialized by hashing {@code s} to a point.
     * @throws IllegalArgumentException If the hash input is invalid.
     */
    public static Curve41417ExtendedPoint fromHash(final ModE414M17 s)
        throws IllegalArgumentException {
        final Curve41417ExtendedPoint p = zero();

        p.decodeHash(s);

        return p;
    }
}
