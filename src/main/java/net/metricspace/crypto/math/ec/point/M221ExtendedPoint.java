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

import net.metricspace.crypto.math.ec.curve.M221Curve;
import net.metricspace.crypto.math.field.ModE221M3;

/**
 * Extended coordinates on the twisted Edwards curve birationally
 * equivalent to the Montgomery curve M-221.
 */
public class M221ExtendedPoint
    extends ExtendedTwistedEdwardsPoint<ModE221M3, M221ExtendedPoint,
                                        M221ExtendedPoint.Scratchpad>
    implements M221Curve {
    /**
     * Scratchpads for extended M-221 points.
     */
    public static final class Scratchpad
        extends ExtendedTwistedEdwardsPoint.Scratchpad<ModE221M3> {

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
            super(new ModE221M3(0), new ModE221M3(0), new ModE221M3(0),
                  new ModE221M3(0), new ModE221M3(0), new ModE221M3(0));
        }

        protected static Scratchpad get() {
            return scratchpads.get();
        }
    }

    private static final M221ExtendedPoint ZERO = new M221ExtendedPoint();

    /**
     * Initialize an {@code M221ExtendedPoint} with zero coordinates.
     */
    private M221ExtendedPoint() {
        this(new ModE221M3(0), new ModE221M3(1),
             new ModE221M3(1), new ModE221M3(0));
    }

    /**
     * Initialize an {@code M221ExtendedPoint} with raw Edwards X and
     * Y coordinates.  This constructor takes possession of the
     * parameters.
     *
     * @param x The X coordinate value.
     * @param y The Y coordinate value.
     */
    protected M221ExtendedPoint(final ModE221M3 x,
                                final ModE221M3 y) {
        super(x, y);
    }

    /**
     * Initialize an {@code M221ExtendedPoint} with four scalar
     * objects.  This constructor takes possession of the parameters,
     * which are used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     * @param t The scalar object for t.
     */
    protected M221ExtendedPoint(final ModE221M3 x,
                                final ModE221M3 y,
                                final ModE221M3 z,
                                final ModE221M3 t) {
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
    public M221ExtendedPoint clone() {
        return new M221ExtendedPoint(x.clone(), y.clone(),
                                     z.clone(), t.clone());
    }

    /**
     * Create a {@code M221ExtendedPoint} initialized as the
     * zero-point on the curve M-221 in extended coordinates.
     *
     * @return A zero point on the curve M-221 in extended
     *         coordinates.
     */
    public static M221ExtendedPoint zero() {
        return new M221ExtendedPoint();
    }

    /**
     * Create a {@code M221ExtendedPoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Edwards {@code x} coordinate.
     * @param y The Edwards {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static M221ExtendedPoint fromEdwards(final ModE221M3 x,
                                                final ModE221M3 y) {
        return new M221ExtendedPoint(x.clone(), y.clone());
    }

    /**
     * Create a {@code M221ExtendedPoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Montgomery {@code x} coordinate.
     * @param y The Montgomery {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static M221ExtendedPoint fromMontgomery(final ModE221M3 x,
                                                   final ModE221M3 y) {
        final ModE221M3 edwardsX = new ModE221M3(0);
        final ModE221M3 edwardsY = new ModE221M3(0);

        TwistedEdwardsPoint.montgomeryToEdwards(x, y, edwardsX, edwardsY);

        return new M221ExtendedPoint(edwardsX, edwardsY);
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
