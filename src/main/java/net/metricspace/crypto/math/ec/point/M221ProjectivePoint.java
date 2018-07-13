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
import net.metricspace.crypto.math.ec.hash.Elligator2;
import net.metricspace.crypto.math.field.ModE221M3;

/**
 * Projective coordinates on the twisted Edwards curve birationally
 * equivalent to the Montgomery curve M-221.
 */
public class M221ProjectivePoint
    extends ProjectiveTwistedEdwardsPoint<ModE221M3, M221ProjectivePoint,
                                          M221ProjectivePoint.Scratchpad>
    implements M221Curve,
               Elligator2<ModE221M3, M221ProjectivePoint,
                          M221ProjectivePoint.Scratchpad> {
    /**
     * Scratchpads for projective M-221 points.
     */
    public static final class Scratchpad
        extends ProjectiveTwistedEdwardsPoint.Scratchpad<ModE221M3> {

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
                  new ModE221M3(0), new ModE221M3(0), new ModE221M3(0),
                  ModE221M3.NUM_DIGITS);
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

    private static final M221ProjectivePoint ZERO = new M221ProjectivePoint();

    /**
     * Initialize an {@code M221ProjectivePoint} with zero
     * coordinates.
     */
    private M221ProjectivePoint() {
        this(new ModE221M3(0), new ModE221M3(1), new ModE221M3(1));
    }

    /**
     * Initialize an {@code M221ProjectivePoint} with raw Edwards X
     * and Y coordinates.  This constructor takes possession of the
     * parameters.
     *
     * @param x The X coordinate value.
     * @param y The Y coordinate value.
     */
    protected M221ProjectivePoint(final ModE221M3 x,
                                  final ModE221M3 y) {
        this(x, y, new ModE221M3(1));
    }

    /**
     * Initialize an {@code M221ProjectivePoint} with three scalar
     * objects.  This constructor takes possession of the parameters,
     * which are used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     */
    protected M221ProjectivePoint(final ModE221M3 x,
                                  final ModE221M3 y,
                                  final ModE221M3 z) {
        super(x, y, z);
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
    public M221ProjectivePoint clone() {
        return new M221ProjectivePoint(x.clone(), y.clone(), z.clone());
    }

    /**
     * Create a {@code M221ProjectivePoint} initialized as the
     * zero-point on the curve M-221 in projective coordinates.
     *
     * @return A zero point on the curve M-221 in projective
     *         coordinates.
     */
    public static M221ProjectivePoint zero() {
        return new M221ProjectivePoint();
    }

    /**
     * Create a {@code M221ProjectivePoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Edwards {@code x} coordinate.
     * @param y The Edwards {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static M221ProjectivePoint fromEdwards(final ModE221M3 x,
                                                  final ModE221M3 y) {
        return new M221ProjectivePoint(x.clone(), y.clone());
    }

    /**
     * Create a {@code M221ProjectivePoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Montgomery {@code x} coordinate.
     * @param y The Montgomery {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static M221ProjectivePoint fromMontgomery(final ModE221M3 x,
                                                     final ModE221M3 y) {
        try(final Scratchpad scratch = Scratchpad.get()) {
            return fromMontgomery(x, y, scratch);
        }
    }

    /**
     * Create a {@code M221ProjectivePoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Montgomery {@code x} coordinate.
     * @param y The Montgomery {@code y} coordinate.
     * @param scratch The scratchpad to use.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static M221ProjectivePoint fromMontgomery(final ModE221M3 x,
                                                     final ModE221M3 y,
                                                     final Scratchpad scratch) {
        final ModE221M3 edwardsX = new ModE221M3(0);
        final ModE221M3 edwardsY = new ModE221M3(0);

        TwistedEdwardsPoint.montgomeryToEdwards(x, y, edwardsX,
                                                edwardsY, scratch);

        return new M221ProjectivePoint(edwardsX, edwardsY);
    }

    /**
     * Create a {@code M221ProjectivePoint} from a hash.
     *
     * @param s The hash input.
     * @return A point initialized by hashing {@code s} to a point.
     * @throws IllegalArgumentException If the hash input is invalid.
     */
    public static M221ProjectivePoint fromHash(final ModE221M3 s)
        throws IllegalArgumentException {
        final M221ProjectivePoint p = zero();

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
