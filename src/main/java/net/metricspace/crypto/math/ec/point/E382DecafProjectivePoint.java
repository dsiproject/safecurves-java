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

import net.metricspace.crypto.math.ec.curve.E382Curve;
import net.metricspace.crypto.math.ec.hash.ElligatorDecaf;
import net.metricspace.crypto.math.field.ModE382M105;

/**
 * Projective coordinates on the Edwards curve E-382 with Decaf point
 * compression.
 */
public class E382DecafProjectivePoint
    extends ProjectiveEdwardsDecafPoint<ModE382M105, E382DecafProjectivePoint,
                                        E382DecafProjectivePoint.Scratchpad>
    implements E382Curve,
               ElligatorDecaf<ModE382M105, E382DecafProjectivePoint,
                              E382DecafProjectivePoint.Scratchpad> {
    /**
     * Scratchpads for projective E-382 points.
     */
    public static final class Scratchpad
        extends ProjectiveEdwardsPoint.Scratchpad<ModE382M105> {

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
            super(new ModE382M105(0), new ModE382M105(0), new ModE382M105(0),
                  new ModE382M105(0), new ModE382M105(0), new ModE382M105(0),
                  new ModE382M105(0));
        }

        protected static Scratchpad get() {
            return scratchpads.get();
        }
    }

    /**
     * Initialize a {@code E382DecafProjectivePoint} with zero coordinates.
     */
    private E382DecafProjectivePoint() {
        this(new ModE382M105(0), new ModE382M105(1), new ModE382M105(1));
    }

    /**
     * Initialize an {@code E382DecafProjectivePoint} with raw Edwards X
     * and Y coordinates.  This constructor takes possession of the
     * parameters.
     *
     * @param x The X coordinate value.
     * @param y The Y coordinate value.
     */
    protected E382DecafProjectivePoint(final ModE382M105 x,
                                       final ModE382M105 y) {
        this(x, y, new ModE382M105(1));
    }

    /**
     * Initialize an {@code E382DecafProjectivePoint} with three scalar
     * objects.  This constructor takes possession of the parameters,
     * which are used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     */
    protected E382DecafProjectivePoint(final ModE382M105 x,
                                       final ModE382M105 y,
                                       final ModE382M105 z) {
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
    public E382DecafProjectivePoint clone() {
        return new E382DecafProjectivePoint(x.clone(), y.clone(), z.clone());
    }

    /**
     * Create a {@code E382DecafProjectivePoint} initialized as the
     * zero-point on the curve E-222 in projective coordinates.
     *
     * @return A zero point on the curve E-222 in projective
     *         coordinates.
     */
    public static E382DecafProjectivePoint zero() {
        return new E382DecafProjectivePoint();
    }

    /**
     * Create a {@code E382DecafProjectivePoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Edwards {@code x} coordinate.
     * @param y The Edwards {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static E382DecafProjectivePoint fromEdwards(final ModE382M105 x,
                                                       final ModE382M105 y) {
        return new E382DecafProjectivePoint(x.clone(), y.clone());
    }

    /**
     * Create a {@code E382DecafProjectivePoint} by decompressing a
     * compressed point.
     *
     * @param s The compressed point.
     * @return A point initialized by decompressing {@code s}
     * @throws IllegalArgumentException If the compressed point is invalid.
     */
    public static E382DecafProjectivePoint fromCompressed(final ModE382M105 s)
        throws IllegalArgumentException {
        final E382DecafProjectivePoint p = zero();

        p.decompress(s);

        return p;
    }

    /**
     * Create a {@code E382DecafProjectivePoint} from a hash.
     *
     * @param s The hash input.
     * @return A point initialized by hashing {@code s} to a point.
     * @throws IllegalArgumentException If the hash input is invalid.
     */
    public static E382DecafProjectivePoint fromHash(final ModE382M105 s)
        throws IllegalArgumentException {
        final E382DecafProjectivePoint p = zero();

        p.decodeHash(s);

        return p;
    }
}
