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

import net.metricspace.crypto.math.ec.curve.E521Curve;
import net.metricspace.crypto.math.field.ModE521M1;

/**
 * Projective coordinates on the Edwards curve E-521.
 */
public class E521ProjectivePoint
    extends ProjectiveEdwardsPoint<ModE521M1, E521ProjectivePoint,
                                   E521ProjectivePoint.Scratchpad>
    implements E521Curve {
    /**
     * Scratchpads for projective E-521 points.
     */
    public static final class Scratchpad
        extends ProjectiveEdwardsPoint.Scratchpad<ModE521M1> {

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
            super(new ModE521M1(0), new ModE521M1(0), new ModE521M1(0),
                  new ModE521M1(0), new ModE521M1(0), new ModE521M1(0),
                  new ModE521M1(0));
        }

        protected static Scratchpad get() {
            return scratchpads.get();
        }
    }

    /**
     * Initialize a {@code E521ProjectivePoint} with zero coordinates.
     */
    private E521ProjectivePoint() {
        this(new ModE521M1(0), new ModE521M1(1), new ModE521M1(1));
    }

    /**
     * Initialize an {@code E521ProjectivePoint} with raw Edwards X
     * and Y coordinates.  This constructor takes possession of the
     * parameters.
     *
     * @param x The X coordinate value.
     * @param y The Y coordinate value.
     */
    protected E521ProjectivePoint(final ModE521M1 x,
                                  final ModE521M1 y) {
        this(x, y, new ModE521M1(1));
    }

    /**
     * Initialize an {@code E521ProjectivePoint} with three scalar
     * objects.  This constructor takes possession of the parameters,
     * which are used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     */
    protected E521ProjectivePoint(final ModE521M1 x,
                                  final ModE521M1 y,
                                  final ModE521M1 z) {
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
    public E521ProjectivePoint clone() {
        return new E521ProjectivePoint(x.clone(), y.clone(), z.clone());
    }

    /**
     * Create a {@code E521ProjectivePoint} initialized as the
     * zero-point on the curve E-521 in projective coordinates.
     *
     * @return A zero point on the curve E-521 in projective
     *         coordinates.
     */
    public static E521ProjectivePoint zero() {
        return new E521ProjectivePoint();
    }

    /**
     * Create a {@code E521ProjectivePoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Edwards {@code x} coordinate.
     * @param y The Edwards {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static E521ProjectivePoint fromEdwards(final ModE521M1 x,
                                                  final ModE521M1 y) {
        return new E521ProjectivePoint(x.clone(), y.clone());
    }
}
