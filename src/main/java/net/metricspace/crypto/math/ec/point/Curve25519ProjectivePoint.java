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

import net.metricspace.crypto.math.ec.MontgomeryLadder;
import net.metricspace.crypto.math.ec.curve.Curve25519Curve;
import net.metricspace.crypto.math.field.ModE255M19;

/**
 * Projective coordinates on the twisted Edwards curve birationally
 * equivalent to the Montgomery curve Curve25519.
 */
public class Curve25519ProjectivePoint
    extends ProjectiveTwistedEdwardsPoint<ModE255M19, Curve25519ProjectivePoint>
    implements Curve25519Curve {
    /**
     * Initialize a {@code Curve25519ProjectivePoint} with zero
     * coordinates.
     */
    private Curve25519ProjectivePoint() {
        this(new ModE255M19(0), new ModE255M19(1), new ModE255M19(1));
    }

    /**
     * Initialize an {@code Curve25519ProjectivePoint} with raw
     * Edwards X and Y coordinates.  This constructor takes possession
     * of the parameters.
     *
     * @param x The X coordinate value.
     * @param y The Y coordinate value.
     */
    protected Curve25519ProjectivePoint(final ModE255M19 x,
                                        final ModE255M19 y) {
        this(x, y, new ModE255M19(1));
    }

    /**
     * Initialize an {@code Curve25519ProjectivePoint} with three scalar
     * objects.  This constructor takes possession of the parameters,
     * which are used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     */
    protected Curve25519ProjectivePoint(final ModE255M19 x,
                                        final ModE255M19 y,
                                        final ModE255M19 z) {
        super(x, y, z);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Curve25519ProjectivePoint clone() {
        return new Curve25519ProjectivePoint(x.clone(), y.clone(), z.clone());
    }

    /**
     * Create a {@code Curve25519ProjectivePoint} initialized as the
     * zero-point on the Curve25519 curve in projective coordinates.
     *
     * @return A zero point on the Curve25519 curve in projective
     *         coordinates.
     */
    public static Curve25519ProjectivePoint zero() {
        return new Curve25519ProjectivePoint();
    }

    /**
     * Create a {@code Curve25519ProjectivePoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Edwards {@code x} coordinate.
     * @param y The Edwards {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static Curve25519ProjectivePoint fromEdwards(final ModE255M19 x,
                                                        final ModE255M19 y) {
        return new Curve25519ProjectivePoint(x.clone(), y.clone());
    }

    /**
     * Create a {@code Curve25519ProjectivePoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Montgomery {@code x} coordinate.
     * @param y The Montgomery {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static Curve25519ProjectivePoint fromMontgomery(final ModE255M19 x,
                                                           final ModE255M19 y) {
        final ModE255M19 edwardsX = new ModE255M19(0);
        final ModE255M19 edwardsY = new ModE255M19(0);

        TwistedEdwardsPoint.montgomeryToEdwards(x, y, edwardsX, edwardsY);

        return new Curve25519ProjectivePoint(edwardsX, edwardsY);
    }
}