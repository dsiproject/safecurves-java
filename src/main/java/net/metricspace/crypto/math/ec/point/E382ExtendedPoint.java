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
import net.metricspace.crypto.math.ec.curve.E382Curve;
import net.metricspace.crypto.math.field.ModE382M105;

/**
 * Extended coordinates on the Edwards curve E-382.
 */
public class E382ExtendedPoint
    extends ExtendedEdwardsPoint<ModE382M105, E382ExtendedPoint>
    implements E382Curve {
    /**
     * Initialize a {@code E382ExtendedPoint} with zero coordinates.
     */
    private E382ExtendedPoint() {
        this(new ModE382M105(0), new ModE382M105(1),
             new ModE382M105(1), new ModE382M105(0));
    }

    /**
     * Initialize an {@code E382ExtendedPoint} with raw Edwards X
     * and Y coordinates.  This constructor takes possession of the
     * parameters.
     *
     * @param x The X coordinate value.
     * @param y The Y coordinate value.
     */
    protected E382ExtendedPoint(final ModE382M105 x,
                             final ModE382M105 y) {
        super(x, y);
    }

    /**
     * Initialize an {@code E382ExtendedPoint} with four scalar
     * objects.  This constructor takes possession of the parameters,
     * which are used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     * @param t The scalar object for t.
     */
    protected E382ExtendedPoint(final ModE382M105 x,
                                final ModE382M105 y,
                                final ModE382M105 z,
                                final ModE382M105 t) {
        super(x, y, z, t);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public E382ExtendedPoint clone() {
        return new E382ExtendedPoint(x.clone(), y.clone(),
                                     z.clone(), t.clone());
    }

    /**
     * Create a {@code E382ExtendedPoint} initialized as the
     * zero-point on the curve E-382 in extended coordinates.
     *
     * @return A zero point on the curve E-382 in extended
     *         coordinates.
     */
    public static E382ExtendedPoint zero() {
        return new E382ExtendedPoint();
    }

    /**
     * Create a {@code E382ExtendedPoint} initialized from Edwards
     * {@code x} and {@code y} points.
     *
     * @param x The Edwards {@code x} coordinate.
     * @param y The Edwards {@code y} coordinate.
     * @return A point initialized to the given Edwards {@code x} and
     *         {@code y} coordinates.
     */
    public static E382ExtendedPoint fromEdwards(final ModE382M105 x,
                                                final ModE382M105 y) {
        return new E382ExtendedPoint(x.clone(), y.clone());
    }
}