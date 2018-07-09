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
package net.metricspace.crypto.math.ec.group;

import net.metricspace.crypto.math.ec.curve.Curve41417Curve;
import net.metricspace.crypto.math.ec.point.Curve41417ExtendedPoint;
import net.metricspace.crypto.math.field.ModE414M17;

/**
 * The Curve41417 elliptic curve group.  This curve was introduced by
 * Bernstein, Chuengsatiansup, and Lange in their paper <a
 * href="https://cr.yp.to/ecdh/curve41417-20140706.pdf">"Curve41417:
 * Karatsuba Revisited"</a> and satisfies all criteria of the <a
 * href="https://safecurves.cr.yp.to/index.html">SafeCurves
 * project</a>.  It is defined by the equation {@code x^2 + y^2 = 1 +
 * 3673 * x^2 * y^2} over the prime field {@code mod 2^414 - 17}, and
 * provides roughly {@code 205.3} bits of security against the
 * Pollard-Rho attack.
 * <p>
 * This group uses the extended point representation.
 *
 * @see ModE414M17
 * @see net.metricspace.crypto.math.ec.curve.Curve41417Curve
 */
public class Curve41417Extended
    extends Curve41417<Curve41417ExtendedPoint>
    implements Curve41417Curve,
               ElligatorGroup<ModE414M17, Curve41417ExtendedPoint> {
    /**
     * The base point of the Curve41417 group.
     */
    private static Curve41417ExtendedPoint BASE_POINT =
        Curve41417ExtendedPoint.fromEdwards(baseX(), baseY());

    /**
     * The zero point of the Curve41417 group.
     */
    private static Curve41417ExtendedPoint ZERO_POINT =
        Curve41417ExtendedPoint.zero();

    /**
     * {@inheritDoc}
     */
    @Override
    public Curve41417ExtendedPoint fromEdwards(final ModE414M17 x,
                                               final ModE414M17 y) {
        return Curve41417ExtendedPoint.fromEdwards(x, y);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Curve41417ExtendedPoint fromHash(final ModE414M17 r) {
        return Curve41417ExtendedPoint.fromHash(r);
    }

    /**
     * {@inheritDoc}
     */
    public Curve41417ExtendedPoint basePoint() {
        return BASE_POINT.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Curve41417ExtendedPoint zeroPoint() {
        return ZERO_POINT.clone();
    }
}
