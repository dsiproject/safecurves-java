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

import net.metricspace.crypto.math.ec.curve.E521Curve;
import net.metricspace.crypto.math.ec.point.E521DecafExtendedPoint;
import net.metricspace.crypto.math.field.ModE521M1;

/**
 * The E-521 elliptic curve.  This curve was introduced independently
 * by three parties: Bernstein and Lange, Hamburg, and Aranha,
 * Barreto, Periera, and Ricardini in their paper <a
 * href="https://eprint.iacr.org/2013/647.pdf">"A Note on
 * High-Security General-Purpose Elliptic Curves"</a>.  It is defined
 * by the equation {@code x^2 + y^2 = 1 - 376014 * x^2 * y^2} over the
 * prime field {@code mod 2^521 - 1}, and the corresponding group
 * provides roughly {@code 259.3} bits of security against the
 * Pollard-Rho attack.
 * <p>
 * This group uses the extended point representation.
 *
 * @see ModE521M1
 * @see net.metricspace.crypto.math.ec.curve.E521Curve
 */
public class E521DecafExtended
    extends E521Decaf<E521DecafExtendedPoint>
    implements E521Curve,
               ElligatorGroup<ModE521M1, E521DecafExtendedPoint> {
    /**
     * The base point of the E-521 group.
     */
    private static E521DecafExtendedPoint BASE_POINT =
        E521DecafExtendedPoint.fromEdwards(baseX(), baseY());

    /**
     * The zero point of the E-521 group.
     */
    private static E521DecafExtendedPoint ZERO_POINT =
        E521DecafExtendedPoint.zero();

    /**
     * {@inheritDoc}
     */
    @Override
    public E521DecafExtendedPoint fromEdwards(final ModE521M1 x,
                                              final ModE521M1 y) {
        return E521DecafExtendedPoint.fromEdwards(x, y);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public E521DecafExtendedPoint fromCompressed(final ModE521M1 s)
        throws IllegalArgumentException {
        return E521DecafExtendedPoint.fromCompressed(s);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public E521DecafExtendedPoint fromHash(final ModE521M1 r) {
        return E521DecafExtendedPoint.fromHash(r);
    }

    /**
     * {@inheritDoc}
     */
    public E521DecafExtendedPoint basePoint() {
        return BASE_POINT.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public E521DecafExtendedPoint zeroPoint() {
        return ZERO_POINT.clone();
    }
}
