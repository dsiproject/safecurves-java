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

import net.metricspace.crypto.math.ec.curve.M511Curve;
import net.metricspace.crypto.math.ec.point.M511ExtendedPoint;
import net.metricspace.crypto.math.field.ModE511M187;

/**
 * The M-511 elliptic curve.  This curve was introduced by Aranha,
 * Barreto, Periera, and Ricardini in their paper <a
 * href="https://eprint.iacr.org/2013/647.pdf">"A Note on
 * High-Security General-Purpose Elliptic Curves"</a>.  It is defined
 * by the Montgomery-form equation {@code y^2 = x^3 + 530438 * x^2 *
 * x} over the prime field {@code mod 2^511 - 187}, and the
 * corresponding group provides roughly {@code 253.8} bits of security
 * against the Pollard-Rho attack.
 * <p>
 * This curve is also birationally equivalent to the twisted Edwards
 * curve {@code 530440 * x^2 + y^2 = 1 + 530436 * x^2 * y^2}.
 * <p>
 * This group uses the extended point representation.
 *
 * @see ModE511M187
 * @see net.metricspace.crypto.math.ec.curve.M511Curve
 */
public class M511Extended
    extends M511<M511ExtendedPoint>
    implements M511Curve {
    /**
     * The base point of the M-511 group.
     */
    private static M511ExtendedPoint BASE_POINT =
        M511ExtendedPoint.fromMontgomery(baseX(), baseY());

    /**
     * The zero point of the M-511 group.
     */
    private static M511ExtendedPoint ZERO_POINT =
        M511ExtendedPoint.zero();

    /**
     * {@inheritDoc}
     */
    @Override
    public M511ExtendedPoint fromTwistedEdwards(final ModE511M187 x,
                                                final ModE511M187 y) {
        return M511ExtendedPoint.fromEdwards(x, y);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public M511ExtendedPoint fromMontgomery(final ModE511M187 x,
                                            final ModE511M187 y) {
        return M511ExtendedPoint.fromMontgomery(x, y);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public M511ExtendedPoint basePoint() {
        return BASE_POINT.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public M511ExtendedPoint zeroPoint() {
        return ZERO_POINT.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int cofactor() {
        return 8;
    }
}
