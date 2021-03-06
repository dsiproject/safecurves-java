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

import net.metricspace.crypto.math.ec.curve.M221Curve;
import net.metricspace.crypto.math.ec.point.M221ExtendedPoint;
import net.metricspace.crypto.math.field.ModE221M3;

/**
 * The M-221 elliptic curve.  This curve was introduced by Aranha,
 * Barreto, Periera, and Ricardini in their paper <a
 * href="https://eprint.iacr.org/2013/647.pdf">"A Note on
 * High-Security General-Purpose Elliptic Curves"</a>.  It is defined
 * by the Montgomery-form equation {@code y^2 = x^3 + 117050 * x^2 *
 * x} over the prime field {@code mod 2^221 - 3}, and provides roughly
 * {@code 108.8} bits of security against the Pollard-Rho attack.
 * <p>
 * This curve is also birationally equivalent to the twisted Edwards
 * curve {@code 117052 * x^2 + y^2 = 1 + 117048 * x^2 * y^2}.
 * <p>
 * This group uses the extended point representation.
 *
 * @see ModE221M3
 * @see net.metricspace.crypto.math.ec.curve.M221Curve
 */
public class M221Extended
    extends M221<M221ExtendedPoint, M221ExtendedPoint.Scratchpad>
    implements M221Curve,
               ElligatorGroup<ModE221M3, M221ExtendedPoint,
                                  M221ExtendedPoint.Scratchpad> {
    /**
     * The base point of the M-221 group.
     */
    private static M221ExtendedPoint BASE_POINT =
        M221ExtendedPoint.fromMontgomery(baseX(), baseY());

    /**
     * The zero point of the M-221 group.
     */
    private static M221ExtendedPoint ZERO_POINT =
        M221ExtendedPoint.fromEdwards(ModE221M3.zero(),
                                      ModE221M3.one());

    /**
     * {@inheritDoc}
     */
    @Override
    public M221ExtendedPoint.Scratchpad scratchpad() {
        return M221ExtendedPoint.Scratchpad.get();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public M221ExtendedPoint
        fromTwistedEdwards(final ModE221M3 x,
                           final ModE221M3 y) {
        return M221ExtendedPoint.fromEdwards(x, y);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public M221ExtendedPoint
        fromMontgomery(final ModE221M3 x,
                       final ModE221M3 y,
                       final M221ExtendedPoint.Scratchpad scratch) {
        return M221ExtendedPoint.fromMontgomery(x, y, scratch);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public M221ExtendedPoint
        fromHash(final ModE221M3 r,
                 final M221ExtendedPoint.Scratchpad scratch) {
        return M221ExtendedPoint.fromHash(r, scratch);
    }

    /**
     * {@inheritDoc}
     */
    public M221ExtendedPoint basePoint() {
        return BASE_POINT.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public M221ExtendedPoint zeroPoint() {
        return ZERO_POINT.clone();
    }

    /**
     * {@inheritDoc}
     */
    public int cofactor() {
        return 8;
    }
}
