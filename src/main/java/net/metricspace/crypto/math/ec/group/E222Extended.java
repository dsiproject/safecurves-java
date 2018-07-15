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

import net.metricspace.crypto.math.ec.curve.E222Curve;
import net.metricspace.crypto.math.ec.point.E222ExtendedPoint;
import net.metricspace.crypto.math.field.ModE222M117;

/**
 * The E-222 elliptic curve group.  This curve was introduced by
 * Aranha, Barreto, Periera, and Ricardini in their paper <a
 * href="https://eprint.iacr.org/2013/647.pdf">"A Note on
 * High-Security General-Purpose Elliptic Curves"</a> and satisfies
 * all criteria of the <a
 * href="https://safecurves.cr.yp.to/index.html">SafeCurves
 * project</a>.  It is defined by the equation {@code x^2 + y^2 = 1 +
 * 160102 * x^2 * y^2} over the prime field {@code mod 2^222 - 117},
 * and provides roughly {@code 109.8} bits of security against the
 * Pollard-Rho attack.
 * <p>
 * This group uses the extended point representation.
 *
 * @see ModE222M117
 * @see net.metricspace.crypto.math.ec.curve.E222Curve
 */
public class E222Extended
    extends E222<E222ExtendedPoint, E222ExtendedPoint.Scratchpad>
    implements E222Curve,
               ElligatorGroup<ModE222M117, E222ExtendedPoint,
                              E222ExtendedPoint.Scratchpad> {
    /**
     * The base point of the E-222 group.
     */
    private static E222ExtendedPoint BASE_POINT =
        E222ExtendedPoint.fromEdwards(baseX(), baseY());

    /**
     * The zero point of the E-222 group.
     */
    private static E222ExtendedPoint ZERO_POINT =
        E222ExtendedPoint.zero();

    /**
     * {@inheritDoc}
     */
    @Override
    public E222ExtendedPoint.Scratchpad scratchpad() {
        return E222ExtendedPoint.Scratchpad.get();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public E222ExtendedPoint
        fromEdwards(final ModE222M117 x,
                    final ModE222M117 y) {
        return E222ExtendedPoint.fromEdwards(x, y);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public E222ExtendedPoint
        fromHash(final ModE222M117 r,
                 final E222ExtendedPoint.Scratchpad scratch) {
        return E222ExtendedPoint.fromHash(r, scratch);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public E222ExtendedPoint basePoint() {
        return BASE_POINT.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public E222ExtendedPoint zeroPoint() {
        return ZERO_POINT.clone();
    }
}
