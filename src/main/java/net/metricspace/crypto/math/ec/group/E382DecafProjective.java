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

import net.metricspace.crypto.math.ec.curve.E382Curve;
import net.metricspace.crypto.math.ec.point.E382DecafProjectivePoint;
import net.metricspace.crypto.math.field.ModE382M105;

/**
 * The E-382 elliptic curve group with Decaf point compression.  This
 * curve was introduced by Aranha, Barreto, Periera, and Ricardini in
 * their paper <a href="https://eprint.iacr.org/2013/647.pdf">"A Note
 * on High-Security General-Purpose Elliptic Curves"</a> and satisfies
 * all criteria of the <a
 * href="https://safecurves.cr.yp.to/index.html">SafeCurves
 * project</a>.  It is defined by the equation {@code x^2 + y^2 = 1 -
 * 67254 * x^2 * y^2} over the prime field {@code mod 2^382 - 105},
 * and provides roughly {@code 189.8} bits of security against the
 * Pollard-Rho attack.
 * <p>
 * Decaf point compression was described by Hamburg in his paper <a
 * href="https://eprint.iacr.org/2015/673.pdf">"Decaf: Eliminating
 * Cofactors through Point Compression"</a>.  It reduces the cofactor
 * by a factor of {@code 4}
 * <p>
 * This group uses the projective point representation.
 *
 * @see ModE382M105
 * @see net.metricspace.crypto.math.ec.curve.E382Curve
 */
public class E382DecafProjective
    extends E382Decaf<E382DecafProjectivePoint,
                      E382DecafProjectivePoint.Scratchpad>
    implements E382Curve,
               ElligatorGroup<ModE382M105, E382DecafProjectivePoint,
                              E382DecafProjectivePoint.Scratchpad> {
    /**
     * The base point of the E-382 group.
     */
    private static E382DecafProjectivePoint BASE_POINT =
        E382DecafProjectivePoint.fromEdwards(baseX(), baseY());

    /**
     * The zero point of the E-382 group.
     */
    private static E382DecafProjectivePoint ZERO_POINT =
        E382DecafProjectivePoint.zero();

    /**
     * {@inheritDoc}
     */
    @Override
    public E382DecafProjectivePoint.Scratchpad scratchpad() {
        return E382DecafProjectivePoint.Scratchpad.get();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public E382DecafProjectivePoint
        fromEdwards(final ModE382M105 x,
                    final ModE382M105 y) {
        return E382DecafProjectivePoint.fromEdwards(x, y);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public E382DecafProjectivePoint
        fromCompressed(final ModE382M105 s,
                       final E382DecafProjectivePoint.Scratchpad scratch)
        throws IllegalArgumentException {
        return E382DecafProjectivePoint.fromCompressed(s, scratch);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public E382DecafProjectivePoint
        fromHash(final ModE382M105 r,
                 final E382DecafProjectivePoint.Scratchpad scratch) {
        return E382DecafProjectivePoint.fromHash(r, scratch);
    }

    /**
     * {@inheritDoc}
     */
    public E382DecafProjectivePoint basePoint() {
        return BASE_POINT.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public E382DecafProjectivePoint zeroPoint() {
        return ZERO_POINT.clone();
    }
}
