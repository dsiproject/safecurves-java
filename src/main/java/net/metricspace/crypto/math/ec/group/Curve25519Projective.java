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

import net.metricspace.crypto.math.ec.curve.Curve25519Curve;
import net.metricspace.crypto.math.ec.point.Curve25519ProjectivePoint;
import net.metricspace.crypto.math.field.ModE255M19;

/**
 * The Curve25519 elliptic curve.  This curve was introduced by
 * Bernstein in his paper <a
 * href="https://cr.yp.to/ecdh/curve25519-20060209.pdf">"Curve25519:
 * New Diffie-Hellman Speed Records"</a>.  It is defined
 * by the Montgomery-form equation {@code y^2 = x^3 + 486662 * x^2 *
 * x} over the prime field {@code mod 2^255 - 19}, and the
 * corresponding group provides roughly {@code 125.8} bits of security
 * against the Pollard-Rho attack.
 * <p>
 * The curve is also birationally equivalent to the twisted Edwards
 * curve {@code 486664 * x^2 + y^2 = 1 + 486660 * x^2 * y^2}.
 * <p>
 * This group uses the projective point representation.
 *
 * @see ModE255M19
 * @see net.metricspace.crypto.math.ec.curve.Curve25519Curve
 */
public class Curve25519Projective
    extends Curve25519<Curve25519ProjectivePoint>
    implements Curve25519Curve {
    /**
     * The base point of the Curve25519 group.
     */
    private static Curve25519ProjectivePoint BASE_POINT =
        Curve25519ProjectivePoint.fromMontgomery(baseX(), baseY());

    /**
     * The zero point of the Curve25519 group.
     */
    private static Curve25519ProjectivePoint ZERO_POINT =
        Curve25519ProjectivePoint.zero();

    /**
     * {@inheritDoc}
     */
    @Override
    public Curve25519ProjectivePoint fromTwistedEdwards(final ModE255M19 x,
                                                        final ModE255M19 y) {
        return Curve25519ProjectivePoint.fromEdwards(x, y);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Curve25519ProjectivePoint fromMontgomery(final ModE255M19 x,
                                                    final ModE255M19 y) {
        return Curve25519ProjectivePoint.fromMontgomery(x, y);
    }

    /**
     * {@inheritDoc}
     */
    public Curve25519ProjectivePoint basePoint() {
        return BASE_POINT.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Curve25519ProjectivePoint zeroPoint() {
        return ZERO_POINT.clone();
    }

    /**
     * {@inheritDoc}
     */
    public int cofactor() {
        return 8;
    }
}
