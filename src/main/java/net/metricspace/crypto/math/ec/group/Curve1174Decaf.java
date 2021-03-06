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

import net.metricspace.crypto.math.ec.curve.Curve1174Curve;
import net.metricspace.crypto.math.ec.point.DecafPoint;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.ec.ladder.MontgomeryLadder;
import net.metricspace.crypto.math.field.ModE251M9;

/**
 * The Curve1174 elliptic curve group.  This curve was introduced by
 * Bernstein, Hamburg, Krasnova, and Lange in their paper <a
 * href="https://eprint.iacr.org/2013/325.pdf">"Elligator:
 * Elliptic-Curve Points Indistinguishable from Uniform Random
 * Strings"</a>.  It is defined by the equation {@code x^2 + y^2 = 1 -
 * 1174 * x^2 * y^2} over the prime field {@code mod 2^251 - 9}, and
 * provides roughly {@code 124.3} bits of security against the
 * Pollard-Rho attack.
 * <p>
 * Decaf point compression was described by Hamburg in his paper <a
 * href="https://eprint.iacr.org/2015/673.pdf">"Decaf: Eliminating
 * Cofactors through Point Compression"</a>.  It reduces the cofactor
 * by a factor of {@code 4}
 *
 * @param <P> The concrete point type.
 * @see ModE251M9
 * @see net.metricspace.crypto.math.ec.curve.Curve1174Curve
 */
public abstract class
    Curve1174Decaf<P extends DecafPoint<ModE251M9, P, T>,
                   T extends MontgomeryLadder.Scratchpad<ModE251M9>>
    extends Curve1174<P, T>
    implements DecafGroup<ModE251M9, P, T> {
    /**
     * The cofactor of Curve1174 is {@code 4}; decaf reduces this by
     * a factor of {@code 4} to {@code 1}.
     *
     * @return The value {@code 1}
     */
    @Override
    public int cofactor() {
        return 1;
    }
}
