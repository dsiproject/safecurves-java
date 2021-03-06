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

import net.metricspace.crypto.math.ec.curve.EdwardsCurve;
import net.metricspace.crypto.math.ec.ladder.MontgomeryLadder;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * Projective Edwards curve points, as described Bernstein and Lange's
 * paper <a
 * href="https://cr.yp.to/newelliptic/newelliptic-20070906.pdf">"Faster
 * Addition and Doubling on Elliptic Curves"</a>.  Curve points are
 * represented as a triple, {@code (X, Y, Z)}, where {@code X = x/Z},
 * {@code Y = y/Z}, where {@code x} and {@code y} are the original
 * curve coordinates.
 * <p>
 * Decaf point compression was described by Hamburg in his paper <a
 * href="https://eprint.iacr.org/2015/673.pdf">"Decaf: Eliminating
 * Cofactors through Point Compression"</a>.  It reduces the cofactor
 * by a factor of {@code 4}
 *
 * @param <S> Scalar values.
 * @param <P> Point type used as an argument.
 */
public abstract class
    ProjectiveEdwardsDecafPoint<S extends PrimeField<S>,
                                P extends ProjectiveEdwardsDecafPoint<S, P, T>,
                                T extends ProjectiveEdwardsPoint.Scratchpad<S>>
    extends ProjectiveEdwardsPoint<S, P, T>
    implements EdwardsDecafPoint<S, P, T> {
    /**
     * Initialize a {@code ProjectiveEdwardsPoint} with three scalar
     * objects.  This constructor takes possession of the parameters,
     * which are used as the coordinate objects.
     *
     * @param x The scalar object for x.
     * @param y The scalar object for y.
     * @param z The scalar object for z.
     */
    protected ProjectiveEdwardsDecafPoint(final S x,
                                          final S y,
                                          final S z) {
        super(x, y, z);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean mmequals(final ProjectivePoint<S, P, T> other) {
        try(final T scratch = scratchpad()) {
            return mmequals(other, scratch);
        }
    }

    /**
     * Compare against a point, when both points are scaled, using a
     * scratchpad..
     *
     * @param other The point against which to compare.
     * @return Whether this point is equal to {@code other}.
     */
    private boolean mmequals(final ProjectivePoint<S, P, T> other,
                            final T scratch) {
        final S r0 = scratch.r0;
        final S r1 = scratch.r1;

        r0.set(x);
        r1.set(other.x);
        r0.mul(other.y);
        r1.mul(y);

        return r0.equals(r1);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public S compress(final T scratch) {
        return DecafPoint.compress(edwardsD(), x, y, z, scratch);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decompress(final S s,
                           final T scratch)
        throws IllegalArgumentException {
        DecafPoint.decompress(edwardsD(), s, x, y, z, scratch);
    }
}
