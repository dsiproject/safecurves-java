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
package net.metricspace.crypto.math.ec;

import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * {@link ECPoint}s that implement point multiplication using a
 * Montgomery ladder algorithm.  This interface can be inherited from
 * to provide a complete implementation.  Additionally, specific point
 * representations with a more efficient individual ladder step can
 * override {@link MontgomeryLadder#ladderStep}.
 *
 * @param <S> Scalar values.
 * @param <P> Point type used as an argument.
 */
public interface MontgomeryLadder<S extends PrimeField<S>,
                                  P extends MontgomeryLadder<S, P>>
    extends ECPoint<S, P> {
    /**
     * {@inheritDoc}
     */
    @Override
    public default void mul(final S scalar) {
        final P r1 = this.clone();

        reset();

        final P r2 = this.clone();
        final P r3 = this.clone();

        for(int i = scalar.numBits(); i >= 0; i--) {
            final long bit = scalar.bit(i);

            ladderStep(bit, r1, r2, r3);
        }
    }

    /**
     * One step on the Montgomery ladder.  The expected behavior of
     * this function is:
     * <pre>
     * {@code
     * if (bit == 0)
     *   R1 = R0 + R1
     *   R0 = 2 * R0
     * else
     *   R0 = R0 + R1
     *   R1 = 2 * R1
     * }
     * </pre>
     * <p>
     * The default implementation performs both branches, optionally
     * zeroes out branches using {@link #reset(long)}, then sums both
     * branches.  This implements a completely branch-free Ladder step
     * at the cost of execution time.
     *
     * @param bit The digit of the scalar value for this ladder step.
     * @param r1 The {@code R1} scalar in the ladder algorithm.
     * @param r2 A scratchpad scalar.
     * @param r3 A second scratchpad scalar.
     * @see #reset(long)
     */
    public default void ladderStep(final long bit,
                                   final P r1,
                                   final P r2,
                                   final P r3) {
        final long negbit = bit ^ 0x1;

        r3.set(r1);
        this.copyTo(r2);

        /* Zero branch */
        r3.add(r2);
        r2.dbl();
        r3.reset(negbit);
        r2.reset(negbit);

        /* One branch */
        this.add(r1);
        r1.dbl();
        this.reset(bit);
        r1.reset(bit);

        /* Recombination */
        r1.add(r3);
        this.add(r2);
    }
}
