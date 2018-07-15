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

import javax.security.auth.Destroyable;

import net.metricspace.crypto.math.ec.group.ECGroup;
import net.metricspace.crypto.math.ec.point.ECPoint;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * Elliptic-curve group parameters.  This is the main interface for
 * definitions of a specific curve.
 *
 * @param <S> Type of scalar values.
 * @param <P> Type of points.
 */
public interface ECGroup<S extends PrimeField<S>,
                         P extends ECPoint<S, P, ?>,
                         T extends ECPoint.Scratchpad<S>> {
    /**
     * Get a scratchpad.  This is a mechanism designed to avoid
     * repeated allocation of scalar values.  Sequences of operations
     * should obtain a scratchpad, pass it into all operations, then
     * destroy it when through.
     *
     * @return A scratchpad.
     */
    public T scratchpad();

    /**
     * Get the prime order of the group.
     *
     * @return The prime order of the group.
     */
    public S primeOrder();

    /**
     * Get the cofactor of the group.
     *
     * @return The cofactor of the group.
     */
    public int cofactor();

    /**
     * The base point (generator).  This serves as {@code 1} in the
     * group.
     *
     * @return The base point.
     */
    public P basePoint();

    /**
     * The point which serves as {@code 0} in the group.
     *
     * @return The zero point.
     */
    public P zeroPoint();

    /**
     * Create a point from a coordinate pair.
     *
     * @param x The x coordinate.
     * @param y The y coordinate.
     * @return The point.
     */
    public P fromCoords(final S x,
                        final S y);
}
