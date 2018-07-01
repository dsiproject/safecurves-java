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

import java.lang.IllegalArgumentException;

import net.metricspace.crypto.math.ec.ladder.MontgomeryLadder;
import net.metricspace.crypto.math.field.PrimeField;

/**
 * Points supporting Decaf point compression. Decaf point compression
 * was described by Hamburg in his paper <a
 * href="https://eprint.iacr.org/2015/673.pdf">"Decaf: Eliminating
 * Cofactors through Point Compression"</a>.  It reduces the cofactor
 * by a factor of {@code 4}
 *
 * @param <C> The type of compressed points.
 */
public interface DecafPoint<S extends PrimeField<S>,
                            P extends DecafPoint<S, P, T>,
                            T extends MontgomeryLadder.Scratchpad<S>>
    extends CompressablePoint<S, P, T, S>,
            MontgomeryLadder<S, P, T> {
    /**
     * Compress raw projective Edwards coordinates.
     *
     * @param d The Edwards curve {@code d} parameter.
     * @param x The {@code x}-coordinate.
     * @param y The {@code y}-coordinate.
     * @param z The {@code z}-coordinate.
     * @param scratch The scratchpad.
     */
    public static <S extends PrimeField<S>,
                   T extends MontgomeryLadder.Scratchpad<S>>
        S compress(final int d,
                   final S x,
                   final S y,
                   final S z,
                   final T scratch) {
        scratch.r0.set(x);
        scratch.r0.mul(y);
        scratch.r0.div(z);

        return compress(d, x, y, z, scratch.r0, scratch);
    }

    /**
     * Compress raw extended Edwards coordinates.
     *
     * @param d The Edwards curve {@code d} parameter.
     * @param x The {@code x}-coordinate.
     * @param y The {@code y}-coordinate.
     * @param z The {@code z}-coordinate.
     * @param t The {@code t}-coordinate, can be safely given in
     *          {@code scratch.r0}, but will be overwritten if this is
     *          done.
     * @param scratch The scratchpad.
     */
    public static <S extends PrimeField<S>,
                   T extends MontgomeryLadder.Scratchpad<S>>
        S compress(final int d,
                   final S x,
                   final S y,
                   final S z,
                   final S t,
                   final T scratch) {
        /* Formula from https://eprint.iacr.org/2015/673.pdf
         *
         * R = 1 / sqrt((a - d) * (Z + Y) * (Z - Y))
         * U = (a - d) * R
         * R = if (-2 * U * Z) negative then -R else R
         * S = abs(u * ((R * ((a * Z * X) - (d * Y * T))) + Y) / a)
         *
         * Set a = 1, slight rewrite to
         *
         * R = ((1 - d) * (Z + Y) * (Z - Y)).invsqrt
         * U = (1 - d) * R
         * Q = R * (-2 * U * Z).signum
         * S = abs(U * ((Q * ((Z * X) - (d * Y * T))) + Y))
         *
         * Manual common subexpression elimination produces the following:
         *
         * C = 1 - d
         * E = Z + Y
         * R = (C * E * (Z - Y)).invsqrt
         * U = C * R
         * G = -2 * U * Z
         * Q = R * G.signum
         * F = d * Y * T
         * S = abs(U * ((Q * ((Z * X) - F)) + Y))
         *
         * We will assume T requires a register assignment of its own.
         * Manual register allocation then produces the following
         * assignments:
         *
         * r0 = T
         * i0 = C
         * r1 = E
         * r2 = R
         * r1.1 = U
         * r3 = G
         * r2.1 = Q
         * r3.1 = F
         *
         * Final formula:
         *
         * i0 = 1 - d
         * r1 = Z + Y
         * r2 = (i0 * r1 * (Z - Y)).invsqrt
         * r1.1 = i0 * r2
         * r3 = -2 * r1.1 * Z
         * r2.1 = r2 * r3.signum
         * r3.1 = d * Y * T
         * r0.1 = abs(r1.1 * ((r2.1 * ((Z * X) - r3.1)) + Y))
         */

        final S r0 = scratch.r0;
        final S r1 = scratch.r1;
        final S r2 = scratch.r2;
        final S r3 = scratch.r3;

        /* i0 = 1 - d */
        final int i0 = 1 - d;


        /* r1 = Z + Y */
        r1.set(z);
        r1.add(y);

        /* r2 = (i0 * r1 * (Z - Y)).invsqrt */
        r2.set(z);
        r2.sub(y);
        r2.mul(r1);
        r2.mul(i0);
        r2.invSqrt();

        /* r1.1 = i0 * r2 */
        r1.set(r2);
        r1.mul(i0);

        /* r3 = -2 * r1.1 * Z */
        r3.set(r1);
        r3.mul(z);
        r3.mul(-2);

        /* r2.1 = r2 * r3.signum */
        r2.mul(r3.signum());

        /* r3.1 = d * Y * T */
        r3.set(t);
        r3.mul(y);
        r3.mul(d);

        /* r0.1 = abs(r1.1 * ((r2.1 * ((Z * X) - r3.1)) + Y)) */
        r0.set(z);
        r0.mul(x);
        r0.sub(r3);
        r0.mul(r2);
        r0.add(y);
        r0.mul(r1);
        r0.abs();

        /* S = r0 */
        return r0.clone();
    }

    /**
     * Decompress a point and fill in the extended Edwards
     * coordinates.
     *
     * @param d The Edwards curve {@code d} parameter.
     * @param s The compressed point.
     * @param x The scalar object to which to write the {@code
     *          x}-coordinate.
     * @param y The scalar object to which to write the {@code
     *          y}-coordinate.
     * @param z The scalar object to which to write the {@code
     *          z}-coordinate.
     * @param t The scalar object to which to write the {@code
     *          t}-coordinate, will not be written if this is null.
     * @param scratch The scratchpad object.
     * @throws IllegalArgumentException If the compressed point is
     *                                  invalid.
     */
    public static <S extends PrimeField<S>,
                   T extends MontgomeryLadder.Scratchpad<S>>
        void decompress(final int d,
                        final S s,
                        final S x,
                        final S y,
                        final S z,
                        final T scratch)
        throws IllegalArgumentException {
        decompress(d, s, x, y, z, null, scratch);
    }

    /**
     * Decompress a point and fill in the extended Edwards
     * coordinates.
     *
     * @param d The Edwards curve {@code d} parameter.
     * @param s The compressed point.
     * @param x The scalar object to which to write the {@code
     *          x}-coordinate.
     * @param y The scalar object to which to write the {@code
     *          y}-coordinate.
     * @param z The scalar object to which to write the {@code
     *          z}-coordinate.
     * @param t The scalar object to which to write the {@code
     *          t}-coordinate, will not be written if this is null.
     * @param scratch The scratchpad object.
     * @throws IllegalArgumentException If the compressed point is
     *                                  invalid.
     */
    public static <S extends PrimeField<S>,
                   T extends MontgomeryLadder.Scratchpad<S>>
        void decompress(final int d,
                        final S s,
                        final S x,
                        final S y,
                        final S z,
                        final S t,
                        final T scratch)
        throws IllegalArgumentException {
        /* Formula from https://eprint.iacr.org/2015/673.pdf
         *
         * Reject unless s.signum == 1
         *
         * X = 2 * s
         * Z = 1 + (a * s^2)
         * U = Z^2 - (4 * d * s^2)
         * V = 1 / (U * s^2).sqrt if (U * s^2).legendre == 1
         *     0 if (U * s^2).legendre == 0
         *     reject otherwise
         * V = -V if (U * V).signum == -1
         * W = V * s * (2 - Z)
         * W = W + 1 if s == 0
         * Y = W * Z
         * T = W * X
         *
         * Set a = 1 and rewritten as:
         *
         * Reject unless s.signum == 1
         *
         * X = 2 * s
         * SS = s^2
         * Z = 1 + SS
         * ZZ = Z^2
         * U = ZZ - (4 * d * SS)
         * C = U * SS
         * Reject if s.signum == -1 or C.legendre == -1
         * V = C.invsqrt * C.legendre
         * E = U * V
         * F = V * E.signum
         * H = 2 - Z
         * W = F * s * H
         * G = W + s.isZero
         * Y = G * Z
         * T = G * X
         *
         * Manual register allocation produces the following substitutions:
         *
         * r0 = SS
         * r1 = U
         * r2 = ZZ
         * r0.1 = C
         * r0.2 = V
         * r1.1 = E
         * r0.3 = F
         * r1.2 = H
         * r0.4 = W
         * r0.5 = G
         *
         * Final formula:
         *
         * X = 2 * s
         * r0 = s^2
         * Z = 1 + r0
         * r2 = Z^2
         * r1 = r2 - (4 * d * r0)
         * r0.1 = r1 * r0
         * i0 = r0.1.legendre
         * Reject if s.signum == -1 or i0 == -1
         * r0.2 = r0.1.invsqrt * i0
         * r1.1 = r1 * r0.2
         * r0.3 = r0.2 * r1.1.signum
         * r1.2 = 2 - Z
         * r0.4 = r0.3 * s * r1.2
         * r0.5 = r0.4 + s.isZero
         * Y = r0.5 * Z
         * T = r0.5 * X
         */

        final S r0 = scratch.r0;
        final S r1 = scratch.r1;
        final S r2 = scratch.r2;

        /* X = 2 * s */
        x.set(s);
        x.mul(2);

        /* r0 = s^2 */
        r0.set(s);
        r0.square();

        /* Z = 1 + r0 */
        z.set(r0);
        z.add(1);

        /* r2 = Z^2 */
        r2.set(z);
        r2.square();

        /* r1 = r2 - (4 * d * r0) */
        r1.set(r0);
        r1.mul(d * -4);
        r1.add(r2);

        /* r0.1 = r1 * r0 */
        r0.mul(r1);

        /* i0 = r0.1.legendre */
        final int i0 = r0.legendre();

        /* Reject if s.signum == -1 or i0 == -1 */
        if (s.signum() == -1 || i0 == -1) {
            throw new IllegalArgumentException("Invalid compressed point");
        }

        /* r0.2 = r0.1.invsqrt * i0 */
        r0.invSqrt();
        r0.mul(i0);

        /* r1.1 = r1 * r0.2 */
        r1.mul(r0);

        /* r0.3 = r0.2 * r1.1.signum */
        r0.mul(r1.signum());

        /* r1.2 = 2 - Z */
        r1.set(2);
        r1.sub(z);

        /* r0.4 = r0.3 * s * r1.2 */
        r0.mul(s);
        r0.mul(r1);

        /* r0.5 = r0.4 + s.isZero */
        r0.add(s.isZero());

        /* Y = r0.5 * Z */
        y.set(r0);
        y.mul(z);

        /* T = r0.5 * X */
        if (t != null) {
            t.set(r0);
            t.mul(x);
        }
    }
}
