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

/**
 * Interface for points that can be compressed according to various
 * compression types.
 *
 * @param <C> The default compression type.
 */
public interface CompressablePoint<C> {
    /**
     * Master superclass for compression kinds.
     *
     * @param <T> Type of compressed points.
     */
    public static interface Kind<T> {}

    /**
     * Compress this point using a specific compression type.
     *
     * @param <T> The compressed point type.
     * @param compressor The compressor to use.
     * @return The compressed point.
     */
    public <T> T compress(final Kind<T> compressor);

    /**
     * Compress this point using the default compression type.
     *
     * @return The compressed point.
     */
    public default C compress() {
        return compress(defaultCompressor());
    }

    /**
     * Decompress this point using a specific compression type and set
     * this point to its value.
     *
     * @param <T> The compressed point type.
     * @param compressor The compressor to use.
     * @param compressed The compressed point.
     */
    public <T> void decompress(final Kind<T> compressor,
                               final T compressed);

    /**
     * Decompress this point using the default compression type and
     * set this point to its value.
     *
     * @param compressed The compressed point.
     */
    public default void decompress(final C compressed) {
        decompress((Kind<C>) defaultCompressor(), compressed);
    }

    /**
     * Get an array of all compression kinds.
     *
     * @return All compression kinds supported by this curve.
     */
    public Kind<Object>[] compressors();

    /**
     * Get the default compression kind.
     *
     * @return Default compression kind for this curve.
     */
    public Kind<C> defaultCompressor();
}
