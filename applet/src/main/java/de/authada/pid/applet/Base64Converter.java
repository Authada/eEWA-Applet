/*
 * Copyright (c) 2024 AUTHADA GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.authada.pid.applet;

import javacard.framework.JCSystem;
import javacard.security.KeyPair;

public class Base64Converter {

    // Mapping table from 6-bit nibbles to Base64 characters.
    private final byte[] map1 = {(byte) 'A', (byte) 'B', (byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F', (byte) 'G', (byte) 'H', (byte) 'I', (byte) 'J', (byte) 'K', (byte) 'L', (byte) 'M', (byte) 'N', (byte) 'O', (byte) 'P', (byte) 'Q', (byte) 'R', (byte) 'S', (byte) 'T', (byte) 'U', (byte) 'V', (byte) 'W', (byte) 'X', (byte) 'Y', (byte) 'Z', (byte) 'a', (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f', (byte) 'g', (byte) 'h', (byte) 'i', (byte) 'j', (byte) 'k', (byte) 'l', (byte) 'm', (byte) 'n', (byte) 'o', (byte) 'p', (byte) 'q', (byte) 'r', (byte) 's', (byte) 't', (byte) 'u', (byte) 'v', (byte) 'w', (byte) 'x', (byte) 'y', (byte) 'z', (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4', (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) '-', (byte) '_'};
    private byte[] out = null;

    /**
     * Encodes a byte array into Base64 format. No blanks or line breaks are
     * inserted in the output.
     *
     * @param in   An array containing the data bytes to be encoded.
     *             at <code>iOff</code>.
     * @return A byte array containing the Base64 encoded data.
     */
    public byte[] encodeToBase64UrlNoPadding(byte[] in) {
        short iLen = (short) in.length;
        short oDataLen = ((short) ((short) (iLen * (short) 4 + (short) 2) / (short) 3));       // output length without padding
        byte[] out = TransientByteArraySimplifier.one((oDataLen));
        short ip = 0;
        short iEnd = iLen;
        short op = 0;
        while (ip < iEnd) {
            short i0 = (short) (in[ip++] & 0xff);
            short i1 = (short) (ip < iEnd ? in[ip++] & 0xff : 0);
            short i2 = (short) (ip < iEnd ? in[ip++] & 0xff : 0);
            short o0 = (short) (i0 >>> 2);
            short o1 = (short) (((i0 & 3) << 4) | (i1 >>> 4));
            short o2 = (short) (((i1 & 0xf) << 2) | (i2 >>> 6));
            short o3 = (short) (i2 & 0x3F);
            out[op++] = map1[o0];
            out[op++] = map1[o1];
            if (op < oDataLen) {
                out[op] = (byte) map1[o2];
                op++;
            }
            if (op < oDataLen) {
                out[op] = (byte) map1[o3];
                op++;
            }
        }
        return out;
    }

    public void cleanUp() {
        try {
            JCSystem.beginTransaction();
            byte[] old = out;
            out = null;
            if (old != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }
    }
}
