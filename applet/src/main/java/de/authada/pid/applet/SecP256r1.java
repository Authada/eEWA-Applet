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

import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

public class SecP256r1 {

    private final static short KEY_LENGTH_EC_FP = 256;
    private final static short INPUT_OFFSET = 0;

    private final static byte[] p = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};

    private final static byte[] a = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfc
    };

    private final static byte[] b = {(byte) 0x5a, (byte) 0xc6, (byte) 0x35, (byte) 0xd8,
            (byte) 0xaa, (byte) 0x3a, (byte) 0x93, (byte) 0xe7, (byte) 0xb3, (byte) 0xeb,
            (byte) 0xbd, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xbc,
            (byte) 0x65, (byte) 0x1d, (byte) 0x06, (byte) 0xb0, (byte) 0xcc, (byte) 0x53,
            (byte) 0xb0, (byte) 0xf6, (byte) 0x3b, (byte) 0xce, (byte) 0x3c, (byte) 0x3e,
            (byte) 0x27, (byte) 0xd2, (byte) 0x60, (byte) 0x4b};

    private final static byte[] G = {(byte) 0x04, (byte) 0x6b, (byte) 0x17, (byte) 0xd1,
            (byte) 0xf2, (byte) 0xe1, (byte) 0x2c, (byte) 0x42, (byte) 0x47, (byte) 0xf8,
            (byte) 0xbc, (byte) 0xe6, (byte) 0xe5, (byte) 0x63, (byte) 0xa4, (byte) 0x40,
            (byte) 0xf2, (byte) 0x77, (byte) 0x03, (byte) 0x7d, (byte) 0x81, (byte) 0x2d,
            (byte) 0xeb, (byte) 0x33, (byte) 0xa0, (byte) 0xf4, (byte) 0xa1, (byte) 0x39,
            (byte) 0x45, (byte) 0xd8, (byte) 0x98, (byte) 0xc2, (byte) 0x96, (byte) 0x4f,
            (byte) 0xe3, (byte) 0x42, (byte) 0xe2, (byte) 0xfe, (byte) 0x1a, (byte) 0x7f,
            (byte) 0x9b, (byte) 0x8e, (byte) 0xe7, (byte) 0xeb, (byte) 0x4a, (byte) 0x7c,
            (byte) 0x0f, (byte) 0x9e, (byte) 0x16, (byte) 0x2b, (byte) 0xce, (byte) 0x33,
            (byte) 0x57, (byte) 0x6b, (byte) 0x31, (byte) 0x5e, (byte) 0xce, (byte) 0xcb,
            (byte) 0xb6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xbf, (byte) 0x51,
            (byte) 0xf5};

    private final static byte[] r = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xbc, (byte) 0xe6, (byte) 0xfa, (byte) 0xad, (byte) 0xa7, (byte) 0x17,
            (byte) 0x9e, (byte) 0x84, (byte) 0xf3, (byte) 0xb9, (byte) 0xca, (byte) 0xc2,
            (byte) 0xfc, (byte) 0x63, (byte) 0x25, (byte) 0x51};

    private final static byte[] authPrivKeyS = {(byte) 0x87, (byte) 0x7b, (byte) 0x75, (byte) 0xb3,
            (byte) 0x62, (byte) 0xc9, (byte) 0x04, (byte) 0x86, (byte) 0xd2, (byte) 0xf2,
            (byte) 0x35, (byte) 0x80, (byte) 0x00, (byte) 0x24, (byte) 0x84, (byte) 0xcf,
            (byte) 0x9c, (byte) 0xa1, (byte) 0xca, (byte) 0xa0, (byte) 0x14, (byte) 0x71,
            (byte) 0x90, (byte) 0x1a, (byte) 0xdd, (byte) 0xd2, (byte) 0xbf, (byte) 0xe6,
            (byte) 0x11, (byte) 0xdd, (byte) 0x8b, (byte) 0xd6};

    private final static byte[] authPubKeyW = {(byte) 0x04, (byte) 0x4b, (byte) 0xfc, (byte) 0x78,
            (byte) 0x55, (byte) 0x2c, (byte) 0x62, (byte) 0x55, (byte) 0x27, (byte) 0xf8,
            (byte) 0x70, (byte) 0x38, (byte) 0xa7, (byte) 0x75, (byte) 0x49, (byte) 0xee,
            (byte) 0xdf, (byte) 0xfa, (byte) 0x0f, (byte) 0x5d, (byte) 0x1b, (byte) 0xb4,
            (byte) 0xe4, (byte) 0x8b, (byte) 0x51, (byte) 0x91, (byte) 0x26, (byte) 0xbd,
            (byte) 0x01, (byte) 0x0f, (byte) 0x62, (byte) 0x7f, (byte) 0x22, (byte) 0x28,
            (byte) 0x39, (byte) 0x5e, (byte) 0x0f, (byte) 0x9c, (byte) 0x5c, (byte) 0x47,
            (byte) 0x74, (byte) 0x00, (byte) 0x29, (byte) 0x41, (byte) 0x71, (byte) 0x43,
            (byte) 0x61, (byte) 0x65, (byte) 0xb8, (byte) 0x26, (byte) 0xcd, (byte) 0x0d,
            (byte) 0x8e, (byte) 0x90, (byte) 0x7b, (byte) 0x7c, (byte) 0x6f, (byte) 0xf9,
            (byte) 0x93, (byte) 0x96, (byte) 0x1a, (byte) 0x28, (byte) 0xc0, (byte) 0x0f,
            (byte) 0x3e};

    static public KeyPair newKeyPair(boolean fixed) {
        KeyPair key = new KeyPair(KeyPair.ALG_EC_FP, KEY_LENGTH_EC_FP);

        ECPrivateKey privKey = (ECPrivateKey) key.getPrivate();
        ECPublicKey pubKey = (ECPublicKey) key.getPublic();

        privKey.setFieldFP(p, INPUT_OFFSET, (short) p.length);
        privKey.setA(a, INPUT_OFFSET, (short) a.length);
        privKey.setB(b, INPUT_OFFSET, (short) b.length);
        privKey.setG(G, INPUT_OFFSET, (short) G.length);
        privKey.setR(r, INPUT_OFFSET, (short) r.length);

        pubKey.setFieldFP(p, INPUT_OFFSET, (short) p.length);
        pubKey.setA(a, INPUT_OFFSET, (short) a.length);
        pubKey.setB(b, INPUT_OFFSET, (short) b.length);
        pubKey.setG(G, INPUT_OFFSET, (short) G.length);
        pubKey.setR(r, INPUT_OFFSET, (short) r.length);

        if (fixed) {
            privKey.setS(authPrivKeyS, INPUT_OFFSET, (short) authPrivKeyS.length);
            pubKey.setW(authPubKeyW, INPUT_OFFSET, (short) authPubKeyW.length);
        } else {
            key.genKeyPair();
        }

        return key;
    }
}
