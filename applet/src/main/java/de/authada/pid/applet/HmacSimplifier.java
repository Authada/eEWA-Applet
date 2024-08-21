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

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

public class HmacSimplifier {


    private static Signature createSignature(byte[] sharedSecret, byte mode) {
        HMACKey keyType = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, (short) 256, false);
        try {
            keyType.setKey(sharedSecret, (short) 0, (short) sharedSecret.length);
        } catch (CryptoException e) {
            if (e.getReason() == CryptoException.ILLEGAL_VALUE) {
                ISOException.throwIt(ErrorConstant.SW_ILLEGAL_VALUE4);
            }
        }

        Signature hMacSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
        try {
            hMacSignature.init(keyType, mode);
        } catch (CryptoException e) {
            if (e.getReason() == CryptoException.ILLEGAL_VALUE) {
                ISOException.throwIt(ErrorConstant.SW_ILLEGAL_VALUE5);
            }
        }

        return hMacSignature;
    }

    protected static boolean createSharedSecretAndVerify(ECPrivateKey privateKey, byte[] foreignPublicKey, byte[] inputData, byte[] inputDataHmac) {
        byte[] sharedSecretTemp = TransientByteArraySimplifier.one((short) 65);
        short offset = KeyAgreementSimplifier.generateSecret(privateKey, foreignPublicKey, sharedSecretTemp);
        byte[] sharedSecret = TransientByteArraySimplifier.one(offset);
        ArraySimplifier.three(sharedSecretTemp, (short) 0, sharedSecret, (short) 0, offset);

        byte[] hmac = TransientByteArraySimplifier.one((short) 32);

        short signedDataOffset = sign(sharedSecret, inputData, hmac);

        return (Util.arrayCompare(inputDataHmac, (short) 0, hmac, (short) 0, (short) hmac.length) == 0);
    }

    public static short sign(byte[] sharedSecret, byte[] inputData, byte[] outputData) {
        short signatureLength = 0;
        Signature hMacSignature = null;
        hMacSignature = createSignature(sharedSecret, Signature.MODE_SIGN);
        try {
            signatureLength = hMacSignature.sign(inputData, (short) 0, (short) inputData.length, outputData, (short) 0);
        } catch (CryptoException e) {
            switch (e.getReason()) {
                case CryptoException.NO_SUCH_ALGORITHM:
                    ISOException.throwIt(ErrorConstant.SW_NO_SUCH_ALGORITHM3);
                    break;
                case CryptoException.ILLEGAL_VALUE:
                    ISOException.throwIt(ErrorConstant.SW_ILLEGAL_VALUE3);
                    break;
                case CryptoException.UNINITIALIZED_KEY:
                    ISOException.throwIt(ErrorConstant.SW_UNINITIALIZED_KEY3);
                    break;
                case CryptoException.INVALID_INIT:
                    ISOException.throwIt(ErrorConstant.SW_INVALID_INIT3);
                    break;
                case CryptoException.ILLEGAL_USE:
                    ISOException.throwIt(ErrorConstant.SW_ILLEGAL_USE);
                    break;
                default:
                    ISOException.throwIt(ErrorConstant.SW_DEFAULT);
                    break;
            }
        }

        return signatureLength;
    }
}
