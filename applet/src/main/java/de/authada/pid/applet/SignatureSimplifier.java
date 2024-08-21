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
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.PrivateKey;
import javacard.security.Signature;

public class SignatureSimplifier {

    public static Signature ecSignatureInstance = null;

    public static void createAndInitSignatureInstance(PrivateKey privateKey) {
        if (ecSignatureInstance == null) {
            ecSignatureInstance = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

            try {
                ecSignatureInstance.init(privateKey, Signature.MODE_SIGN);
            } catch (CryptoException e) {
                switch(e.getReason()) {
                    case CryptoException.ILLEGAL_VALUE:
                        ISOException.throwIt(ErrorConstant.SW_ILLEGAL_VALUE2);
                        break;
                    case CryptoException.UNINITIALIZED_KEY:
                        ISOException.throwIt(ErrorConstant.SW_UNINITIALIZED_KEY2);

                }
            }
        }
    }

    public static void oneUpdateSignature(byte[] data) {
        if (ecSignatureInstance == null) {
            ISOException.throwIt(ErrorConstant.SW_NULL);
        }

        ecSignatureInstance.update(data, (short)0, ((short) data.length));
    }

    public static byte[] oneComputeSignature(byte[] data) {
        if (ecSignatureInstance == null) {
            ISOException.throwIt(ErrorConstant.SW_NULL);
        }

        byte[] signatureTemp = TransientByteArraySimplifier.one((short) 128);
        short signLength = 0;
        try {
            signLength = ecSignatureInstance.sign(data, (short) 0,
                    (short) data.length, signatureTemp, (short) 0);

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

        byte[] signature = TransientByteArraySimplifier.one(signLength);
        ArraySimplifier.one(signatureTemp, (short) 0, signature, (short) 0, signLength);

        cleanUpSignatureInstance();

        return signature;
    }

    public static byte[] one(byte[] data, PrivateKey privateKey) {
        createAndInitSignatureInstance(privateKey);

        return oneComputeSignature(data);
    }

    public static void cleanUpSignatureInstance() {
        try {
            JCSystem.beginTransaction();
            Signature old = ecSignatureInstance;
            ecSignatureInstance = null;
            if (old != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }
    }
}
