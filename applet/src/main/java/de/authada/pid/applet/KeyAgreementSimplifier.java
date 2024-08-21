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
import javacard.security.CryptoException;
import javacard.security.KeyAgreement;
import javacard.security.PrivateKey;

public class KeyAgreementSimplifier {
    protected static short generateSecret(PrivateKey privateKey, byte[] otherPublicKeyW, byte[] sharedSecret) {
        short lengthOfSecret = 0;
        final KeyAgreement instance = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        try {
            instance.init(privateKey);
        } catch (CryptoException e) {
            switch (e.getReason()) {
                case CryptoException.NO_SUCH_ALGORITHM:
                    ISOException.throwIt(ErrorConstant.SW_NO_SUCH_ALGORITHM);
                    break;
                case CryptoException.ILLEGAL_VALUE:
                    ISOException.throwIt(ErrorConstant.SW_ILLEGAL_VALUE);
                    break;
                case CryptoException.UNINITIALIZED_KEY:
                    ISOException.throwIt(ErrorConstant.SW_UNINITIALIZED_KEY);
                    break;
                case CryptoException.INVALID_INIT:
                    ISOException.throwIt(ErrorConstant.SW_INVALID_INIT);
                    break;
                default:
                    ISOException.throwIt(ErrorConstant.SW_DEFAULT);
                    break;
            }
        } catch (Exception e) {
            ISOException.throwIt(ErrorConstant.SW_GENERAL);
        }
        try {
            lengthOfSecret = instance.generateSecret(otherPublicKeyW, (short) 0, (short) otherPublicKeyW.length, sharedSecret, (short) 0);
        } catch (
                CryptoException e) {
            switch (e.getReason()) {
                case CryptoException.NO_SUCH_ALGORITHM:
                    ISOException.throwIt(ErrorConstant.SW_NO_SUCH_ALGORITHM2);
                    break;
                case CryptoException.ILLEGAL_VALUE:
                    ISOException.throwIt(ErrorConstant.SW_ILLEGAL_VALUE2);
                    break;
                case CryptoException.UNINITIALIZED_KEY:
                    ISOException.throwIt(ErrorConstant.SW_UNINITIALIZED_KEY2);
                    break;
                case CryptoException.INVALID_INIT:
                    ISOException.throwIt(ErrorConstant.SW_INVALID_INIT2);
                    break;
                default:
                    ISOException.throwIt(ErrorConstant.SW_DEFAULT2);
                    break;
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(ErrorConstant.SW_ARRAY);
        } catch (
                Exception e) {
            ISOException.throwIt(ErrorConstant.SW_GENERAL2);
        }

        return lengthOfSecret;
    }
}
