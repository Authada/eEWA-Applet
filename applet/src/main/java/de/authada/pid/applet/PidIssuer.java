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

import javacard.framework.*;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

import static de.authada.pid.applet.Util.lengthCreator;


public class PidIssuer {

    private CSP csp;

    public PidIssuer(CSP csp) {
        this.csp = csp;
    }

    protected byte[] createDeviceKeysAndProcessNonce(byte[] nonce, KeyPair deviceKeys, KeyPair authenticationKeys) {

        byte[] proofOfPossession = csp.signEcdsaSha256(nonce, deviceKeys.getPrivate());
        byte[] transientECPublicKey = TransientByteArraySimplifier.one((short) 70);

        short lengthOfECPublicKeyW = PublicKeySimplifier.one((ECPublicKey) deviceKeys.getPublic(), transientECPublicKey, (short) 0);

        byte[] transientECPublicKeyFixedLength = TransientByteArraySimplifier.one(lengthOfECPublicKeyW);

        ArraySimplifier.three(transientECPublicKey, (short) 0, transientECPublicKeyFixedLength, (short) 0, lengthOfECPublicKeyW);

        byte[] deviceKeyAttestation = csp.signEcdsaSha256(transientECPublicKeyFixedLength, authenticationKeys.getPrivate());

        short lengthOfProofOfPossession = (short) proofOfPossession.length;
        short lengthOfDeviceKeyAttestation = (short) deviceKeyAttestation.length;

        byte[] response = TransientByteArraySimplifier.one(((short) (lengthOfProofOfPossession + lengthOfDeviceKeyAttestation + 4)));

        response[0] = (byte) (lengthOfProofOfPossession >> 8);
        response[1] = (byte) (lengthOfProofOfPossession & 0xFF);
        short offset = 2;
        offset = ArraySimplifier.two(proofOfPossession, (short) 0, response, offset, (short) proofOfPossession.length);

        response[offset] = (byte) (deviceKeyAttestation.length >> 8);
        offset++;
        response[offset] = (byte) (deviceKeyAttestation.length & 0xFF);
        offset++;

        ArraySimplifier.four(deviceKeyAttestation, (short) 0, response, offset, (short) deviceKeyAttestation.length);
        return response;
    }

    protected PersonalDataHolder verifyAuthenticatedChannelAndCreatePersonalData(ECPrivateKey privateKey, byte[] sendData) {
        short personalDataOffset = 0;
        byte[] hmac = null;
        byte[] pubKey = null;

        if (ArraySimplifier.tagCompareOne(sendData, personalDataOffset, PidIssuerConstants.hmac)) {
            personalDataOffset = Util.next(personalDataOffset);
            short lengthOfHmac = lengthCreator(sendData, personalDataOffset);
            personalDataOffset = Util.next(personalDataOffset);
            hmac = TransientByteArraySimplifier.one(lengthOfHmac);
            personalDataOffset += ArraySimplifier.one(sendData, personalDataOffset, hmac, (short) 0, lengthOfHmac);
        }
        short hMacDataOffset = personalDataOffset;

        if (ArraySimplifier.tagCompareOne(sendData, personalDataOffset, PidIssuerConstants.pubKey)) {
            personalDataOffset = Util.next(personalDataOffset);
            short lengthOfPubKey = lengthCreator(sendData, personalDataOffset);
            personalDataOffset = Util.next(personalDataOffset);
            pubKey = TransientByteArraySimplifier.one(lengthOfPubKey);
            personalDataOffset += ArraySimplifier.one(sendData, personalDataOffset, pubKey, (short) 0, lengthOfPubKey);
        }

        if (hmac == null) {
            ISOException.throwIt(ErrorConstant.SW_HMAC_MISSING);
        }
        if (pubKey == null) {
            ISOException.throwIt(ErrorConstant.SW_FOREIGN_PUB_KEY_MISSING);
        }

        short lengthOfSignedData = (short) (sendData.length - hMacDataOffset);
        byte[] signedData = TransientByteArraySimplifier.one(lengthOfSignedData);

        ArraySimplifier.two(sendData, hMacDataOffset, signedData, (short) 0, lengthOfSignedData);

        if (csp.verifyWithHmacSha256(privateKey, pubKey, signedData, hmac)) {
            return PersonalDataCreator.byteArrayToPersonalData(sendData, personalDataOffset);
        } else {
            ISOException.throwIt(ErrorConstant.SW_CHANNEL_NOT_AUTHENTICATED);
        }
        return null;
    }

}
