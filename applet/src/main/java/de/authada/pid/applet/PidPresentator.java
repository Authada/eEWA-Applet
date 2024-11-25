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

import static de.authada.pid.applet.Util.lengthCreator;
import static de.authada.pid.applet.Util.next;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

public class PidPresentator {
    private static final byte separator = '.';
    private static final byte concatinator = '~';
    private static final short SIGNATURE_LEN_ES256 = 64;

    public static byte[] create(byte[] buffer, PersonalDataHolder personalDataHolder, KeyPair keyPair) {
        short offset = 0;

        short lengthOfPublicKeyW = lengthCreator(buffer, offset);
        offset = next(offset);

        byte[] foreignPublicKey = TransientByteArraySimplifier.one(lengthOfPublicKeyW);
        offset += ArraySimplifier.one(buffer, offset, foreignPublicKey, (short) 0, lengthOfPublicKeyW);

        short lengthOfCredentialHandle = lengthCreator(buffer, offset);
        offset = next(offset);

        byte[] credentialHandleCandidate = TransientByteArraySimplifier.one((CredentialHandle.CREDENTIAL_HANDLE_LENGTH));
        offset += ArraySimplifier.two(buffer, offset, credentialHandleCandidate, (short) 0, lengthOfCredentialHandle);

        short lengthOfIat = lengthCreator(buffer, offset);
        offset = next(offset);

        byte[] iat = TransientByteArraySimplifier.one(lengthOfIat);
        offset += ArraySimplifier.three(buffer, offset, iat, (short) 0, lengthOfIat);

        short lengthOfAut = lengthCreator(buffer, offset);
        offset = next(offset);

        byte[] aud = TransientByteArraySimplifier.one(lengthOfAut);
        offset += ArraySimplifier.four(buffer, offset, aud, (short) 0, lengthOfAut);

        short lengthOfNonce = lengthCreator(buffer, offset);
        offset = next(offset);

        byte[] nonce = TransientByteArraySimplifier.one(lengthOfNonce);
        offset += ArraySimplifier.one(buffer, offset, nonce, (short) 0, lengthOfNonce);

        short lengthOfSelector = lengthCreator(buffer, offset);
        offset = next(offset);


        byte[] selector = TransientByteArraySimplifier.one(lengthOfSelector);
        offset += ArraySimplifier.two(buffer, offset, selector, (short) 0, lengthOfSelector);

        if (personalDataHolder.verifyCredentialHandle(credentialHandleCandidate)) {
            byte[] sharedSecret = TransientByteArraySimplifier.one((short) 32);
            KeyAgreementSimplifier.generateSecret(keyPair.getPrivate(), foreignPublicKey, sharedSecret);

            KeyPair ephemeralKeyPair = SecP256r1.newKeyPair(false);

            Base64Converter base64Converter = new Base64Converter();

            byte[] header = SdJwtVcCreator.createHeader(keyPair.getPublic(), foreignPublicKey, personalDataHolder.x5cCertificates, base64Converter);
            byte[] body = SdJwtVcCreator.fromPersonalData(personalDataHolder, (ECPublicKey) ephemeralKeyPair.getPublic(), selector, iat);

            byte[] base64Header = base64Converter.encodeToBase64UrlNoPadding(header);
            byte[] base64Body = base64Converter.encodeToBase64UrlNoPadding(body);

            short subjectLength = (short) (base64Header.length + 1 + base64Body.length);
            byte[] subject = TransientByteArraySimplifier.one(subjectLength);

            short subjectOffset = 0;
            subjectOffset = ArraySimplifier.one(base64Header, (short) 0, subject, subjectOffset, (short) base64Header.length);

            subject[subjectOffset] = separator;
            subjectOffset++;

            subjectOffset = ArraySimplifier.two(base64Body, (short) 0, subject, subjectOffset, (short) base64Body.length);

            byte[] signature = TransientByteArraySimplifier.one((short) 32);

            HmacSimplifier.sign(sharedSecret, subject, signature);

            byte[] base64Signature = base64Converter.encodeToBase64UrlNoPadding(signature);

            short jwtLength = (short) (subjectLength + 2 + base64Signature.length);
            byte[] jwt = TransientByteArraySimplifier.one(jwtLength);

            short jwtOffset = 0;

            jwtOffset = ArraySimplifier.three(subject, (short) 0, jwt, jwtOffset, subjectLength);

            jwt[jwtOffset] = separator;
            jwtOffset++;

            jwtOffset = ArraySimplifier.four(base64Signature, (short) 0, jwt, jwtOffset, (short) base64Signature.length);

            jwt[jwtOffset] = concatinator;

            //creates a KB-JWT payload containing the nonce, audience, and a hash of the SD-JWT and the selected disclosures and signs it using kb_eph_priv.

            byte[] kbJwtHeader = KbJWTCreator.createHeader();
            byte[] base64UrlEncodedKbJwtHeader = base64Converter.encodeToBase64UrlNoPadding(kbJwtHeader);


            byte[] sdHash = HashSimplifier.create(jwt, (short) 0, jwtLength);

            byte[] base64UrlSdHash = base64Converter.encodeToBase64UrlNoPadding(sdHash);

            byte[] kbJwtBody = KbJWTCreator.createBody(iat, aud, nonce, base64UrlSdHash);

            byte[] base64UrlEncodedKbJwtBody = base64Converter.encodeToBase64UrlNoPadding(kbJwtBody);

            short lengthOfkbSubject = (short) (base64UrlEncodedKbJwtHeader.length + 1 + base64UrlEncodedKbJwtBody.length);
            byte[] kbJwtSubject = TransientByteArraySimplifier.one(lengthOfkbSubject);
            short kbJwtSubjectOffset = 0;


            kbJwtSubjectOffset = ArraySimplifier.three(base64UrlEncodedKbJwtHeader, (short) 0, kbJwtSubject, kbJwtSubjectOffset, (short) base64UrlEncodedKbJwtHeader.length);

            kbJwtSubject[kbJwtSubjectOffset] = separator;
            kbJwtSubjectOffset++;

            kbJwtSubjectOffset = ArraySimplifier.four(base64UrlEncodedKbJwtBody, (short) 0, kbJwtSubject, kbJwtSubjectOffset, (short) base64UrlEncodedKbJwtBody.length);

            byte[] kbJwtSignature = SignatureSimplifier.one(kbJwtSubject, ephemeralKeyPair.getPrivate());

            byte[] base64KbJwtSignature = base64Converter.encodeToBase64UrlNoPadding(transcodeSignatureToConcat(kbJwtSignature, SIGNATURE_LEN_ES256));
            cleanUp(ephemeralKeyPair);

            short kbJwtLength = (short) (base64KbJwtSignature.length + 1 + kbJwtSubject.length);
            byte[] kbJwt = TransientByteArraySimplifier.one(kbJwtLength);

            short kbJwtOffset = 0;

            kbJwtOffset = ArraySimplifier.one(kbJwtSubject, (short) 0, kbJwt, kbJwtOffset, (short) kbJwtSubject.length);

            kbJwt[kbJwtOffset] = separator;
            kbJwtOffset++;

            kbJwtOffset = ArraySimplifier.two(base64KbJwtSignature, (short) 0, kbJwt, kbJwtOffset, (short) base64KbJwtSignature.length);

            //----------pid---------------

            short pidLength = (short) (kbJwt.length + jwt.length);
            byte[] pid = TransientByteArraySimplifier.one(pidLength);

            short pidOffset = 0;

            pidOffset = ArraySimplifier.three(jwt, (short) 0, pid, pidOffset, (short) jwt.length);

            pidOffset = ArraySimplifier.four(kbJwt, (short) 0, pid, pidOffset, (short) kbJwt.length);

            return pid;
        } else {
            ISOException.throwIt(ErrorConstant.SW_CREDENTIAL_HANDLE_NOT_FOUND);
        }
        return null;
    }

    private static void cleanUp(KeyPair ephemeralKeyPair) {
        try {
            JCSystem.beginTransaction();
            KeyPair oldData = ephemeralKeyPair;
            ephemeralKeyPair = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }
    }

    private static byte[] transcodeSignatureToConcat(final byte[] derSignature, final short outputLength) {
        short offset = Short.MIN_VALUE;
        if (derSignature[1] > 0) {
            offset = 2;
        } else if (derSignature[1] == (byte) 0x81) {
            offset = 3;
        } else {
            ISOException.throwIt(ErrorConstant.SW_ILLEGAL_VALUE);
        }

        byte rLength = derSignature[((short) (offset + 1))];

        short i;
        for (i = rLength; (i > 0) && (derSignature[((short) ((offset + 2 + rLength) - i))] == 0); i--) {
            // do nothing
        }

        byte sLength = derSignature[((short) (offset + 2 + rLength + 1))];

        short j;
        for (j = sLength; (j > 0) && (derSignature[((short) ((offset + 2 + rLength + 2 + sLength) - j))] == 0); j--) {
            // do nothing
        }

        short rawLen = i < j ? j : i;
        short halvedOutputLen = ((short) (outputLength / 2));
        rawLen = rawLen < halvedOutputLen ? halvedOutputLen : rawLen;

        if ((derSignature[((short) (offset - 1))] & 0xff) != ((short) (derSignature.length - offset))
                || (derSignature[((short) (offset - 1))] & 0xff) != ((short) (2 + rLength + 2 + sLength))
                || derSignature[offset] != 2
                || derSignature[((short) (offset + 2 + rLength))] != 2) {
            ISOException.throwIt(ErrorConstant.SW_ILLEGAL_VALUE2);
        }

        final byte[] concatSignature = TransientByteArraySimplifier.one(((short) (2 * rawLen)));

        ArraySimplifier.one(derSignature, ((short) ((offset + 2 + rLength) - i)), concatSignature, ((short) (rawLen - i)), i);
        ArraySimplifier.two(derSignature, ((short) ((offset + 2 + rLength + 2 + sLength) - j)), concatSignature, ((short) (2 * rawLen - j)), j);

        return concatSignature;
    }

}
