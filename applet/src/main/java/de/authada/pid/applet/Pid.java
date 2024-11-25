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

import javacard.framework.*;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacardx.apdu.ExtendedLength;
import org.globalplatform.GPSystem;
import org.globalplatform.Personalization;
import org.globalplatform.SecureChannel;

public class Pid extends Applet implements Personalization, ExtendedLength {

    // instruction bytes
    final static byte VERIFY = (byte) 0x20;
    final static byte CLEAN_TRANSIENT = (byte) 0x35;
    final static byte CREATE_KEY_PAIR = (byte) 0x36;
    final static byte WALLET_ATTESTATION = (byte) 0x39;
    final static byte STORE_PERSONAL_DATA = (byte) 0x42;
    final static byte CREATE_PID = (byte) 0x43;
    final static byte GET_PERSONAL_DATA = (byte) 0x44;
    final static byte GET_AUTHENTICATION_PUBLIC_KEY = (byte) 0x45;
    final static byte INIT_UPDATE = (byte) 0x50;
    final static byte SET_PIN = (byte) 0x51;
    final static byte GET_PUBLIC_KEY = (byte) 0x52;
    final static byte DELETE_KEY_ID = (byte) 0x53;
    final static byte CLEAN_UP = (byte) 0x71;
    static final byte HAS_PIN = 0x73;
    static final byte CREATE_SIGNATURE_WITH_KEY = 0x74;
    static final byte CREATE_SIGNATURE_WITH_KEY_SINGLE = 0x75;
    final static byte EXT_AUTHENTICATE = (byte) 0x82;
    // maximum number of incorrect tries before the
    // PIN is blocked
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x06;

    public static byte[] keyIdTag = {(byte) 0xD0, (byte) 0x01};
    public static byte[] signatureDataTag = {(byte) 0xD0, (byte) 0x02};
    public static byte[] nonceTag = {(byte) 0xD0, (byte) 0x03};

    final static short MAX_NON_EL_DATA_SIZE = 256;

    private final KeyPair authenticationKeys;

    private OwnerPIN pin = null;
    private final CSP csp;

    private final PidIssuer pidIssuer;

    private final Object[] keyIdKeyPairArray;

    private SecureChannel secCh = null;

    private PersonalDataHolder personalDataHolder;

    private Pid(byte[] bArray, short bOffset, byte bLength) {
        csp = new CSP();
        authenticationKeys = SecP256r1.newKeyPair(true);
        pidIssuer = new PidIssuer(csp);
        keyIdKeyPairArray = new Object[100];
        register();
    }

    @Override
    public boolean select() {
        // The applet declines to be selected if the pin is blocked.
        if (pin != null && pin.getTriesRemaining() == 0) {
            return false;
        }
        secCh = GPSystem.getSecureChannel();
        return true;
    }

    @Override
    public void deselect() {
        // reset the pin value
        if (pin != null) {
            pin.reset();
        }

        SignatureSimplifier.cleanUpSignatureInstance();
        secCh.resetSecurity();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Pid(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buf = apdu.getBuffer();
        switch (buf[ISO7816.OFFSET_INS]) {
            case VERIFY:
                verify(apdu);
                return;
            case CREATE_KEY_PAIR:
                createKeyPair(apdu);
                return;
            case WALLET_ATTESTATION:
                walletAttestation(apdu);
                return;
            case CREATE_SIGNATURE_WITH_KEY:
                createSignatureWithKey(apdu);
                return;
            case CREATE_SIGNATURE_WITH_KEY_SINGLE:
                createSignatureWithKeySingle(apdu);
                return;
            case CLEAN_TRANSIENT:
                requestObjectDeletion();
                return;
            case GET_AUTHENTICATION_PUBLIC_KEY:
                getAuthenticationPublicKey(apdu);
                return;
            case GET_PUBLIC_KEY:
                getPublicKey(apdu);
                return;
            case DELETE_KEY_ID:
                deleteKeyId(apdu);
                return;
            case SET_PIN:
                setPin(apdu);
                return;
            case STORE_PERSONAL_DATA:
                storePersonalData(apdu);
                return;
            case CREATE_PID:
                createPid(apdu);
                return;
            case GET_PERSONAL_DATA:
                getPersonalData(apdu);
                return;
            case CLEAN_UP:
                cleanUp(apdu);
                return;
            case EXT_AUTHENTICATE:
            case INIT_UPDATE:
                short len = secCh.processSecurity(apdu);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
                return;
            case HAS_PIN:
                hasPin(apdu);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void hasPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        if (pin == null) {
            ISOException.throwIt(ErrorConstant.SW_PIN_NOT_SET);
        }
    }


    private void cleanUp(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short recv = apdu.setIncomingAndReceive();
        cleanUpPersonalDataHolder();
    }


    private void createPid(APDU apdu) {
        checkForPersonalData();
        if (personalDataHolder.keyId == null) {
            ISOException.throwIt(ErrorConstant.SW_NO_KEY_ID);
        }

        byte[] body = receiveData(apdu);

        KeyIdKeyPair keyIdKeyPair = getKeyIdKeyPair(personalDataHolder.keyId);
        byte[] pid = PidPresentator.create(body, personalDataHolder, keyIdKeyPair.keyPair);

        short le = apdu.setOutgoing();
        apdu.setOutgoingLength((short) pid.length);
        apdu.sendBytesLong(pid, (short) 0, (short) pid.length);
    }

    private short getIndexOfKeyIdKeyPair(byte[] keyId) {
        short index = -1;
        for (short i = 0; i < keyIdKeyPairArray.length; i++) {
            if (keyIdKeyPairArray[i] != null && ArraySimplifier.compareOne(((KeyIdKeyPair) keyIdKeyPairArray[i]).keyId, keyId)) {
                index = i;
                break;
            }
        }

        if (index == -1) {
            ISOException.throwIt(ErrorConstant.SW_NO_KEY_ID_FOUND);
        }

        return index;
    }

    private KeyIdKeyPair getKeyIdKeyPair(byte[] keyId) {
        short index = getIndexOfKeyIdKeyPair(keyId);
        return ((KeyIdKeyPair) keyIdKeyPairArray[index]);
    }

    private void storePersonalData(APDU apdu) {
        byte[] body = receiveData(apdu);

        short offset = 0;
        if (ArraySimplifier.tagCompareOne(body, offset, keyIdTag)) {
            offset = Util.next(offset);
            short lengthOfKeyId = lengthCreator(body, offset);
            offset = Util.next(offset);
            byte[] keyId = TransientByteArraySimplifier.one(lengthOfKeyId);
            offset += ArraySimplifier.one(body, offset, keyId, (short) 0, lengthOfKeyId);

            KeyIdKeyPair keyIdKeyPair = getKeyIdKeyPair(keyId);

            //there can only be one set of PID data, so cleanup to prevent having data leftovers
            cleanUpPersonalDataHolder();
            personalDataHolder = pidIssuer.verifyAuthenticatedChannelAndCreatePersonalData(
                    (ECPrivateKey) keyIdKeyPair.keyPair.getPrivate(),
                    body,
                    offset
            );

            byte[] credentialHandle = personalDataHolder.createCredentialHandle();
            personalDataHolder.keyId = keyIdKeyPair.keyId;

            short le = apdu.setOutgoing();
            apdu.setOutgoingLength((short) credentialHandle.length);
            apdu.sendBytesLong(credentialHandle, (short) 0, (short) credentialHandle.length);
        } else {
            ISOException.throwIt(ErrorConstant.SW_NO_KEY_ID);
        }
    }

    private void getPersonalData(APDU apdu) {
        checkForPersonalData();

        byte[] credentialHandleCandidate = receiveData(apdu);
        byte[] personalData = personalDataHolder.getPersonalData(credentialHandleCandidate);

        short le = apdu.setOutgoing();
        apdu.setOutgoingLength((short) personalData.length);
        apdu.sendBytesLong(personalData, (short) 0, (short) personalData.length);
    }


    private void createKeyPair(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        KeyIdKeyPair item = new KeyIdKeyPair();
        item.keyPair = SecP256r1.newKeyPair(false);

        item.keyId = new byte[48];
        Util.generateRandomId(item.keyId);

        for (short i = 0; i < keyIdKeyPairArray.length; i++) {
            if (keyIdKeyPairArray[i] == null) {
                keyIdKeyPairArray[i] = item;
                break;
            }
        }

        short le = apdu.setOutgoing();
        apdu.setOutgoingLength((short) item.keyId.length);
        apdu.sendBytesLong(item.keyId, (short) 0, (short) item.keyId.length);
    }


    private void walletAttestation(APDU apdu) {
        byte[] buffer = receiveData(apdu);

        short offset = 0;
        if (ArraySimplifier.tagCompareOne(buffer, offset, keyIdTag)) {
            offset = Util.next(offset);
            short lengthOfKeyId = lengthCreator(buffer, offset);
            offset = Util.next(offset);
            byte[] keyId = TransientByteArraySimplifier.one(lengthOfKeyId);
            offset += ArraySimplifier.one(buffer, offset, keyId, (short) 0, lengthOfKeyId);

            KeyIdKeyPair keyIdKeyPair = getKeyIdKeyPair(keyId);

            if (ArraySimplifier.tagCompareOne(buffer, offset, nonceTag)) {
                offset = Util.next(offset);
                short lengthOfNonce = lengthCreator(buffer, offset);
                offset = Util.next(offset);
                byte[] nonce = TransientByteArraySimplifier.one(lengthOfNonce);
                offset += ArraySimplifier.one(buffer, offset, nonce, (short)0, lengthOfNonce);

                byte[] response = pidIssuer.createDeviceKeysAndProcessNonce(nonce, keyIdKeyPair.keyPair, authenticationKeys);

                apdu.setOutgoing();
                apdu.setOutgoingLength(((short) response.length));
                apdu.sendBytesLong(response, (short) 0, ((short) response.length));
            } else {
                ISOException.throwIt(ErrorConstant.SW_ARRAY4);
            }
        } else {
            ISOException.throwIt(ErrorConstant.SW_NO_KEY_ID);
        }
    }


    private byte[] getDataToSignFromInputWithTags(byte[] input) {
        short offset = Util.next((short)0);
        short lengthOfKeyId = lengthCreator(input, offset);
        offset = Util.next(offset);
        byte[] keyId = TransientByteArraySimplifier.one(lengthOfKeyId);
        offset += ArraySimplifier.one(input, offset, keyId, (short) 0, lengthOfKeyId);

        KeyIdKeyPair keyIdKeyPair = getKeyIdKeyPair(keyId);
        initSignatureInstance(keyIdKeyPair.keyPair);

        if (ArraySimplifier.tagCompareOne(input, offset, signatureDataTag)) {
            offset = Util.next(offset);
            short lengthOfDataToSign = lengthCreator(input, offset);
            offset = Util.next(offset);
            byte[] dataToSign = TransientByteArraySimplifier.one(lengthOfDataToSign);
            ArraySimplifier.one(input, offset, dataToSign, (short)0, lengthOfDataToSign);

            return dataToSign;
        } else {
            ISOException.throwIt(ErrorConstant.SW_ARRAY4);
        }

        return null;
    }

    private void createSignatureWithKeySingle(APDU apdu) {
        byte[] body = receiveData(apdu);

        if (ArraySimplifier.tagCompareOne(body, (short)0, keyIdTag)) {
            byte[] signature = SignatureSimplifier.oneComputeSignature(getDataToSignFromInputWithTags(body));

            apdu.setOutgoing();
            apdu.setOutgoingLength((short) signature.length);
            apdu.sendBytesLong(signature, (short) 0, (short) signature.length);
        } else {
            ISOException.throwIt(ErrorConstant.SW_NO_KEY_ID);
        }
    }

    private void createSignatureWithKey(APDU apdu) {
        byte[] body = receiveData(apdu);

        //Special handling for older Secure Elements and eSIM: Input data size from EL APDUs is
        //seemingly limited to something around 4000 Bytes, so chaining got implemented. Currently,
        //only this function to create a signature with the device private key gets special command
        //chaining treatment as other functions did not show the need to do so.

        if (apdu.isCommandChainingCLA()) {
            if (ArraySimplifier.tagCompareOne(body, (short)0, keyIdTag)) {
                SignatureSimplifier.oneUpdateSignature(getDataToSignFromInputWithTags(body));
            } else {
                SignatureSimplifier.oneUpdateSignature(body);
            }
        } else {
            byte[] signature = SignatureSimplifier.oneComputeSignature(body);

            apdu.setOutgoing();
            apdu.setOutgoingLength((short) signature.length);
            apdu.sendBytesLong(signature, (short) 0, (short) signature.length);
        }
    }

    private void setPin(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] buffer = apdu.getBuffer();

        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

        pin.update(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC]);

        cleanUpPersonalDataHolder();
    }

    private void requestObjectDeletion() {
        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        } else {
            ISOException.throwIt(ErrorConstant.SW_DELETE_NOT_SUPPORTED);
        }
    }

    private void verify(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            switch (pin.getTriesRemaining()) {
                case 2:
                    ISOException.throwIt(ErrorConstant.SW_PIN_WRONG_TWO_TRIES_LEFT);
                    return;
                case 1:
                    ISOException.throwIt(ErrorConstant.SW_PIN_WRONG_ONE_TRY_LEFT);
                    return;
                case 0:
                    ISOException.throwIt(ErrorConstant.SW_WALLET_BLOCKED);
                    return;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
    }

    private void getAuthenticationPublicKey(APDU apdu) {
        checkForPinSetAndValidated();

        byte[] buffer = apdu.getBuffer();
        short lengthOfW = PublicKeySimplifier.one((ECPublicKey) authenticationKeys.getPublic(), buffer, ISO7816.OFFSET_CDATA);

        apdu.setOutgoing();
        apdu.setOutgoingLength(lengthOfW);
        apdu.sendBytesLong(buffer, ISO7816.OFFSET_CDATA, lengthOfW);
    }

    private void getPublicKey(APDU apdu) {
        checkForPinSetAndValidated();

        byte[] keyId = getKeyIdFromApdu(apdu);
        KeyIdKeyPair keyIdKeyPair = getKeyIdKeyPair(keyId);

        byte[] buffer = apdu.getBuffer();
        short lengthOfW = PublicKeySimplifier.one((ECPublicKey) keyIdKeyPair.keyPair.getPublic(), buffer, ISO7816.OFFSET_CDATA);

        apdu.setOutgoing();
        apdu.setOutgoingLength(lengthOfW);
        apdu.sendBytesLong(buffer, ISO7816.OFFSET_CDATA, lengthOfW);
    }

    private void deleteKeyId(APDU apdu) {
        byte[] keyId = getKeyIdFromApdu(apdu);

        short index = getIndexOfKeyIdKeyPair(keyId);

        deleteKeyIdKeyPairFromArray(index);
    }

    private void deleteKeyIdKeyPairFromArray(short index) {
        if (keyIdKeyPairArray[index] != null) {
            ((KeyIdKeyPair) keyIdKeyPairArray[index]).cleanUp();
            keyIdKeyPairArray[index] = null;
        }
    }

    private byte[] getKeyIdFromApdu(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short recv = apdu.setIncomingAndReceive();

        byte[] keyId = TransientByteArraySimplifier.one(recv);

        ArraySimplifier.one(buffer, ISO7816.OFFSET_CDATA, keyId, (short) 0, recv);
        return keyId;
    }

    private void cleanUpPersonalDataHolder() {
        if (personalDataHolder != null) {
            if (personalDataHolder.keyId != null) {
                short index = getIndexOfKeyIdKeyPair(personalDataHolder.keyId);
                deleteKeyIdKeyPairFromArray(index);
            }

            PersonalDataGarbageCollector.cleanUp(personalDataHolder);
            try {
                JCSystem.beginTransaction();
                PersonalDataHolder oldData = personalDataHolder;
                personalDataHolder = null;
                if (oldData != null) {
                    JCSystem.requestObjectDeletion();
                }
                JCSystem.commitTransaction();
            } catch (Exception e) {
                JCSystem.abortTransaction();
            }
        }
    }

    private byte[] receiveData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short recv = apdu.setIncomingAndReceive();

        // Case 4E APDU with lc < 256 leads to an empty buffer (apdu.getBuffer()) when using eSIM.
        // Implemented workaround for eSIM compatibility: If lc < 256, the data gets padded with
        // zeros at the beginning. The original length of the data gets stored in p1

        short p1 = (short) (buffer[ISO7816.OFFSET_P1] & 0xFF);
        boolean isPaddedData = p1 != (short)0;
        short dataLength = isPaddedData ? p1 : apdu.getIncomingLength();

        short dataOffset = isPaddedData ? ((short) (apdu.getOffsetCdata() + (MAX_NON_EL_DATA_SIZE - dataLength))) : apdu.getOffsetCdata();

        if (isPaddedData) {
            short lengthOfPadding = ((short) (MAX_NON_EL_DATA_SIZE - dataLength));
            recv = ((short) (recv - lengthOfPadding));
        }

        byte[] body = TransientByteArraySimplifier.one(dataLength);
        short offset = 0;
        while (recv > 0) {
            offset = ArraySimplifier.one(buffer, dataOffset, body, offset, recv);
            recv = apdu.receiveBytes(dataOffset);
        }

        return body;
    }

    private void checkForPersonalData() {
        if (personalDataHolder == null) {
            ISOException.throwIt(ErrorConstant.SW_NO_DATA_STORED);
        }
    }

    private void checkForPinSetAndValidated() {
        if (pin == null) {
            ISOException.throwIt(ErrorConstant.SW_PIN_NOT_SET);
        }

        if (!pin.isValidated()) {
            ISOException.throwIt(ErrorConstant.SW_PIN_VERIFICATION_REQUIRED);
        }
    }

    private void initSignatureInstance(KeyPair keyPair) {
        SignatureSimplifier.createAndInitSignatureInstance(keyPair.getPrivate());
    }

    @Override
    public short processData(byte[] arg0, short arg1, short arg2, byte[] arg3, short arg4) {
        // TODO Auto-generated method stub
        return 0;
    }

}
