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
import javacardx.apdu.ExtendedLength;
import org.globalplatform.GPSystem;
import org.globalplatform.Personalization;
import org.globalplatform.SecureChannel;

public class Pid extends Applet implements Personalization, ExtendedLength {

    // instruction bytes
    final static byte VERIFY = (byte) 0x20;
    final static byte CLEAN_TRANSIENT = (byte) 0x35;
    final static byte CREATE_DEVICE_KEYS_AND_NONCE = (byte) 0x39;
    final static byte STORE_PERSONAL_DATA = (byte) 0x42;
    final static byte CREATE_PID = (byte) 0x43;
    final static byte GET_PERSONAL_DATA = (byte) 0x44;
    final static byte GET_AUTHENTICATION_PUBLIC_KEY = (byte) 0x45;
    final static byte GET_DEVICE_PUBLIC_KEY = (byte) 0x46;
    final static byte INIT_UPDATE = (byte) 0x50;
    final static byte SET_PIN = (byte) 0x51;
    final static byte CLEAN_UP = (byte) 0x71;
    static final byte CREATE_SIGNATURE_WITH_DEV_KEY = 0x72;
    static final byte HAS_PIN = 0x73;
    final static byte EXT_AUTHENTICATE = (byte) 0x82;
    // maximum number of incorrect tries before the
    // PIN is blocked
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x06;

    final static short MAX_NON_EL_DATA_SIZE = 256;

    private final KeyPair authenticationKeys;

    private OwnerPIN pin = null;
    private final CSP csp;

    private final PidIssuer pidIssuer;
    private KeyPair deviceKeys;

    private SecureChannel secCh = null;

    private PersonalDataHolder personalDataHolder;

    private Pid(byte[] bArray, short bOffset, byte bLength) {
        csp = new CSP();
        authenticationKeys = SecP256r1.newKeyPair(true);
        pidIssuer = new PidIssuer(csp);
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
            case CREATE_DEVICE_KEYS_AND_NONCE:
                createDeviceKeysAndProcessNonce(apdu);
                return;
            case CREATE_SIGNATURE_WITH_DEV_KEY:
                createSignatureWithDeviceKey(apdu);
                return;
            case CLEAN_TRANSIENT:
                requestObjectDeletion();
                return;
            case GET_AUTHENTICATION_PUBLIC_KEY:
                getAuthenticationPublicKey(apdu);
                return;
            case GET_DEVICE_PUBLIC_KEY:
                getDevicePublicKey(apdu);
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
        cleanUpDeviceKeys();
        cleanUpPersonalDataHolder();
    }

    private void createPid(APDU apdu) {
        checkForDeviceKeysSet();
        checkForPersonalData();

        byte[] body = receiveData(apdu);
        byte[] pid = PidPresentator.create(body, personalDataHolder, deviceKeys);

        short le = apdu.setOutgoing();
        apdu.setOutgoingLength((short) pid.length);
        apdu.sendBytesLong(pid, (short) 0, (short) pid.length);
    }

    private void storePersonalData(APDU apdu) {
        checkForDeviceKeysSet();

        byte[] body = receiveData(apdu);

        personalDataHolder = pidIssuer.verifyAuthenticatedChannelAndCreatePersonalData((ECPrivateKey) deviceKeys.getPrivate(), body);

        byte[] credentialHandle = personalDataHolder.createCredentialHandle();

        short le = apdu.setOutgoing();
        apdu.setOutgoingLength((short) credentialHandle.length);
        apdu.sendBytesLong(credentialHandle, (short) 0, (short) credentialHandle.length);
    }

    private void getPersonalData(APDU apdu) {
        checkForPersonalData();

        byte[] credentialHandleCandidate = receiveData(apdu);
        byte[] personalData = personalDataHolder.getPersonalData(credentialHandleCandidate);

        short le = apdu.setOutgoing();
        apdu.setOutgoingLength((short) personalData.length);
        apdu.sendBytesLong(personalData, (short) 0, (short) personalData.length);
    }

    private void createDeviceKeysAndProcessNonce(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short recv = apdu.setIncomingAndReceive();

        if (deviceKeys != null) {
            cleanUpDeviceKeys();
        }
        deviceKeys = SecP256r1.newKeyPair(false);

        byte[] nonce = TransientByteArraySimplifier.one(recv);

        ArraySimplifier.one(buffer, ISO7816.OFFSET_CDATA, nonce, (short) 0, recv);

        byte[] response = pidIssuer.createDeviceKeysAndProcessNonce(nonce, deviceKeys, authenticationKeys);

        apdu.setOutgoing();
        apdu.setOutgoingLength(((short) response.length));
        apdu.sendBytesLong(response, (short) 0, ((short) response.length));
    }

    private void createSignatureWithDeviceKey(APDU apdu) {
        byte[] transientBuffer = receiveData(apdu);

        //Special handling for older Secure Elements and eSIM: Input data size from EL APDUs is
        //seemingly limited to something around 4000 Bytes, so chaining got implemented. Currently,
        //only this function to create a signature with the device private key gets special command
        //chaining treatment as other functions did not show the need to do so.

        if (apdu.isCommandChainingCLA()) {
            initSignatureInstance();
            SignatureSimplifier.oneUpdateSignature(transientBuffer);
        } else {

            //in case only one command is send for generating a signature and no command chain
            initSignatureInstance();

            byte[] signature = SignatureSimplifier.oneComputeSignature(transientBuffer);

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

    private void getDevicePublicKey(APDU apdu) {
        checkForPinSetAndValidated();
        checkForDeviceKeysSet();

        byte[] buffer = apdu.getBuffer();
        short lengthOfW = PublicKeySimplifier.one((ECPublicKey) deviceKeys.getPublic(), buffer, ISO7816.OFFSET_CDATA);

        apdu.setOutgoing();
        apdu.setOutgoingLength(lengthOfW);
        apdu.sendBytesLong(buffer, ISO7816.OFFSET_CDATA, lengthOfW);
    }

    private void cleanUpDeviceKeys() {
        try {
            JCSystem.beginTransaction();
            KeyPair oldKeys = deviceKeys;
            deviceKeys = null;
            if (oldKeys != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }
    }

    private void cleanUpPersonalDataHolder() {
        if (personalDataHolder != null) {
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

    private void checkForDeviceKeysSet() {
        if (deviceKeys == null) {
            ISOException.throwIt(ErrorConstant.SW_NO_DEVICE_KEY);
        }
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

    private void initSignatureInstance() {
        checkForDeviceKeysSet();
        SignatureSimplifier.createAndInitSignatureInstance(deviceKeys.getPrivate());
    }

    @Override
    public short processData(byte[] arg0, short arg1, short arg2, byte[] arg3, short arg4) {
        // TODO Auto-generated method stub
        return 0;
    }

}
