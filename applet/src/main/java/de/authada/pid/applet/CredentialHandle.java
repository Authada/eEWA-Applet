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
import javacard.security.RandomData;

public class CredentialHandle {
    final static short CREDENTIAL_HANDLE_LENGTH = 48;
    private byte[] credentialHandleArray = null;

    public CredentialHandle() {
    }

    public byte[] generateCredentialHandle() {
        RandomData random = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        credentialHandleArray = new byte[CREDENTIAL_HANDLE_LENGTH];
        random.nextBytes(credentialHandleArray, (short) 0, CREDENTIAL_HANDLE_LENGTH);
        return credentialHandleArray;
    }

    public byte[] getCredentialHandleArray() {
        return credentialHandleArray;
    }

    public void cleanUp() {
        try {
            JCSystem.beginTransaction();
            byte[] oldData = credentialHandleArray;
            credentialHandleArray = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }
    }
}
