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
import javacard.security.PrivateKey;

public class CSP {

    public byte[] signEcdsaSha256(byte[] data, PrivateKey privateKey) {
        return SignatureSimplifier.one(data, privateKey);
    }

    public boolean verifyWithHmacSha256(ECPrivateKey ecPrivateKey, byte[] foreignPublicKey, byte[] data, byte[] inputDataHmac) {
        return HmacSimplifier.createSharedSecretAndVerify(ecPrivateKey, foreignPublicKey, data, inputDataHmac);
    }
}
