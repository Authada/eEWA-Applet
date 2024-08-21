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

import javacard.security.InitializedMessageDigest;
import javacard.security.MessageDigest;

public class HashSimplifier {
    public static byte[] create(byte[] input, short inputOffset, short inputLength) {
        byte[] hashedValue = TransientByteArraySimplifier.one((short) 32);
        InitializedMessageDigest sh256 = MessageDigest.getInitializedMessageDigestInstance(MessageDigest.ALG_SHA_256, false);
        short ret = sh256.doFinal(input, (short) 0, (short) input.length, hashedValue, (short) 0);
        return hashedValue;
    }
}
