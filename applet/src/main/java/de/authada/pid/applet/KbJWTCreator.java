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

import static de.authada.pid.applet.KbJWTConstants.*;

public class KbJWTCreator {
    public static byte[] createHeader() {
        return KbJWTConstants.header;
    }

    public static byte[] createBody(byte[] iat, byte[] auditor, byte[] nonce, byte[] sdHash) {
        short length = (short) (payloadBeginIat.length
                + iat.length
                + payloadAud.length
                + auditor.length
                + payloadNonce.length
                + nonce.length
                + payloadSdHash.length
                + sdHash.length
                + payloadEnd.length);

        byte[] body = TransientByteArraySimplifier.one(length);

        short offset = 0;

        offset = ArraySimplifier.one(payloadBeginIat, (short) 0, body, offset, (short) payloadBeginIat.length);

        offset = ArraySimplifier.two(iat, (short) 0, body, offset, (short) iat.length);

        offset = ArraySimplifier.three(payloadAud, (short) 0, body, offset, (short) payloadAud.length);
        offset = ArraySimplifier.four(auditor, (short) 0, body, offset, (short) auditor.length);

        offset = ArraySimplifier.one(payloadNonce, (short) 0, body, offset, (short) payloadNonce.length);
        offset = ArraySimplifier.two(nonce, (short) 0, body, offset, (short) nonce.length);

        offset = ArraySimplifier.three(payloadSdHash, (short) 0, body, offset, (short) payloadSdHash.length);
        offset = ArraySimplifier.four(sdHash, (short) 0, body, offset, (short) sdHash.length);

        offset = ArraySimplifier.one(payloadEnd, (short) 0, body, offset, (short) payloadEnd.length);

        return body;
    }
}
