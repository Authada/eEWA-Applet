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
import javacard.framework.SystemException;

public class TransientByteArraySimplifier {
    public static byte[] one(short length) {
        try {
            return JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(ErrorConstant.SW_NEGATIVE_ARRAY_SIZE);
        } catch (SystemException e) {
            switch (e.getReason()) {
                case SystemException.ILLEGAL_VALUE:
                    ISOException.throwIt(ErrorConstant.SW_ILLEGAL_VALUE);
                    break;
                case SystemException.NO_TRANSIENT_SPACE:
                    ISOException.throwIt(ErrorConstant.SW_NO_TRANSIENT);
                    break;
                case SystemException.ILLEGAL_TRANSIENT:
                    ISOException.throwIt(ErrorConstant.SW_ILLEGAL_TRANSIENT);
                    break;
            }
        }
        return null;
    }
}
