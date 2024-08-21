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
import javacard.framework.TransactionException;
import javacard.framework.Util;

public class ArraySimplifier {

    public static short one(byte[] input, short inputOffset, byte[] output, short outputOffset, short length) throws ISOException {
        short offset = 0;
        try {
            offset = Util.arrayCopy(input, inputOffset, output, outputOffset, length);
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(ErrorConstant.SW_ARRAY);
        } catch (TransactionException e) {
            ISOException.throwIt(ErrorConstant.SW_TRANS);
        } catch (NullPointerException e) {
            ISOException.throwIt(ErrorConstant.SW_NULL);
        } catch (Exception e) {
            ISOException.throwIt(ErrorConstant.SW_DEFAULT);
        }
        return offset;
    }

    public static short two(byte[] input, short inputOffset, byte[] output, short outputOffset, short length) throws ISOException {
        short offset = 0;
        try {
            offset = Util.arrayCopy(input, inputOffset, output, outputOffset, length);
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(ErrorConstant.SW_ARRAY2);
        } catch (TransactionException e) {
            ISOException.throwIt(ErrorConstant.SW_TRANS2);
        } catch (NullPointerException e) {
            ISOException.throwIt(ErrorConstant.SW_NULL2);
        } catch (Exception e) {
            ISOException.throwIt(ErrorConstant.SW_DEFAULT);
        }
        return offset;
    }

    public static short three(byte[] input, short inputOffset, byte[] output, short outputOffset, short length) throws ISOException {
        short offset = 0;
        try {
            offset = Util.arrayCopy(input, inputOffset, output, outputOffset, length);
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(ErrorConstant.SW_ARRAY3);
        } catch (TransactionException e) {
            ISOException.throwIt(ErrorConstant.SW_TRANS3);
        } catch (NullPointerException e) {
            ISOException.throwIt(ErrorConstant.SW_NULL3);
        } catch (Exception e) {
            ISOException.throwIt(ErrorConstant.SW_DEFAULT);
        }
        return offset;
    }

    public static short four(byte[] input, short inputOffset, byte[] output, short outputOffset, short length) throws ISOException {
        short offset = 0;
        try {
            offset = Util.arrayCopy(input, inputOffset, output, outputOffset, length);
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(ErrorConstant.SW_ARRAY4);
        } catch (TransactionException e) {
            ISOException.throwIt(ErrorConstant.SW_TRANS4);
        } catch (NullPointerException e) {
            ISOException.throwIt(ErrorConstant.SW_NULL4);
        } catch (Exception e) {
            ISOException.throwIt(ErrorConstant.SW_DEFAULT);
        }
        return offset;
    }

    public static boolean tagCompareOne(byte[] input, short inputOffset, byte[] candidate) throws ISOException {
        boolean returnValue = false;
        if (input.length <= inputOffset) {
            return returnValue;
        }
        try {
            return (Util.arrayCompare(input, inputOffset, candidate, (short) 0, (short) 2) == 0);
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(ErrorConstant.SW_ARRAY);
        } catch (NullPointerException e) {
            ISOException.throwIt(ErrorConstant.SW_NULL);
        }


        return returnValue;
    }

    public static boolean compareOne(byte[] input, byte[] candidate) throws ISOException {
        boolean returnValue = false;
        try {
            return (Util.arrayCompare(input, (short) 0, candidate, (short) 0, (short) candidate.length) == 0);
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(ErrorConstant.SW_ARRAY);
        } catch (NullPointerException e) {
            ISOException.throwIt(ErrorConstant.SW_NULL);
        }


        return returnValue;
    }
}
