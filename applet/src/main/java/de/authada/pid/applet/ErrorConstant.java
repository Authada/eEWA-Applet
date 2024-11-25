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

public class ErrorConstant {

    //no tries left for PIN
    final static short SW_WALLET_BLOCKED = 0x63C0;
    final static short SW_PIN_WRONG_ONE_TRY_LEFT = 0x63C1;
    final static short SW_PIN_WRONG_TWO_TRIES_LEFT = 0x63C2;
    // signal that the PIN has not been validated and a verification is required
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6310;
    static final short SW_PIN_NOT_SET = 0x6311;

    final static short SW_NO_DATA_STORED = 0x6320;
    final static short SW_NO_DEVICE_KEY = 0x6321;
    final static short SW_CHANNEL_NOT_AUTHENTICATED = 0x6322;
    static final short SW_HMAC_MISSING = 0x6323;
    static final short SW_FOREIGN_PUB_KEY_MISSING = 0x6324;
    static final short SW_CREDENTIAL_HANDLE_NOT_FOUND = 0x6325;
    static final short SW_NO_KEY_ID = 0x6326;
    static final short SW_NO_KEY_ID_FOUND = 0x6327;

    final static short SW_ILLEGAL_VALUE = 0x6410;
    final static short SW_ILLEGAL_VALUE2 = 0x6411;
    final static short SW_ILLEGAL_VALUE3 = 0x6412;
    final static short SW_ILLEGAL_VALUE4 = 0x6413;
    final static short SW_ILLEGAL_VALUE5 = 0x6414;
    final static short SW_NO_SUCH_ALGORITHM = 0x6420;
    final static short SW_NO_SUCH_ALGORITHM2 = 0x6421;
    final static short SW_NO_SUCH_ALGORITHM3 = 0x6422;
    final static short SW_UNINITIALIZED_KEY = 0x6430;
    final static short SW_UNINITIALIZED_KEY2 = 0x6431;
    final static short SW_UNINITIALIZED_KEY3 = 0x6432;
    final static short SW_INVALID_INIT = 0x6440;
    final static short SW_INVALID_INIT2 = 0x6441;
    final static short SW_INVALID_INIT3 = 0x6442;
    final static short SW_ARRAY = 0x6450;
    final static short SW_ARRAY2 = 0x6451;
    final static short SW_ARRAY3 = 0x6452;
    final static short SW_ARRAY4 = 0x6453;
    final static short SW_NULL = 0x6460;
    final static short SW_NULL2 = 0x6461;
    final static short SW_NULL3 = 0x6462;
    final static short SW_NULL4 = 0x6463;
    final static short SW_TRANS = 0x6470;
    final static short SW_TRANS2 = 0x6471;
    final static short SW_TRANS3 = 0x6472;
    final static short SW_TRANS4 = 0x6473;
    final static short SW_DEFAULT = 0x6480;
    final static short SW_DEFAULT2 = 0x6481;
    static final short SW_GENERAL = 0x6490;
    static final short SW_GENERAL2 = 0x6491;

    final static short SW_ILLEGAL_USE = 0x64A0;
    final static short SW_ILLEGAL_TRANSIENT = 0x64A2;
    final static short SW_NO_TRANSIENT = 0x64A3;
    final static short SW_UNITIALIZED_KEY = 0x64A4;
    final static short SW_NEGATIVE_ARRAY_SIZE = 0x64A5;
    final static short SW_DELETE_NOT_SUPPORTED = 0x64A6;
}
