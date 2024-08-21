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

public class PidIssuerConstants {
    public static byte[] hmac = {(byte) 0xA0, (byte) 0x01};
    public static byte[] pubKey = {(byte) 0xB0, (byte) 0x01};
    public static byte[] numberOfx5cCertificates = {(byte) 0xB0, (byte) 0x02};
    public static byte[] x5cCertificate = {(byte) 0xB0, (byte) 0x03};
    public static byte[] givenName = {(byte) 0xC0, (byte) 0x01};
    public static byte[] familyName = {(byte) 0xC0, (byte) 0x02};
    public static byte[] birthDate = {(byte) 0xC0, (byte) 0x03};
    public static byte[] sourceDocumentType = {(byte) 0xC0, (byte) 0x04};
    public static byte[] dateOfExpiry = {(byte) 0xC0, (byte) 0x05};
    public static byte[] academicTitle = {(byte) 0xC0, (byte) 0x06};
    public static byte[] streetAddress = {(byte) 0xC0, (byte) 0x07};
    public static byte[] locality = {(byte) 0xC0, (byte) 0x08};
    public static byte[] postalCode = {(byte) 0xC0, (byte) 0x09};
    public static byte[] country = {(byte) 0xC0, (byte) 0x0A};
    public static byte[] noPlaceInfo = {(byte) 0xC0, (byte) 0x0B};
    public static byte[] freeTextPlace = {(byte) 0xC0, (byte) 0x0C};
    public static byte[] nationality = {(byte) 0xC0, (byte) 0x0D};
    public static byte[] birthFamilyName = {(byte) 0xC0, (byte) 0x0E};
    public static byte[] placeOfBirthLocality = {(byte) 0xC0, (byte) 0x0F};
    public static byte[] placeOfBirthCountry = {(byte) 0xC0, (byte) 0x10};
    public static byte[] placeOfBirthNoPlaceInfo = {(byte) 0xC0, (byte) 0x11};
    public static byte[] placeOfBirthFreeTextPlace = {(byte) 0xC0, (byte) 0x12};
    public static byte[] alsoKnownAs = {(byte) 0xC0, (byte) 0x13};
}
