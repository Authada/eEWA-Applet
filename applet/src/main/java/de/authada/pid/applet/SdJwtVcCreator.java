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
import javacard.security.ECPublicKey;
import javacard.security.PublicKey;

import static de.authada.pid.applet.PidIssuerConstants.*;
import static de.authada.pid.applet.SdJwtVcConstants.*;
import static de.authada.pid.applet.Util.next;

public class SdJwtVcCreator {

    private static short personaLDataLengthCreator(PersonalDataHolder personalDataHolder, byte[] selector) {
        short selectorOffset = 0;

        short lengthOfResponse = (short) (begin.length + cnfJwkPrefix.length + yPrefix.length + end.length);

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, givenName)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(givenNamePrefix, personalDataHolder.givenName));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, familyName)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(familyNamePrefix, personalDataHolder.familyName));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, birthDate)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(birthDatePrefix, personalDataHolder.birthDate));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, sourceDocumentType)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(sourceDocumentTypePrefix, personalDataHolder.sourceDocumentType));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, dateOfExpiry)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(dateOfExpiryPrefix, personalDataHolder.dateOfExpiry));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, academicTitle)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(academicTitlePrefix, personalDataHolder.academicTitle));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, streetAddress)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(addressStreetPrefix, personalDataHolder.streetAddress));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, locality)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(localityPrefix, personalDataHolder.locality));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, postalCode)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(postalCodePrefix, personalDataHolder.postalCode));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, country)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(countryPrefix, personalDataHolder.country));
            lengthOfResponse++;// + 1 because of encapsulation in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, noPlaceInfo)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(noPlaceInfoPrefix, personalDataHolder.noPlaceInfo));
            lengthOfResponse++;// + 1 because of encapsulation in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, freeTextPlace)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(freeTextPlacePrefix, personalDataHolder.freeTextPlace));
            lengthOfResponse++;// + 1 because of encapsulation in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, nationality)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(nationalityPrefix, personalDataHolder.nationality));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, birthFamilyName)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(birthFamilyNamePrefix, personalDataHolder.birthFamilyName));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthLocality)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(placeOfBirthLocalityPrefix, personalDataHolder.placeOfBirthLocality));
            lengthOfResponse++;// + 1 because of encapsulation in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthCountry)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(pobCountryPrefix, personalDataHolder.placeOfBirthCountry));
            lengthOfResponse++;// + 1 because of encapsulation in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthNoPlaceInfo)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(pobNoPlaceInfoPrefix, personalDataHolder.placeOfBirthNoPlaceInfo));
            lengthOfResponse++;// + 1 because of encapsulation in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthFreeTextPlace)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(freeTextPlacePrefix, personalDataHolder.placeOfBirthFreeTextPlace));
            lengthOfResponse++;// + 1 because of encapsulation in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, alsoKnownAs)) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(alsoKnownAsPrefix, personalDataHolder.alsoKnownAs));
        }
        return lengthOfResponse;
    }

    private static short addLengthItem(byte[] prefix, byte[] data) {
        return (short) (prefix.length + data.length + endOfCredential.length);
    }

    public static byte[] fromPersonalData(PersonalDataHolder personalDataHolder, ECPublicKey ephemeralEcPublicKey, byte[] selector) {

        Base64Converter base64Converter = new Base64Converter();
        byte[] publicKeyW = TransientByteArraySimplifier.one((short) 65);
        short publiKeyLength = PublicKeySimplifier.one(ephemeralEcPublicKey, publicKeyW, (short) 0);

        if (publiKeyLength != 65) {
            ISOException.throwIt(ErrorConstant.SW_ILLEGAL_VALUE);
        }


        byte[] publicKeyWx = TransientByteArraySimplifier.one((short) 32), publicKeyWy = TransientByteArraySimplifier.one((short) 32);

        ArraySimplifier.one(publicKeyW, (short) 1, publicKeyWx, (short) 0, (short) publicKeyWx.length);
        ArraySimplifier.one(publicKeyW, (short) 33, publicKeyWy, (short) 0, (short) publicKeyWy.length);

        byte[] encodedX = base64Converter.encodeToBase64UrlNoPadding(publicKeyWx);
        byte[] encodedy = base64Converter.encodeToBase64UrlNoPadding(publicKeyWy);


        short lengthOfResponse = personaLDataLengthCreator(personalDataHolder, selector);

        lengthOfResponse += (short) (encodedX.length + encodedy.length);


        byte[] transientJWT = TransientByteArraySimplifier.one(lengthOfResponse);
        short offset = 0;

        offset = ArraySimplifier.one(begin, (short) 0, transientJWT, offset, (short) begin.length);
        short selectorOffset = 0;
        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, givenName) && personalDataHolder.givenName != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(givenNamePrefix, personalDataHolder.givenName, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, familyName) && personalDataHolder.familyName != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(familyNamePrefix, personalDataHolder.familyName, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, birthDate) && personalDataHolder.birthDate != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(birthDatePrefix, personalDataHolder.birthDate, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, sourceDocumentType) && personalDataHolder.sourceDocumentType != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(sourceDocumentTypePrefix, personalDataHolder.sourceDocumentType, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, dateOfExpiry) && personalDataHolder.dateOfExpiry != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(dateOfExpiryPrefix, personalDataHolder.dateOfExpiry, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, academicTitle) && personalDataHolder.academicTitle != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(academicTitlePrefix, personalDataHolder.academicTitle, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, streetAddress) && personalDataHolder.streetAddress != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(addressStreetPrefix, personalDataHolder.streetAddress, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, locality) && personalDataHolder.locality != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(localityPrefix, personalDataHolder.locality, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, postalCode) && personalDataHolder.postalCode != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(postalCodePrefix, personalDataHolder.postalCode, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, country) && personalDataHolder.country != null) {
            selectorOffset = next(selectorOffset);
            offset = addItemEncapsulatedEnd(countryPrefix, personalDataHolder.country, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, noPlaceInfo) && personalDataHolder.noPlaceInfo != null) {
            selectorOffset = next(selectorOffset);
            offset = addItemEncapsulatedEnd(noPlaceInfoPrefix, personalDataHolder.noPlaceInfo, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, freeTextPlace) && personalDataHolder.freeTextPlace != null) {
            selectorOffset = next(selectorOffset);
            offset = addItemEncapsulatedEnd(freeTextPlacePrefix, personalDataHolder.freeTextPlace, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, nationality) && personalDataHolder.nationality != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(nationalityPrefix, personalDataHolder.nationality, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, birthFamilyName) && personalDataHolder.birthFamilyName != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(birthFamilyNamePrefix, personalDataHolder.birthFamilyName, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthLocality) && personalDataHolder.placeOfBirthLocality != null) {
            selectorOffset = next(selectorOffset);
            offset = addItemEncapsulatedEnd(placeOfBirthLocalityPrefix, personalDataHolder.placeOfBirthLocality, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthCountry) && personalDataHolder.placeOfBirthCountry != null) {
            selectorOffset = next(selectorOffset);
            offset = addItemEncapsulatedEnd(pobCountryPrefix, personalDataHolder.placeOfBirthCountry, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthNoPlaceInfo) && personalDataHolder.placeOfBirthNoPlaceInfo != null) {
            selectorOffset = next(selectorOffset);
            offset = addItemEncapsulatedEnd(pobNoPlaceInfoPrefix, personalDataHolder.placeOfBirthNoPlaceInfo, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthFreeTextPlace) && personalDataHolder.placeOfBirthFreeTextPlace != null) {
            selectorOffset = next(selectorOffset);
            offset = addItemEncapsulatedEnd(freeTextPlacePrefix, personalDataHolder.placeOfBirthFreeTextPlace, offset, transientJWT);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, alsoKnownAs) && personalDataHolder.alsoKnownAs != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(alsoKnownAsPrefix, personalDataHolder.alsoKnownAs, offset, transientJWT);
        }

        offset = ArraySimplifier.three(cnfJwkPrefix, (short) 0, transientJWT, offset, (short) cnfJwkPrefix.length);
        offset = ArraySimplifier.four(encodedX, (short) 0, transientJWT, offset, (short) encodedX.length);
        offset = ArraySimplifier.one(yPrefix, (short) 0, transientJWT, offset, (short) yPrefix.length);
        offset = ArraySimplifier.two(encodedy, (short) 0, transientJWT, offset, (short) encodedy.length);
        offset = ArraySimplifier.three(end, (short) 0, transientJWT, offset, (short) end.length);

        return transientJWT;
    }

    private static short addItem(byte[] prefix, byte[] value, short offset, byte[] response) {
        offset = ArraySimplifier.one(prefix, (short) 0, response, offset, (short) prefix.length);
        offset = ArraySimplifier.two(value, (short) 0, response, offset, (short) value.length);
        return ArraySimplifier.three(endOfCredential, (short) 0, response, offset, (short) endOfCredential.length);
    }

    private static short addItemEncapsulatedEnd(byte[] prefix, byte[] value, short offset, byte[] response) {
        offset = ArraySimplifier.one(prefix, (short) 0, response, offset, (short) prefix.length);
        offset = ArraySimplifier.two(value, (short) 0, response, offset, (short) value.length);
        return ArraySimplifier.three(encapsulatedJsonEnd, (short) 0, response, offset, (short) encapsulatedJsonEnd.length);
    }

    public static byte[] createHeader(PublicKey ecPublic, byte[] foreignPublicKey, Object[] x5cCertificates, Base64Converter base64Converter) {
        byte[] transientECPublicKey = TransientByteArraySimplifier.one((short) 65);
        short ecPublicKeyWLength = PublicKeySimplifier.one((ECPublicKey) ecPublic, transientECPublicKey, (short) 0);

        byte[] ecPublicKeyWx = TransientByteArraySimplifier.one((short)32);
        byte[] ecPublicKeyWy = TransientByteArraySimplifier.one((short)32);

        ArraySimplifier.one(transientECPublicKey, (short)1, ecPublicKeyWx, (short)0, (short)ecPublicKeyWx.length);
        ArraySimplifier.two(transientECPublicKey, (short)33, ecPublicKeyWy, (short)0, (short)ecPublicKeyWy.length);

        byte[] base64EncodedEcPublicKeyX = base64Converter.encodeToBase64UrlNoPadding(ecPublicKeyWx);
        byte[] base64EncodedEcPublicKeyY = base64Converter.encodeToBase64UrlNoPadding(ecPublicKeyWy);

        byte[] foreignPublicKeyWx = TransientByteArraySimplifier.one((short)32);
        byte[] foreignPublicKeyWy = TransientByteArraySimplifier.one((short)32);

        ArraySimplifier.one(foreignPublicKey, (short)1, foreignPublicKeyWx, (short)0, (short)foreignPublicKeyWx.length);
        ArraySimplifier.two(foreignPublicKey, (short)33, foreignPublicKeyWy, (short)0, (short)foreignPublicKeyWy.length);

        byte[] base64EncodedForeignPublicKeyX = base64Converter.encodeToBase64UrlNoPadding(foreignPublicKeyWx);
        byte[] base64EncodedForeignPublicKeyY = base64Converter.encodeToBase64UrlNoPadding(foreignPublicKeyWy);

        Object[] base64EncodedCertificates = TransientObjectArraySimplifier.one(((short) x5cCertificates.length));
        short base64EncodedCertsDataLength = 0;
        for (short i = 0; i < x5cCertificates.length; i++) {
            base64EncodedCertificates[i] = base64Converter.encodeToBase64UrlNoPadding(((byte[]) x5cCertificates[i]));
            base64EncodedCertsDataLength += (short) ((byte[]) base64EncodedCertificates[i]).length;
        }

        short length = (short) (headerBegin.length + base64EncodedEcPublicKeyX.length + yPrefix.length + base64EncodedEcPublicKeyY.length +
                headerRpk.length + base64EncodedForeignPublicKeyX.length + yPrefix.length + base64EncodedForeignPublicKeyY.length + encapsulatedJsonEnd.length + + headerX5c.length + x5cSeparator.length * ((short)(x5cCertificates.length - 1)) + base64EncodedCertsDataLength + headerEnd.length);
        byte[] header = TransientByteArraySimplifier.one(length);

        short offset = 0;

        offset = ArraySimplifier.one(headerBegin, (short) 0, header, offset, (short) headerBegin.length);
        offset = ArraySimplifier.two(base64EncodedEcPublicKeyX, (short) 0, header, offset, (short) base64EncodedEcPublicKeyX.length);
        offset = ArraySimplifier.three(yPrefix, (short) 0, header, offset, (short) yPrefix.length);
        offset = ArraySimplifier.two(base64EncodedEcPublicKeyY, (short) 0, header, offset, (short) base64EncodedEcPublicKeyY.length);
        offset = ArraySimplifier.three(headerRpk, (short) 0, header, offset, (short) headerRpk.length);
        offset = ArraySimplifier.two(base64EncodedForeignPublicKeyX, (short) 0, header, offset, (short) base64EncodedForeignPublicKeyX.length);
        offset = ArraySimplifier.three(yPrefix, (short) 0, header, offset, (short) yPrefix.length);
        offset = ArraySimplifier.two(base64EncodedForeignPublicKeyY, (short) 0, header, offset, (short) base64EncodedForeignPublicKeyY.length);
        offset = ArraySimplifier.one(encapsulatedJsonEnd, (short) 0, header, offset, (short) encapsulatedJsonEnd.length);
        offset = ArraySimplifier.one(headerX5c, (short) 0, header, offset, (short) headerX5c.length);

        for (short i = 0; i < base64EncodedCertificates.length; i++) {
            offset = ArraySimplifier.one(((byte[]) base64EncodedCertificates[i]), (short) 0, header, offset, (short) ((byte[]) base64EncodedCertificates[i]).length);
            if (i < (short)(base64EncodedCertificates.length - 1)) {
                offset = ArraySimplifier.one(x5cSeparator, (short) 0, header, offset, (short) x5cSeparator.length);
            }
        }

        offset = ArraySimplifier.one(headerEnd, (short) 0, header, offset, (short) headerEnd.length);

        return header;
    }
}
