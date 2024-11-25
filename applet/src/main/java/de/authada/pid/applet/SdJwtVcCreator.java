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

    private static short personalDataLengthCreator(PersonalDataHolder personalDataHolder, byte[] selector, byte[] iat) {
        short selectorOffset = 0;

        short lengthOfResponse = (short) (begin.length + cnfJwkPrefix.length + yPrefix.length + end.length);

        if (personalDataHolder.dateOfExpiry != null) {
            lengthOfResponse = (short) (lengthOfResponse + expPrefix.length + personalDataHolder.dateOfExpiry.length + comma.length);
        }

        if (iat != null) {
            lengthOfResponse = (short) (lengthOfResponse + iatPrefix.length + iat.length + comma.length);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, givenName) && personalDataHolder.givenName != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(givenNamePrefix, personalDataHolder.givenName));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, familyName) && personalDataHolder.familyName != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(familyNamePrefix, personalDataHolder.familyName));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, birthDate) && personalDataHolder.birthDate != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(birthDatePrefix, personalDataHolder.birthDate));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, sourceDocumentType) && personalDataHolder.sourceDocumentType != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(sourceDocumentTypePrefix, personalDataHolder.sourceDocumentType));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, dateOfExpiry) && personalDataHolder.dateOfExpiry != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + dateOfExpiryPrefix.length + personalDataHolder.dateOfExpiry.length + comma.length);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, academicTitle) && personalDataHolder.academicTitle != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(academicTitlePrefix, personalDataHolder.academicTitle));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, streetAddress) && personalDataHolder.streetAddress != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(addressStreetPrefix, personalDataHolder.streetAddress));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, locality) && personalDataHolder.locality != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(localityPrefix, personalDataHolder.locality));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, postalCode) && personalDataHolder.postalCode != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(postalCodePrefix, personalDataHolder.postalCode));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, country) && personalDataHolder.country != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(countryPrefix, personalDataHolder.country));
            lengthOfResponse++;// + 1 because of encapsulation in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, noPlaceInfo) && personalDataHolder.noPlaceInfo != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(noPlaceInfoPrefix, personalDataHolder.noPlaceInfo));
            lengthOfResponse++;// + 1 because of encapsulation in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, freeTextPlace) && personalDataHolder.freeTextPlace != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(freeTextPlacePrefix, personalDataHolder.freeTextPlace));
            lengthOfResponse++;// + 1 because of encapsulation in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, nationality) && personalDataHolder.nationality != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(nationalityPrefix, personalDataHolder.nationality));
            lengthOfResponse++; //+ 1 because of array in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, birthFamilyName) && personalDataHolder.birthFamilyName != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(birthFamilyNamePrefix, personalDataHolder.birthFamilyName));
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthLocality) && personalDataHolder.placeOfBirthLocality != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(placeOfBirthLocalityPrefix, personalDataHolder.placeOfBirthLocality));
            lengthOfResponse++;// + 1 because of encapsulation in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthCountry) && personalDataHolder.placeOfBirthCountry != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(pobCountryPrefix, personalDataHolder.placeOfBirthCountry));
            lengthOfResponse++;// + 1 because of encapsulation in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthNoPlaceInfo) && personalDataHolder.placeOfBirthNoPlaceInfo != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(pobNoPlaceInfoPrefix, personalDataHolder.placeOfBirthNoPlaceInfo));
            lengthOfResponse++;// + 1 because of encapsulation in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthFreeTextPlace) && personalDataHolder.placeOfBirthFreeTextPlace != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(freeTextPlacePrefix, personalDataHolder.placeOfBirthFreeTextPlace));
            lengthOfResponse++;// + 1 because of encapsulation in json
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, alsoKnownAs) && personalDataHolder.alsoKnownAs != null) {
            selectorOffset = next(selectorOffset);
            lengthOfResponse = (short) (lengthOfResponse + addLengthItem(alsoKnownAsPrefix, personalDataHolder.alsoKnownAs));
        }
        return lengthOfResponse;
    }

    private static short addLengthItem(byte[] prefix, byte[] data) {
        return (short) (prefix.length + data.length + endOfCredential.length);
    }

    public static byte[] fromPersonalData(PersonalDataHolder personalDataHolder, ECPublicKey ephemeralEcPublicKey, byte[] selector, byte[] iat) {

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


        short lengthOfResponse = personalDataLengthCreator(personalDataHolder, selector, iat);

        lengthOfResponse += (short) (encodedX.length + encodedy.length);


        byte[] transientJWT = TransientByteArraySimplifier.one(lengthOfResponse);
        short offset = 0;

        offset = ArraySimplifier.one(begin, (short) 0, transientJWT, offset, (short) begin.length);

        //exp
        if (personalDataHolder.dateOfExpiry != null) {
            offset = addItem(expPrefix, personalDataHolder.dateOfExpiry, offset, transientJWT, comma);
        }

        if (iat != null) {
            offset = addItem(iatPrefix, iat, offset, transientJWT, comma);
        }

        short selectorOffset = 0;
        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, givenName) && personalDataHolder.givenName != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(givenNamePrefix, personalDataHolder.givenName, offset, transientJWT, endOfCredential);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, familyName) && personalDataHolder.familyName != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(familyNamePrefix, personalDataHolder.familyName, offset, transientJWT, endOfCredential);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, birthDate) && personalDataHolder.birthDate != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(birthDatePrefix, personalDataHolder.birthDate, offset, transientJWT, endOfCredential);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, sourceDocumentType) && personalDataHolder.sourceDocumentType != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(sourceDocumentTypePrefix, personalDataHolder.sourceDocumentType, offset, transientJWT, endOfCredential);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, dateOfExpiry) && personalDataHolder.dateOfExpiry != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(dateOfExpiryPrefix, personalDataHolder.dateOfExpiry, offset, transientJWT, comma);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, academicTitle) && personalDataHolder.academicTitle != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(academicTitlePrefix, personalDataHolder.academicTitle, offset, transientJWT, endOfCredential);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, streetAddress) && personalDataHolder.streetAddress != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(addressStreetPrefix, personalDataHolder.streetAddress, offset, transientJWT, endOfCredential);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, locality) && personalDataHolder.locality != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(localityPrefix, personalDataHolder.locality, offset, transientJWT, endOfCredential);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, postalCode) && personalDataHolder.postalCode != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(postalCodePrefix, personalDataHolder.postalCode, offset, transientJWT, endOfCredential);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, country) && personalDataHolder.country != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(countryPrefix, personalDataHolder.country, offset, transientJWT, encapsulatedJsonEnd);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, noPlaceInfo) && personalDataHolder.noPlaceInfo != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(noPlaceInfoPrefix, personalDataHolder.noPlaceInfo, offset, transientJWT, encapsulatedJsonEnd);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, freeTextPlace) && personalDataHolder.freeTextPlace != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(freeTextPlacePrefix, personalDataHolder.freeTextPlace, offset, transientJWT, encapsulatedJsonEnd);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, nationality) && personalDataHolder.nationality != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(nationalityPrefix, personalDataHolder.nationality, offset, transientJWT, arrayItemEnd);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, birthFamilyName) && personalDataHolder.birthFamilyName != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(birthFamilyNamePrefix, personalDataHolder.birthFamilyName, offset, transientJWT, endOfCredential);
        }

        boolean placeOfBirthAskedAndThere = false;
        boolean hasMoreThanPoBLocality = false;

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthLocality) && personalDataHolder.placeOfBirthLocality != null) {
            placeOfBirthAskedAndThere = true;
            selectorOffset = next(selectorOffset);
            offset = addItem(placeOfBirthLocalityPrefix, personalDataHolder.placeOfBirthLocality, offset, transientJWT, endOfCredentialWithoutComma);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthCountry) && personalDataHolder.placeOfBirthCountry != null) {
            placeOfBirthAskedAndThere = true;
            hasMoreThanPoBLocality = true;
            offset = ArraySimplifier.three(comma, (short) 0, transientJWT, offset, (short) comma.length);
            selectorOffset = next(selectorOffset);
            offset = addItem(pobCountryPrefix, personalDataHolder.placeOfBirthCountry, offset, transientJWT, encapsulatedJsonEnd);
        }
        if (placeOfBirthAskedAndThere && !hasMoreThanPoBLocality) {
            offset = ArraySimplifier.three(encapsulatedJsonEnd2, (short) 0, transientJWT, offset, (short) encapsulatedJsonEnd2.length);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthNoPlaceInfo) && personalDataHolder.placeOfBirthNoPlaceInfo != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(pobNoPlaceInfoPrefix, personalDataHolder.placeOfBirthNoPlaceInfo, offset, transientJWT, encapsulatedJsonEnd);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, placeOfBirthFreeTextPlace) && personalDataHolder.placeOfBirthFreeTextPlace != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(freeTextPlacePrefix, personalDataHolder.placeOfBirthFreeTextPlace, offset, transientJWT, encapsulatedJsonEnd);
        }

        if (ArraySimplifier.tagCompareOne(selector, selectorOffset, alsoKnownAs) && personalDataHolder.alsoKnownAs != null) {
            selectorOffset = next(selectorOffset);
            offset = addItem(alsoKnownAsPrefix, personalDataHolder.alsoKnownAs, offset, transientJWT, endOfCredential);
        }

        offset = ArraySimplifier.three(cnfJwkPrefix, (short) 0, transientJWT, offset, (short) cnfJwkPrefix.length);
        offset = ArraySimplifier.four(encodedX, (short) 0, transientJWT, offset, (short) encodedX.length);
        offset = ArraySimplifier.one(yPrefix, (short) 0, transientJWT, offset, (short) yPrefix.length);
        offset = ArraySimplifier.two(encodedy, (short) 0, transientJWT, offset, (short) encodedy.length);
        offset = ArraySimplifier.three(end, (short) 0, transientJWT, offset, (short) end.length);

        return transientJWT;
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


    private static short addItem(byte[] prefix, byte[] value, short offset, byte[] response, byte[] itemEnd) {
        offset = ArraySimplifier.one(prefix, (short) 0, response, offset, (short) prefix.length);
        offset = ArraySimplifier.two(value, (short) 0, response, offset, (short) value.length);
        return ArraySimplifier.three(itemEnd, (short) 0, response, offset, (short) itemEnd.length);
    }
}
