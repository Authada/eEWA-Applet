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

import static de.authada.pid.applet.Util.lengthCreator;
import static de.authada.pid.applet.Util.next;

public class PersonalDataCreator {
    public static PersonalDataHolder byteArrayToPersonalData(byte[] rawData, short offset) {
        PersonalDataHolder personalDataHolder = new PersonalDataHolder();
        short length = 0;

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.numberOfx5cCertificates)) {
            offset = next(offset);
            offset = next(offset);
            byte numberOfCertificates = rawData[offset];
            offset = ((short) (offset + 1));
            Object[] certificates = new Object[numberOfCertificates];

            for (short i = 0; i < numberOfCertificates; i++) {
                offset = storeCertificate(certificates, i, offset, rawData);
            }

            personalDataHolder.x5cCertificates = certificates;
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.givenName)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.givenName = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.givenName, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.familyName)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.familyName = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.familyName, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.birthDate)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.birthDate = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.birthDate, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.sourceDocumentType)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.sourceDocumentType = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.sourceDocumentType, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.dateOfExpiry)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.dateOfExpiry = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.dateOfExpiry, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.academicTitle)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.academicTitle = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.academicTitle, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.streetAddress)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.streetAddress = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.streetAddress, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.locality)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.locality = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.locality, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.postalCode)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.postalCode = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.postalCode, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.country)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.country = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.country, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.noPlaceInfo)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.noPlaceInfo = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.noPlaceInfo, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.freeTextPlace)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.freeTextPlace = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.freeTextPlace, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.nationality)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.nationality = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.nationality, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.birthFamilyName)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.birthFamilyName = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.birthFamilyName, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.placeOfBirthLocality)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.placeOfBirthLocality = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.placeOfBirthLocality, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.placeOfBirthCountry)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.placeOfBirthCountry = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.placeOfBirthCountry, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.placeOfBirthNoPlaceInfo)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.placeOfBirthNoPlaceInfo = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.placeOfBirthNoPlaceInfo, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.placeOfBirthFreeTextPlace)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.placeOfBirthFreeTextPlace = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.placeOfBirthFreeTextPlace, (short) 0, length);
        }

        if (ArraySimplifier.tagCompareOne(rawData, offset, PidIssuerConstants.alsoKnownAs)) {
            offset = next(offset);
            length = lengthCreator(rawData, offset);
            personalDataHolder.alsoKnownAs = new byte[length];
            offset = next(offset);
            offset += ArraySimplifier.one(rawData, offset, personalDataHolder.alsoKnownAs, (short) 0, length);
        }

        return personalDataHolder;
    }

    private static short storeCertificate(Object[] certificates, short number, short offset, byte[] data) {
        if (ArraySimplifier.tagCompareOne(data, offset, PidIssuerConstants.x5cCertificate)) {
            offset = next(offset);
            short length = lengthCreator(data, offset);
            byte[] cert = new byte[length];

            offset = next(offset);
            offset += ArraySimplifier.one(data, offset, cert, (short) 0, length);
            certificates[number] = cert;
        }

        return offset;
    }
}
