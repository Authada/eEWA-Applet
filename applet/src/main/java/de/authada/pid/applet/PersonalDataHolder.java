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
import javacard.framework.Util;

public class PersonalDataHolder {

    Object[] x5cCertificates = null;
    byte[] givenName = null;//mandatory
    byte[] familyName = null;//madantory
    byte[] birthDate = null;//mandatory
    byte[] sourceDocumentType = null;//optional
    byte[] dateOfExpiry = null;
    byte[] academicTitle = null;//optional
    byte[] streetAddress = null;//optional
    byte[] locality = null;//optional
    byte[] postalCode = null;//optional
    byte[] country = null;//optional
    byte[] noPlaceInfo = null;//optional
    byte[] freeTextPlace = null;//optional
    byte[] nationality = null;//optional
    byte[] birthFamilyName = null;//optional
    byte[] placeOfBirthLocality = null;//optional
    byte[] placeOfBirthCountry = null;//optional
    byte[] placeOfBirthNoPlaceInfo = null;//Optional
    byte[] placeOfBirthFreeTextPlace = null;
    byte[] alsoKnownAs = null;//optional

    byte[] keyId = null;
    CredentialHandle credentialHandle = null;

    public byte[] createCredentialHandle() {
        credentialHandle = new CredentialHandle();
        return credentialHandle.generateCredentialHandle();
    }

    public boolean verifyCredentialHandle(byte[] credentialHandleCandidate) {
        return ArraySimplifier.compareOne(credentialHandle.getCredentialHandleArray(), credentialHandleCandidate);
    }

    public byte[] getPersonalData(byte[] credentialHandleCandidate) {
        if (!verifyCredentialHandle(credentialHandleCandidate)) {
            ISOException.throwIt(ErrorConstant.SW_CREDENTIAL_HANDLE_NOT_FOUND);
        }

        byte[] transientPersonalData = TransientByteArraySimplifier.one(getLengthOfPersonalData());

        short offset = 0;
        offset = addDataWithTagToArray(PidIssuerConstants.givenName, givenName, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.familyName, familyName, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.birthDate, birthDate, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.sourceDocumentType, sourceDocumentType, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.dateOfExpiry, dateOfExpiry, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.academicTitle, academicTitle, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.streetAddress, streetAddress, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.locality, locality, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.postalCode, postalCode, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.country, country, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.noPlaceInfo, noPlaceInfo, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.freeTextPlace, freeTextPlace, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.nationality, nationality, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.birthFamilyName, birthFamilyName, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.placeOfBirthLocality, placeOfBirthLocality, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.placeOfBirthCountry, placeOfBirthCountry, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.placeOfBirthNoPlaceInfo, placeOfBirthNoPlaceInfo, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.placeOfBirthFreeTextPlace, placeOfBirthFreeTextPlace, offset, transientPersonalData);
        offset = addDataWithTagToArray(PidIssuerConstants.alsoKnownAs, alsoKnownAs, offset, transientPersonalData);

        return transientPersonalData;
    }

    private short addDataWithTagToArray(byte[] tag, byte[] data, short offset, byte[] array) {
        if (data != null) {
            offset = ArraySimplifier.two(tag, (short) 0, array, offset, ((short) tag.length));
            offset = Util.setShort(array, offset, (short) data.length);
            return ArraySimplifier.three(data, (short) 0, array, offset, ((short) data.length));
        }
        return offset;
    }

    private short getLengthOfPersonalData() {
        return (short) (getNullSafeLengthOfFieldWithTag(givenName) +
                getNullSafeLengthOfFieldWithTag(familyName) +
                getNullSafeLengthOfFieldWithTag(birthDate) +
                getNullSafeLengthOfFieldWithTag(sourceDocumentType) +
                getNullSafeLengthOfFieldWithTag(dateOfExpiry) +
                getNullSafeLengthOfFieldWithTag(academicTitle) +
                getNullSafeLengthOfFieldWithTag(streetAddress) +
                getNullSafeLengthOfFieldWithTag(locality) +
                getNullSafeLengthOfFieldWithTag(postalCode) +
                getNullSafeLengthOfFieldWithTag(country) +
                getNullSafeLengthOfFieldWithTag(noPlaceInfo) +
                getNullSafeLengthOfFieldWithTag(freeTextPlace) +
                getNullSafeLengthOfFieldWithTag(nationality) +
                getNullSafeLengthOfFieldWithTag(birthFamilyName) +
                getNullSafeLengthOfFieldWithTag(placeOfBirthLocality) +
                getNullSafeLengthOfFieldWithTag(placeOfBirthCountry) +
                getNullSafeLengthOfFieldWithTag(placeOfBirthNoPlaceInfo) +
                getNullSafeLengthOfFieldWithTag(placeOfBirthFreeTextPlace) +
                getNullSafeLengthOfFieldWithTag(alsoKnownAs));
    }

    private short getNullSafeLengthOfFieldWithTag(byte[] dataField) {
        if (dataField != null) {
            return (short) (4 + dataField.length); //4 = lengthOfTag + length of encoding of data length
        }
        return 0;
    }
}
