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

import javacard.framework.JCSystem;

public class PersonalDataGarbageCollector {
    public static void cleanUp(PersonalDataHolder personalDataHolder) {
        try {
            JCSystem.beginTransaction();
            Object[] oldData = personalDataHolder.x5cCertificates;
            personalDataHolder.x5cCertificates = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.givenName;
            personalDataHolder.givenName = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.familyName;
            personalDataHolder.familyName = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.birthDate;
            personalDataHolder.birthDate = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.sourceDocumentType;
            personalDataHolder.sourceDocumentType = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.dateOfExpiry;
            personalDataHolder.dateOfExpiry = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.academicTitle;
            personalDataHolder.academicTitle = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.streetAddress;
            personalDataHolder.streetAddress = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.locality;
            personalDataHolder.locality = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.postalCode;
            personalDataHolder.postalCode = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.country;
            personalDataHolder.country = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.noPlaceInfo;
            personalDataHolder.noPlaceInfo = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.freeTextPlace;
            personalDataHolder.freeTextPlace = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.nationality;
            personalDataHolder.nationality = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.birthFamilyName;
            personalDataHolder.birthFamilyName = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.placeOfBirthLocality;
            personalDataHolder.placeOfBirthLocality = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.placeOfBirthCountry;
            personalDataHolder.placeOfBirthCountry = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.placeOfBirthNoPlaceInfo;
            personalDataHolder.placeOfBirthNoPlaceInfo = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.placeOfBirthFreeTextPlace;
            personalDataHolder.placeOfBirthFreeTextPlace = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.alsoKnownAs;
            personalDataHolder.alsoKnownAs = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }

        personalDataHolder.credentialHandle.cleanUp();

        try {
            JCSystem.beginTransaction();
            byte[] oldData = personalDataHolder.keyId;
            personalDataHolder.keyId = null;
            if (oldData != null) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
        }
    }
}
