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

public class SdJwtVcConstants {
    static byte[] headerBegin = {'{', '"', 't', 'y', 'p', '"', ':', '"', 'v', 'c', '+', 's', 'd', '-', 'j', 'w', 't', '"', ',', '"', 'a', 'l', 'g', '"', ':', '"', 'D', 'V', 'S', '-', 'P', '2', '5', '6', '-', 'S', 'H', 'A', '2', '5', '6', '-', 'H', 'S', '2', '5', '6', '"', ',', '"', 'j', 'w', 'k', '"', ':', '{', '"', 'k', 't', 'y', '"', ':', '"', 'E', 'C', '"', ',', '"', 'c', 'r', 'v', '"', ':', '"', 'P', '-', '2', '5', '6', '"', ',',
            '"', 'x', '"', ':', '"'};

    static byte[] headerRpk = {'"', '}', ',', '"', 'r', 'p', 'k', '"', ':', '{', '"', 'k', 't', 'y', '"', ':', '"', 'E', 'C', '"', ',', '"', 'c', 'r', 'v', '"', ':', '"', 'P', '-', '2', '5', '6', '"', ',',
            '"', 'x', '"', ':', '"'};

    static byte[] headerX5c = {'"', 'x', '5', 'c', '"', ':', '[', '"'};

    static byte[] headerEnd = {'"', ']', '}'};

    static byte[] begin = {'{', '"', 'v', 'c', 't', '"', ':', '"', 'h', 't', 't', 'p', 's', ':', '/', '/', 'm', 'e', 't', 'a', 'd', 'a', 't', 'a', '-', '8', 'c', '0', '6', '2', 'a', '.', 'u', 's', 'e', 'r', 'c', 'o', 'n', 't', 'e', 'n', 't', '.', 'o', 'p', 'e', 'n', 'c', 'o', 'd', 'e', '.', 'd', 'e', '/', 'p', 'i', 'd', '.', 'j', 's', 'o', 'n','"', ',',
            '"', 'v', 'c', 't', '#', 'i', 'n', 't', 'e', 'g', 'r', 'i', 't', 'y', '"', ':', '"', 's', 'h', 'a', '2', '5', '6', '-', '0', '6', 'a', 'f', '3', 'f', '5', 'd', '5', '7', '5', '9', '4', '3', '5', '0', '8', '3', '0', '0', 'a', '4', '3', '6', '1', '1', '1', '3', 'e', 'f', '3', '5', '8', '0', 'a', '6', 'c', '7', '7', '1', 'd', '3', '6', 'e', 'a', 'a', '1', 'f', '2', 'f', '2', 'f', '1', 'f', 'e', '8', '7', '6', '4', 'a', 'c', 'f', '3', '3', '"', ',',
            '"', '_', 's', 'd', '_', 'a', 'l', 'g', '"', ':', '"', 's', 'h', 'a', '-', '2', '5', '6', '"', ',',
            '"', 'i', 's', 's', 'u', 'i', 'n', 'g', '_', 'c', 'o', 'u', 'n', 't', 'r', 'y', '"', ':', '"', 'D', '"', ',',
            '"', 'i', 's', 's', 'u', 'i', 'n', 'g', '_', 'a', 'u', 't', 'h', 'o', 'r', 'i', 't', 'y', '"', ':', '"', 'D', '"', ',',
            '"', 'i', 's', 's', '"', ':', '"', 'h', 't', 't', 'p', 's', ':', '/', '/', 'a', 'u', 't', 'h', 'a', 'd', 'a', '.', 'd', 'e', '"', ','
    };

    static byte[] endOfCredential = {'"', ','};
    static byte[] endOfCredentialWithoutComma = {'"'};
    static byte[] comma = {','};

    static byte[] expPrefix = {'"', 'e', 'x', 'p', '"', ':'};
    static byte[] iatPrefix = {'"', 'i', 'a', 't', '"', ':'};

    static byte[] givenNamePrefix = {'"', 'g', 'i', 'v', 'e', 'n', '_', 'n', 'a', 'm', 'e', '"', ':', '"'};

    static byte[] familyNamePrefix = {'"', 'f', 'a', 'm', 'i', 'l', 'y', '_', 'n', 'a', 'm', 'e', '"', ':', '"'};

    static byte[] birthDatePrefix = {'"', 'b', 'i', 'r', 't', 'h', 'd', 'a', 't', 'e', '"', ':', '"'};

    static byte[] sourceDocumentTypePrefix = {'"', 's', 'o', 'u', 'r', 'c', 'e', '_', 'd', 'o', 'c', 'u', 'm', 'e', 'n', 't', '_', 't', 'y', 'p', 'e', '"', ':', '"'};

    static byte[] dateOfExpiryPrefix = {'"', 'd', 'a', 't', 'e', '_', 'o', 'f', '_', 'e', 'x', 'p', 'i', 'r', 'y', '"', ':'};

    static byte[] academicTitlePrefix = {'"', 'a', 'c', 'a', 'd', 'e', 'm', 'i', 'c', '_', 't', 'i', 't', 'l', 'e', '"', ':', '"'};

    static byte[] addressStreetPrefix = {'"', 'a', 'd', 'd', 'r', 'e', 's', 's', '"', ':', '{', '"', 's', 't', 'r', 'e', 'e', 't', '"', ':', '"'};

    static byte[] localityPrefix = {'"', 'l', 'o', 'c', 'a', 'l', 'i', 't', 'y', '"', ':', '"'};

    static byte[] freeTextPlacePrefix = {'"', 'f', 'r', 'e', 'e', '_', 't', 'e', 'x', 't', '_', 'p', 'l', 'a', 'c', 'e', '"', ':', '"'};

    static byte[] postalCodePrefix = {'"', 'p', 'o', 's', 't', 'a', 'l', '_', 'c', 'o', 'd', 'e', '"', ':', '"'};

    static byte[] countryPrefix = {'"', 'c', 'o', 'u', 'n', 't', 'r', 'y', '"', ':', '"'};

    static byte[] noPlaceInfoPrefix = {'"', 'n', 'o', '_', 'p', 'l', 'a', 'c', 'e', '_', 'i', 'n', 'f', 'o', '"', ':', '"'};

    static byte[] nationalityPrefix = {'"', 'n', 'a', 't', 'i', 'o', 'n', 'a', 'l', 'i', 't', 'i', 'e', 's', '"', ':', '[', '"'};

    static byte[] arrayItemEnd = {'"', ']', ','};

    static byte[] birthFamilyNamePrefix = {'"', 'b', 'i', 'r', 't', 'h', '_', 'f', 'a', 'm', 'i', 'l', 'y', '_', 'n', 'a', 'm', 'e', '"', ':', '"'};

    static byte[] placeOfBirthLocalityPrefix = {'"', 'p', 'l', 'a', 'c', 'e', '_', 'o', 'f', '_', 'b', 'i', 'r', 't', 'h', '"', ':', '{', '"', 'l', 'o', 'c', 'a', 'l', 'i', 't', 'y', '"', ':', '"'};

    static byte[] pobCountryPrefix = {'"', 'c', 'o', 'u', 'n', 't', 'r', 'y', '"', ':', '"'};

    static byte[] pobNoPlaceInfoPrefix = {'"', 'n', 'o', '_', 'p', 'l', 'a', 'c', 'e', '_', 'i', 'n', 'f', 'o', '"', ':', '"'};

    static byte[] alsoKnownAsPrefix = {'"', 'a', 'l', 's', 'o', '_', 'k', 'n', 'o', 'w', 'n', '_', 'a', 's', '"', ':', '"'};

    static byte[] encapsulatedJsonEnd = {'"', '}', ','};
    static byte[] encapsulatedJsonEnd2 = {'}', ','};

    static byte[] cnfJwkPrefix = {'"', 'c', 'n', 'f', '"', ':', '{', '"', 'j', 'w', 'k', '"', ':', '{', '"', 'k', 't', 'y', '"', ':', '"', 'E', 'C', '"', ',', '"', 'c', 'r', 'v', '"', ':', '"', 'P', '-', '2', '5', '6', '"', ',',
            '"', 'x', '"', ':', '"'};

    static byte[] yPrefix = {'"', ',', '"', 'y', '"', ':', '"'};

    static byte[] end = {'"', '}', '}', '}'};

    static byte[] x5cSeparator = {'"', ',', '"'};
}
