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

    static byte[] begin = {'{', '"', 'v', 'c', 't', '"', ':', '"', 'h', 't', 't', 'p', 's', ':', '/', '/', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'b', 'm', 'i', '.', 'b', 'u', 'n', 'd', '.', 'd', 'e', '/', 'c', 'r', 'e', 'd', 'e', 'n', 't', 'i', 'a', 'l', '/', 'p', 'i', 'd', '/', '1', '.', '0', '"', ',',
            '"', 'v', 'c', 't', '#', 'i', 'n', 't', 'e', 'g', 'r', 'i', 't', 'y', '"', ':', '"', 's', 'h', 'a', '2', '5', '6', '-', 'W', 'R', 'L', '5', 'c', 'a', '_', 'x', 'G', 'g', 'X', '3', 'c', '1', 'V', 'L', 'm', 'X', 'f', 'h', '-', '9', 'c', 'L', 'l', 'J', 'N', 'X', 'N', '-', 'T', 's', 'M', 'k', '-', 'P', 'm', 'K', 'j', 'Z', '5', 't', '0', '"', ',', '"', '_', 's', 'd', '_', 'a', 'l', 'g', '"', ':', '"', 's', 'h', 'a', '-', '2', '5', '6', '"', ','};

    static byte[] endOfCredential = {'"', ','};

    static byte[] givenNamePrefix = {'"', 'g', 'i', 'v', 'e', 'n', '_', 'n', 'a', 'm', 'e', '"', ':', '"'};

    static byte[] familyNamePrefix = {'"', 'f', 'a', 'm', 'i', 'l', 'y', '_', 'n', 'a', 'm', 'e', '"', ':', '"'};

    static byte[] birthDatePrefix = {'"', 'b', 'i', 'r', 't', 'h', 'd', 'a', 't', 'e', '"', ':', '"'};

    static byte[] sourceDocumentTypePrefix = {'"', 's', 'o', 'u', 'r', 'c', 'e', '_', 'd', 'o', 'c', 'u', 'm', 'e', 'n', 't', '_', 't', 'y', 'p', 'e', '"', ':', '"'};

    static byte[] dateOfExpiryPrefix = {'"', 'd', 'a', 't', 'e', '_', 'o', 'f', '_', 'e', 'x', 'p', 'i', 'r', 'y', '"', ':', '"'};

    static byte[] academicTitlePrefix = {'"', 'a', 'c', 'a', 'd', 'e', 'm', 'i', 'c', '_', 't', 'i', 't', 'l', 'e', '"', ':', '"'};

    static byte[] addressStreetPrefix = {'"', 'a', 'd', 'd', 'r', 'e', 's', 's', '"', ':', '{', '"', 's', 't', 'r', 'e', 'e', 't', '"', ':', '"'};

    static byte[] localityPrefix = {'"', 'l', 'o', 'c', 'a', 'l', 'i', 't', 'y', '"', ':', '"'};

    static byte[] freeTextPlacePrefix = {'"', 'f', 'r', 'e', 'e', '_', 't', 'e', 'x', 't', '_', 'p', 'l', 'a', 'c', 'e', '"', ':', '"'};

    static byte[] postalCodePrefix = {'"', 'p', 'o', 's', 't', 'a', 'l', '_', 'c', 'o', 'd', 'e', '"', ':', '"'};

    static byte[] countryPrefix = {'"', 'c', 'o', 'u', 'n', 't', 'r', 'y', '"', ':', '"'};

    static byte[] noPlaceInfoPrefix = {'"', 'n', 'o', '_', 'p', 'l', 'a', 'c', 'e', '_', 'i', 'n', 'f', 'o', '"', ':', '"'};

    static byte[] nationalityPrefix = {'"', 'n', 'a', 't', 'i', 'o', 'n', 'a', 'l', 'i', 't', 'y', '"', ':', '"'};//theres only one nationality on the eID,therefore no array

    static byte[] birthFamilyNamePrefix = {'"', 'b', 'i', 'r', 't', 'h', '_', 'f', 'a', 'm', 'i', 'l', 'y', '_', 'n', 'a', 'm', 'e', '"', ':', '"'};

    static byte[] placeOfBirthLocalityPrefix = {'"', 'p', 'l', 'a', 'c', 'e', '_', 'o', 'f', '_', 'b', 'i', 'r', 't', 'h', '"', ':', '{', '"', 'l', 'o', 'c', 'a', 'l', 'i', 't', 'y', '"', ':', '"'};

    static byte[] pobCountryPrefix = {'"', 'c', 'o', 'u', 'n', 't', 'r', 'y', '"', ':', '"'};

    static byte[] pobNoPlaceInfoPrefix = {'"', 'n', 'o', '_', 'p', 'l', 'a', 'c', 'e', '_', 'i', 'n', 'f', 'o', '"', ':', '"'};

    static byte[] alsoKnownAsPrefix = {'"', 'a', 'l', 's', 'o', '_', 'k', 'n', 'o', 'w', 'n', '_', 'a', 's', '"', ':', '"'};

    static byte[] encapsulatedJsonEnd = {'"', '}', ','};

    static byte[] cnfJwkPrefix = {'"', 'c', 'n', 'f', '"', ':', '{', '"', 'j', 'w', 'k', '"', ':', '{', '"', 'k', 't', 'y', '"', ':', '"', 'E', 'C', '"', ',', '"', 'c', 'r', 'v', '"', ':', '"', 'P', '-', '2', '5', '6', '"', ',',
            '"', 'x', '"', ':', '"'};

    static byte[] yPrefix = {'"', ',', '"', 'y', '"', ':', '"'};

    static byte[] end = {'"', '}', '}', '}'};

    static byte[] x5cSeparator = {'"', ',', '"'};
}
