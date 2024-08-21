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

public class KbJWTConstants {
    static byte[] header = {'{', '"', 't', 'y', 'p', '"', ':', '"', 'k', 'b', '+', 'j', 'w', 't', '"', ',', '"', 'a', 'l', 'g', '"', ':', '"', 'E', 'S', '2', '5', '6', '"', '}'};

    static byte[] payloadBeginIat = {'{', '"', 'i', 's', 's', '"', ':', '"', 'h', 't', 't', 'p', 's', ':', '/', '/', 'a', 'u', 't', 'h', 'a', 'd', 'a', '.', 'd', 'e', '"', ',', '"', 'i', 'a', 't', '"', ':',};

    static byte[] payloadAud = {',', '"', 'a', 'u', 'd', '"', ':', '"',};

    static byte[] payloadNonce = {'"', ',', '"', 'n', 'o', 'n', 'c', 'e', '"', ':', '"',};

    static byte[] payloadSdHash = {'"', ',', '"', 's', 'd', '_', 'h', 'a', 's', 'h', '"', ':', '"',};

    static byte[] payloadEnd = {'"', '}'};
}

