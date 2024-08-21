# eEWA Applet 

This applet implements the functionalities needed for options C and D and is operable on Secure Elements and eSIMs.
It is written using JavaCard version 3.0.5.

## Key features

- Device key pair gets created for each issuing process
- Personal data including necessary data for the PID like x5c certificate chain are stored in TLV format
- Applet creates ad-hoc PID for each presentation. Currently, only SD-JWT VC credentials are supported
- For signature creation, ALG_ECDSA_SHA_256 from javacard.security.Signature is used (see https://docs.oracle.com/javacard/3.0.5/api/javacard/security/Signature.html#ALG_ECDSA_SHA_256)
