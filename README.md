# totp-tool
A command line utility for performing useful operations related to understanding TOTP.

As things stand, this is limited to calculating the TOTP value for a Base32 encoded secret. The secret
must be provided via the command line. The result is the 8 digit current TOTP code.

Assumptions:
* The desired length of the TOTP code is 8 digits.
* The secret is assumed to be a Base32 encoded hex string.
* SHA-1 is used for calculating the hash.
