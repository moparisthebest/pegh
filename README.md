pegh
----

[pegh](http://klingonska.org/dict/?q=tlh%3Apegh) is Klingon for secret

pegh is a file encryption tool using passwords and authenticated encryption. It returns proper exit codes so you can tell whether encryption/decryption failed or not.

pegh implements a simple versioned file format so encryption parameters can change in the future, but currently version 0 derives a 256-bit key from your password with scrypt, and uses that to encrypt/decrypt your file with aes-256-gcm.

todo: document usage and file format