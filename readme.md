# Easy Password Manager

## Main Idea of Operation

This project is an easy to use but at the same time very secure password manager. All passwords are stored under a layer of AES encryption in its CBC 256 version with a 256-bit (32-byte) derived key stored securely (Aragon in its thickest form) in a protected file on the system.

The program works in such a way that there are two different hashes. One of the two (located in `~/.local/share/epm/epm_aes_key.key`) is a "public" hash in the form of an Aragon2 string (the hash itself includes a section for the randomly generated "salt" value) and this is used only for user authentication. Absolutely any action within the manager requires passing this authentication. The second hash is actually the 256-bit AES key mentioned above; The only difference is that for security reasons this key is never stored in a system file (in a "private" hash), but rather it is generated during the execution of the program. Once the user has been authenticated and therefore the access key to the manager was the correct one to generate the authentication hash, the corresponding program data file is read, which includes the random value for this second hash and, together with the manager key, the private AES encryption key is built. Each operation in the manager requires encryption and/or decryption, therefore the key has to be generated each time.

## Basic user guide

First of all, if this is the first time you start using the manager, when you launch the program it will make you generate a master encryption key for the data file. To keep passwords safe it is preferable to enter a good master key for the manager, although this problem is largely mitigated thanks to key derivation with Aragon2.

[![Master key initialization](images/init.png)](images/init.png)

TODO: Terminar
