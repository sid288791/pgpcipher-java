# Open PGP Cipher in java

### Steps to run the project
* clone project
    1. git clone https://github.com/sid288791/pgpcipher-java.git
    2. ./gradlew clean build  
* Goto PgpcipherJavaApplication.java    
  - If you want to encrypt file provide below details
  
        1. pgp_pub_key = ''    
        2. file_to_enc = ''     
        3. enc_output_file = '' 
  - comment decryptByPrivKey function as below  
  
    1. //decryptByPrivKey(priv_key_file, passphrase, enc_file, output_file)
  
  - If you want to decrypt file provide below details    
  
    1. pgp_priv_key = ''     
    2. passphrase = ''    
    3. enc_file = ''     
    4. dec_output_file 
    
  - comment encByPubKey function as below    
        1. //encryptByPubKey(pgp_pub_key, file_to_enc, output_file)
* run PgpcipherJavaApplication.java 

# Export and Import pgp keys with GPG

### Export public key with GPG

- $ gpg --list-keys
- $ gpg --export -a keyname > public.asc
- $ cat public.asc

### Export private key with gpg

- $ gpg --list-keys
- $ gpg --export-secret-key -a john > private key
- $ cat private.key

### Import public key with GPG

- $ gpg --list-keys
- $ gpg --import public.asc
- $ gpg --list-public-keys

### Import private key with GPG

- $ gpg --import private.key
- $ gpg --list-secret-keys





   
