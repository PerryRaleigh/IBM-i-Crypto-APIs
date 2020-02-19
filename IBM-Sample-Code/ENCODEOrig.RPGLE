* Sample RPG program: Setup key and encode with key
*
* COPYRIGHT 5722-SS1 (c) IBM Corp 2011
*
* This material contains programming source code for your
* consideration. These examples have not been thoroughly
* tested under all conditions. IBM, therefore, cannot
* guarantee or imply reliability, serviceability, or function
* of these programs. All programs contained herein are
* provided to you "AS IS". THE IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* EXPRESSLY DISCLAIMED. IBM provides no program services for
* these programs and files.
*
* Description: This is a sample program to demonstrate use
* of the Cryptographic Services APIs. APIs demonstrated in
* this program are:
* Load Master Key
* Set Master Key
* Create Key Store
* Generate Key Record
* Create Algorithm Context
* Encrypt Data using key record from key store
* Destroy Algorithm Context
*
* Function:
* Load Master Key 3
* Set Master Key 3
* Create key store file, CUSKEYFILE.
* Create a KEK in CUSKEYFILE with label CUSDTAKEK.
* Create an algorithm context
* Encrypt a sample data string using the key and the algorithm context
* previously created
*
* Use the following command to compile this program:
* CRTRPGMOD MODULE(MY_LIB/ENCODEFNL) SRCFILE(MY_LIB/QRPGLESRC)
*
H dftactgrp(*no) bnddir('QC2LE')

* System includes
D/Copy QSYSINC/QRPGLESRC,QUSEC
D/Copy QSYSINC/QRPGLESRC,QC3CCI

* API error structure
D APIERR DS
D ERRPRV 10I 0 INZ(272)
D ERRLEN 10I 0
D EXCPID 7A
D RSRVD2 1A
D EXCPDT 256A

D keystr DS
D name 20A INZ('CUSKEYFILEDJREUSCH ')
D record 32A INZ('CUSDTAKEK')
D rsvd 4A INZ(X'00000000')

* Prototypes
*
DLoadMstKeyPart pr extproc('Qc3LoadMasterKeyPart')
D MasterKeyID 10i 0
D Passphrase 20
D PassPhraseLen 10i 0
D CCSID 10i 0
D ecode like(APIERR)
*
DSetMasterKey pr extproc('Qc3SetMasterKey')
D MasterKeyID 10i 0
D KeyVfyValue 20
D ecde like(APIERR)
*
DCrtKeyStore pr extproc('Qc3CreateKeyStore')
D FileName 20 const
D KeyID 10i 0 const
D PublicAuth 10 const
D Description 50 const
D errCod 1

DGenKeyRcd pr extproc('Qc3GenKeyRecord')
D FileName 20 const
D RecordLabel 32 const
D KeyType 10i 0 const
D KeySize 10i 0 const
D KeyExp 10i 0 const
D DisFnc 10i 0 const
D csp 1 const
D cspDevNam 10 const options(*omit)
D errCod 1

*Encrypt Data
*
D Qc3EncryptData Pr ExtProc('Qc3EncryptData')
D clrDta 32767a
D clrDtaLen 10I 0
D clrDtaFmt 8
D algorithm like(QC3D0400)
D algorithmFmt 8
D key like(KeyC)
D keyFmtNm 8
D srvProvider 1
D deviceName 10
D encryptedData 32767a
D encryptedBufL 10I 0
D encryptedRtnL 10I 0
D errcde like(APIERR)


DCrtAlgCtx pr extproc('Qc3CreateAlgorithmContext')
D algD 1 const
D algFormat 8 const
D AESctx 8
D errCod 1


DDestroyAlgCtx pr extproc('Qc3DestroyAlgorithmContext')
D AESTkn 8 const
D errCod 1


* Local variables
*
D Passphrase S 20 inz('this is a 20 char pp')
D PassPhraseLen S 10i 0 inz(20)
D CCSID S 10i 0 inz(37)
D MasterKeyID S 10i 0
D KeyVfyValue S 20
D algorithm S like(QC3D0400)
D algorithmFmt S 8 inz('ALGD0400')
D AESctx s 8
D srvProvider S 1
D clrDta S 32767a
D clrDtaLen S 10I 0
D clrDtaFmt S 8 inz('DATA0100')
D deviceName S 10
D encryptedData S 32767a
D encryptedDtaL S 10I 0
D encryptedBufL S 10I 0
D encryptedRtnL S 10I 0
D KeyC S 1504
D keyFmtNm S 8 inz('KEYD0200')
D key S like(KeyC)
D InputStrinG C 'My Test String ABCDEF'
D
D
*
C eval MasterKeyID = 3
C
C callp LoadMstKeyPart( MasterKeyID
C :Passphrase
C :PassPhraseLen
C :CCSID
C :APIERR)
C
C callp SetMasterKey( MasterKeyID
C :KeyVfyValue
C :APIERR)

* Create key store file, CUSKEYFILE, and generate a key record
* with label CUSDTAKEK.
* parameters:
* 1) Qualified Key Store file name
* 2) Master Key ID
* 3) Public authority on Key Store File
* 4) Text description
* 5) Error code
C eval QC3D040000 = *loval
C eval QC3KS00 = 'CUSKEYFILEDJREUSCH'
C callp CrtKeyStore( QC3KS00 :3
C :'*EXCLUDE'
C :'Key store for CUSDTA,CUSPI'
C :QUSEC)
* Generate AES key record CUSDTAKEK
* parameters:
* 1)Qualified key store file name: QC3KS00 = djreusch/cuskeyfile
* 2)Record label QC3RL = CUSDTAKEK
* 3)Key type = 50 = RSA
* 4)Key size = 512 = RSA
* 5)Public key exponent, not valid unless key type = 50 , then 65537
* 6)Disallowed function
* 7)Cryptographic service provider 0 = any csp
* 8)Cryptographic device name not valid unless csp = 2(hardware)
* 9)Error code
*
C eval QC3RL = 'CUSDTAKEK'
C*
*
C callp GenKeyRcd( QC3KS00 :QC3RL
C :50 :512
C :65537 :0
C :'1' :*OMIT
C :QUSEC)
C


* Create an AES algorithm context CUSDTAKEK
* parameters
* 1) Algorithm description
* 2) Algorithm descritpion format name
* 3) Algorithm context token (output)
* 4) Error code
C
C eval QC3D0400 = *loval
C Eval QC3PKA = 50
C Eval QC3PKABF = '0'
C Eval QC3SHA = X'00000000'
C
C callp CrtAlgCtx( QC3D0400 :'ALGD0400'
C :AESctx :QUSEC)
C
* Encrypt data
*
* 1) Data to be encrypted
* 2) Length of data to be encrypted
* 3) Format of clear data, DATA0100 says use data in clrdta parm
* 4) encryption algorithm
* 5) algorithm format
* 6) The key to use for encrypting the data
* 7) The format of the key
* 8) service provider type 1 = software
* 9) device name - not valid for software service provider
* 10) the encrypted output string
* 11) the buffer length for the encrypted data
* 12) the actual length of the encrypted data
* 13) error information data structure

C Eval clrDta = InputString
C Eval clrDtaLen = %len(%trim(clrDta))
C Eval encryptedBufL = %size(encryptedData)
C Eval srvProvider = '1'
C Eval algorithm = QC3D0400
C Eval keyFmtNm = 'KEYD0400'
C Eval key = keystr
C Reset EncryptedData
C CallP Qc3EncryptData(
C clrDta :
C clrDtaLen :
C clrDtaFmt :
C algorithm :
C algorithmFmt :
C key :
C keyFmtNm :
C srvProvider :
C deviceName :
C encryptedData :
C encryptedBufL :
C encryptedRtnL :
C APIERR
C )
*
C callp DestroyAlgCtx( AESctx :QUSEC)
C eval *inlr = *on
