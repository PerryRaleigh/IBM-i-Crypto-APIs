**free
// -------------------------------------------------------------------
// LICENSE AND DISCLAIMER
// ----------------------
// This material contains IBM copyrighted sample programming source
// code ( Sample Code ).
// IBM grants you a nonexclusive license to compile, link, execute,
// display, reproduce, distribute and prepare derivative works of
// this Sample Code.  The Sample Code has not been thoroughly
// tested under all conditions.  IBM, therefore, does not guarantee
// or imply its reliability, serviceability, or function. IBM
// provides no program services for the Sample Code.
//
// All Sample Code contained herein is provided to you "AS IS"
// without any warranties of any kind. THE IMPLIED WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NON-INFRINGMENT ARE EXPRESSLY DISCLAIMED.
// SOME JURISDICTIONS DO NOT ALLOW THE EXCLUSION OF IMPLIED
// WARRANTIES, SO THE ABOVE EXCLUSIONS MAY NOT APPLY TO YOU.  IN NO
// EVENT WILL IBM BE LIABLE TO ANY PARTY FOR ANY DIRECT, INDIRECT,
// SPECIAL OR OTHER CONSEQUENTIAL DAMAGES FOR ANY USE OF THE SAMPLE
// CODE INCLUDING, WITHOUT LIMITATION, ANY LOST PROFITS, BUSINESS
// INTERRUPTION, LOSS OF PROGRAMS OR OTHER DATA ON YOUR INFORMATION
// HANDLING SYSTEM OR OTHERWISE, EVEN IF WE ARE EXPRESSLY ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGES.
//
// -------------------------------------------------------------------
//  <START_COPYRIGHT>
//
//  Licensed Materials - Property of IBM
//
//  5770-SS1
//
//  (c) Copyright IBM Corp. 2015, 2015
//  All Rights Reserved
//
//  U.S. Government Users Restricted Rights - use,
//  duplication or disclosure restricted by GSA
//  ADP Schedule Contract with IBM Corp.
//
//  Status: Version 1 Release 0
//  <END_COPYRIGHT>
// -------------------------------------------------------------------
//
// This material contains programming source code for your
// consideration. IBM provides no program services for
// these programs and files.
//
// Sample RPG program: Setup key and encode with key
// Description: This is a sample program to demonstrate use
// of the Cryptographic Services APIs. APIs demonstrated in
// this program are:
// Load Master Key
// Set Master Key
// Create Key Store
// Generate Key Record
// Create Algorithm Context
// Encrypt Data using key record from key store
// Destroy Algorithm Context
//
// Function:
// Load Master Key 3
// Set Master Key 3
// Create key store file, CUSKEYFILE.
// Create a KEK in CUSKEYFILE with label CUSDTAKEK.
// Create an algorithm context
// Encrypt a sample data string using the key and the algorithm context
// previously created
//
// TO CREATE the module:
// Use the following command to compile this program:
// CRTRPGMOD MODULE(MY_LIB/ENCODEFNL) SRCFILE(MY_LIB/QRPGLESRC)

Ctl-opt OPTION(*SRCSTMT : *NODEBUGIO) dftactgrp(*no)
        COPYRIGHT('5770SS1 (C) Copyright IBM Corp. 2015, 2015. All rights +
                   reserved. US Government Users Restricted Rights - Use, +
                   duplication or disclosure restricted by GSA ADP Schedule +
                   Contract with IBM Corp. Licensed Materials-Property of IBM');

// System includes
/Copy QSYSINC/QRPGLESRC,QUSEC
/Copy QSYSINC/QRPGLESRC,QC3CCI

// API error structure
Dcl-ds APIERR;
  ERRPRV int(10) INZ(272);
  ERRLEN int(10);
  EXCPID char(7);
  RSRVD2 char(1);
  EXCPDT char(256);
End-ds;

Dcl-ds keystr;
  name char(20) INZ('CUSKEYFILEDJREUSCH ');
  record char(32) INZ('CUSDTAKEK');
  rsvd char(4) INZ(X'00000000');
End-ds;

// Prototypes
Dcl-pr LoadMstKeyPart extpgm('Qc3LoadMasterKeyPart');
  MasterKeyID int(10);
  Passphrase char(20);
  PassPhraseLen int(10);
  CCSID int(10);
  ecode like(APIERR);
End-pr;

Dcl-pr SetMasterKey extpgm('Qc3SetMasterKey');
  MasterKeyID int(10);
  KeyVfyValue char(20);
  ecode like(APIERR);
End-pr;

Dcl-pr CrtKeyStore extpgm('Qc3CreateKeyStore');
  FileName char(20) const;
  KeyID int(10) const;
  PublicAuth char(10) const;
  Description char(50) const;
  errCod char(1);
End-pr;

Dcl-pr GenKeyRcd extpgm('Qc3GenKeyRecord');
  FileName char(20) const;
  RecordLabel char(32) const;
  KeyType int(10) const;
  KeySize int(10) const;
  KeyExp int(10) const;
  DisFnc int(10) const;
  csp char(1) const;
  cspDevNam char(10) const options(*omit);
  errCod char(1);
End-pr;

//Encrypt Data
Dcl-pr Qc3EncryptData extpgm('Qc3EncryptData');
  clrDta char(32767);
  clrDtaLen inz(10);
  clrDtaFmt char(8);
  algorithm like(QC3D0400);
  algorithmFmt char(8);
  key like(KeyC);
  keyFmtNm char(8);
  srvProvider char(1);
  deviceName char(10);
  encryptedData char(32767);
  encryptedBufL int(10);
  encryptedRtnL int(10);
  errcde like(APIERR);
END-PR;

Dcl-pr CrtAlgCtx extpgm('Qc3CreateAlgorithmContext');
  algD char(1) const;
  algFormat char(8) const;
  AESctx char(8);
  errCod char(1);
END-PR;

Dcl-pr DestroyAlgCtx extpgm('Qc3DestroyAlgorithmContext');
  AESTkn char(8) const;
  errCod char(1);
END-PR;

// Local variables
Dcl-s Passphrase char(20) inz('this is a 20 char pp');
Dcl-s PassPhraseLen int(10) inz(20);
Dcl-s CCSID int(10) inz(37);
Dcl-s MasterKeyID int(10);
Dcl-s KeyVfyValue char(20);
Dcl-s algorithm like(QC3D0400);
Dcl-s algorithmFmt char(8) inz('ALGD0400');
Dcl-s AESctx char(8);
Dcl-s srvProvider char(1);
Dcl-s clrDta char(32767);
Dcl-s clrDtaLen int(10);
Dcl-s clrDtaFmt char(8) inz('DATA0100');
Dcl-s deviceName char(10);
Dcl-s encryptedData char(32767);

Dcl-s encryptedDtaL int(10);

Dcl-s encryptedBufL int(10);
Dcl-s encryptedRtnL int(10);
Dcl-s KeyC char(1504);
Dcl-s keyFmtNm char(8) inz('KEYD0200');
Dcl-s key like(KeyC);
Dcl-c InputStrinG 'My Test String ABCDEF';

MasterKeyID = 3;

LoadMstKeyPart( MasterKeyID
    :Passphrase
    :PassPhraseLen
    :CCSID
    :APIERR);

SetMasterKey( MasterKeyID
    :KeyVfyValue
    :APIERR);

// Create key store file, CUSKEYFILE, and generate a key record
// with label CUSDTAKEK.
// parameters:
// 1) Qualified Key Store file name
// 2) Master Key ID
// 3) Public authority on Key Store File
// 4) Text description
// 5) Error code

QC3D040000 = *loval;
QC3KS00 = 'CUSKEYFILEDJREUSCH';
CrtKeyStore( QC3KS00 :3
    :'*EXCLUDE'
    :'Key store for CUSDTA,CUSPI'
    :QUSEC);

// Generate AES key record CUSDTAKEK
// parameters:
// 1)Qualified key store file name: QC3KS00 = djreusch/cuskeyfile
// 2)Record label QC3RL = CUSDTAKEK
// 3)Key type = 50 = RSA
// 4)Key size = 512 = RSA
// 5)Public key exponent, not valid unless key type = 50 , then 65537
// 6)Disallowed function
// 7)Cryptographic service provider 0 = any csp
// 8)Cryptographic device name not valid unless csp = 2(hardware)
// 9)Error code

QC3RL = 'CUSDTAKEK';
GenKeyRcd( QC3KS00 :QC3RL
    :50 :512
    :65537 :0
    :'1' :*OMIT
    :QUSEC);

// Create an AES algorithm context CUSDTAKEK
// parameters
// 1) Algorithm description
// 2) Algorithm descritpion format name
// 3) Algorithm context token (output)
// 4) Error code

QC3D0400 = *loval;
QC3PKA = 50;
QC3PKABF = '0';
QC3SHA = X'00000000';
CrtAlgCtx( QC3D0400 :'ALGD0400'
    :AESctx :QUSEC);

// Encrypt data
// 1) Data to be encrypted
// 2) Length of data to be encrypted
// 3) Format of clear data, DATA0100 says use data in clrdta parm
// 4) encryption algorithm
// 5) algorithm format
// 6) The key to use for encrypting the data
// 7) The format of the key
// 8) service provider type 1 = software
// 9) device name - not valid for software service provider
// 10) the encrypted output string
// 11) the buffer length for the encrypted data
// 12) the actual length of the encrypted data
// 13) error information data structure

clrDta = InputString;
clrDtaLen = %len(%trim(clrDta));
encryptedBufL = %size(encryptedData);
srvProvider = '1';
algorithm = QC3D0400;
keyFmtNm = 'KEYD0400';
key = keystr;
Reset EncryptedData;
Qc3EncryptData(
    clrDta :
    clrDtaLen :
    clrDtaFmt :
    algorithm :
    algorithmFmt :
    key :
    keyFmtNm :
    srvProvider :
    deviceName :
    encryptedData :
    encryptedBufL :
    encryptedRtnL :
    APIERR
    );

DestroyAlgCtx( AESctx :QUSEC);
*inlr = *on;

