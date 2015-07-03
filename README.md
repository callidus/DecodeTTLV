# DecodeTTLV
This little utility script will decode TTLV byte buffers as used in the KMIP
protocol. The script requires the PyKMIP library for enum definitions. To use
the script just run it, providing hex encoded TTLV data on the command line.

For example, the following data:

```
42007b01000001c842007a0100000048420069010000002042006a02000000040000000100000000
42006b020000000400000001000000004200920900000008000000005596798f42000d0200000004
000000010000000042000f010000017042005c05000000040000000a0000000042007f0500000004
000000000000000042007c0100000148420057050000000400000002000000004200940700000024
38396136386435302d316334392d346135662d616632612d65366237613264393364653900000000
42008f010000010042004001000000f8420042050000000400000001000000004200450800000070
907ef0d8d06eea4d4410813259d4b2e7cc547dfee391b57a7fa8566f6471d3910692f20ec3ce520f
c65eee142b3cfc359da6503790e996cf5e3ca9fae393ccf0ecf520ff14939476ba1daff3f0cbcf81
e9bd9c39a84778b28529370ef05cb10ca080e1cfbbce2ca3ff654484f29fd0cb4200280500000004
000000030000000042002a02000000040000010000000000420046010000004842009e0500000004
00000001000000004200360100000030420094070000002462613637363839362d353462362d3439
65302d386635622d63326638613733333136336600000000
```

Will be converted to human readable output like so:

```
RESPONSE_MESSAGE:STRUCTURE(456):stru1
 RESPONSE_HEADER:STRUCTURE(72):stru2
  PROTOCOL_VERSION:STRUCTURE(32):stru3
   PROTOCOL_VERSION_MAJOR:INTEGER(4):1
   PROTOCOL_VERSION_MINOR:INTEGER(4):1
  TIME_STAMP:DATE_TIME(8):Thu Jan  1 01:00:00 1970
  BATCH_COUNT:INTEGER(4):1
 RESPONSE_BATCH_ITEM:STRUCTURE(368):stru2
  OPERATION:ENUMERATION(4):GET
  RESULT_STATUS:ENUMERATION(4):SUCCESS
  RESPONSE_PAYLOAD:STRUCTURE(328):stru3
   OBJECT_TYPE:ENUMERATION(4):SYMMETRIC_KEY
   UNIQUE_IDENTIFIER:TEXT_STRING(36):89a68d50-1c49-4a5f-af2a-e6b7a2d93de9
   SYMMETRIC_KEY:STRUCTURE(256):stru4
    KEY_BLOCK:STRUCTURE(248):stru5
     KEY_FORMAT_TYPE:ENUMERATION(4):RAW
     KEY_VALUE:BYTE_STRING(112):907ef0d8d06eea ... truncated
     CRYPTOGRAPHIC_ALGORITHM:ENUMERATION(4):AES
     CRYPTOGRAPHIC_LENGTH:INTEGER(4):256
     KEY_WRAPPING_DATA:STRUCTURE(72):stru6
      WRAPPING_METHOD:ENUMERATION(4):ENCRYPT
      ENCRYPTION_KEY_INFORMATION:STRUCTURE(48):stru7
       UNIQUE_IDENTIFIER:TEXT_STRING(36):ba676896-54b6-49e0-8f5b-c2f8a733163f
```
(key truncated for easy viewing, it wont be by the script)
