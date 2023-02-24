import 'dart:math';
import 'dart:typed_data';
import 'dart:convert';
import 'dart:io';

import 'package:convert/convert.dart';
import 'package:elliptic/elliptic.dart';
import 'package:pointycastle/export.dart';
import 'package:basic_utils/src/library/crypto/pss_signer.dart';
import 'package:pointycastle/asn1/object_identifiers.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/src/utils.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as ecc_fp;
import 'package:basic_utils/basic_utils.dart' as b;
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';


void main() async {
  final keyParams = ECKeyGeneratorParameters(ECCurve_prime256v1());

  var secureRandom = getSecureRandom();

  var rngParams = ParametersWithRandom(keyParams, secureRandom);
  var generator = ECKeyGenerator();
  generator.init(rngParams);

  var keyPair = generator.generateKeyPair();
  var publicKey = keyPair.publicKey as ECPublicKey;
  var privateKey = keyPair.privateKey as ECPrivateKey;

  var message = 'Hello World';
  var messageBytes = Uint8List.fromList(message.codeUnits);
  

  var signer = Signer('SHA-256/ECDSA');
  var a = encodePrivateKeyToPem(privateKey);
  var c = encodePublicKeyToPem(publicKey);

// var a = b.CryptoUtils.encodeEcPrivateKeyToPem(privateKey);
// var c = b.CryptoUtils.encodeEcPublicKeyToPem(publicKey);

 await File('privateKeynew.pem').writeAsString(a);
  await File('publicKeynew.pem').writeAsString(c);

 var a_decoded = b.CryptoUtils.ecPrivateKeyFromPem(a);
 var c_decoded = b.CryptoUtils.ecPublicKeyFromPem(c);
signer.init(true, ParametersWithRandom(
    PrivateKeyParameter<ECPrivateKey>(ECPrivateKey(privateKey.d, ECCurve_prime256v1())),secureRandom
  ));

 var signature = signer.generateSignature(messageBytes);
 
 var verifier = Signer('SHA-256/ECDSA');
 verifier.init(false, PublicKeyParameter<ECPublicKey>(c_decoded));
 var verified = verifier.verifySignature(messageBytes, signature);

 var sig = signature as ECSignature;
 var sig_r = sig.r;
  var sig_s = sig.s;
  var  sig_big_int = sig_r+sig_s;
  final byteList = bigIntToBytes(sig_big_int);

  await File('signature.txt').writeAsString(byteList.toString());
  var sighex = b.CryptoUtils.ecSignatureToBase64(sig);
  

//  print(returnECSignatureToHex(sig));

}



Uint8List i2osp(BigInt number,
      {int? outLen, Endian endian = Endian.big}) {

        final byteMask = BigInt.from(0xff);
    var size = (number.bitLength + 7) >> 3;
    if (outLen == null) {
      outLen = size;
    } else if (outLen < size) {
      throw Exception('Number too large');
    }
    final result = Uint8List(outLen);
    var pos = endian == Endian.big ? outLen - 1 : 0;
    for (var i = 0; i < size; i++) {
      result[pos] = (number & byteMask).toInt();
      if (endian == Endian.big) {
        pos -= 1;
      } else {
        pos += 1;
      }
      number = number >> 8;
    }
    return result;
  }

 String encodePrivateKeyToPem(ECPrivateKey ecPrivateKey) {
  const BEGIN_EC_PRIVATE_KEY = '-----BEGIN ENCRYPTED PRIVATE KEY-----';
  const END_EC_PRIVATE_KEY = '-----END ENCRYPTED PRIVATE KEY-----';
    var outer = ASN1Sequence();

    var version = ASN1Integer(BigInt.zero);
    var privateKeyAsBytes = i2osp(ecPrivateKey.d!);
    var privateKey = ASN1OctetString(octets: privateKeyAsBytes);
    var choice = ASN1Sequence(tag: 0x30);

    choice.add(
        ASN1ObjectIdentifier.fromName('prime256v1'));

    var publicKey = ASN1Sequence(tag: 0x31);
    var q = ecPrivateKey.parameters!.G * ecPrivateKey.d!;
    var encodedBytes = q!.getEncoded(false);
    var subjectPublicKey = ASN1BitString(stringValues: encodedBytes);
    publicKey.add(subjectPublicKey);

    outer.add(version);
    outer.add(privateKey);
    outer.add(choice);
    outer.add(publicKey);
    var dataBase64 = base64.encode(outer.encode());
    var chunks = b.StringUtils.chunk(dataBase64, 64);

    return '$BEGIN_EC_PRIVATE_KEY\n${chunks.join('\n')}\n$END_EC_PRIVATE_KEY';
  }



String encodePublicKeyToPem(ECPublicKey publicKey){
  const BEGIN_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----';
  const END_PUBLIC_KEY = '-----END PUBLIC KEY-----';

  var outer = ASN1Sequence();
  var algorithm = ASN1Sequence();
  algorithm.add(ASN1ObjectIdentifier.fromName('ecPublicKey'));
  algorithm.add(ASN1ObjectIdentifier.fromName('prime256v1'));
  var encodedBytes = publicKey.Q!.getEncoded(false);
  var subjectPublicKey = ASN1BitString(stringValues: encodedBytes);
  outer.add(algorithm);
  outer.add(subjectPublicKey);
  var dataBase64 = base64.encode(outer.encode());
  var chunks = b.StringUtils.chunk(dataBase64, 64);
  return '$BEGIN_PUBLIC_KEY\n${chunks.join('\n')}\n$END_PUBLIC_KEY';

}

Uint8List bigIntToBytes(BigInt bigInt) {
  final byteCount = (bigInt.bitLength + 7) ~/ 8; // round up to nearest byte
  final bytes = Uint8List(byteCount);
  for (var i = 0; i < byteCount; i++) {
    bytes[i] = bigInt.toUnsigned(8).toInt();
    bigInt = bigInt >> 8;
  }
  return bytes;
}




 SecureRandom getSecureRandom() {
    var secureRandom = FortunaRandom();
    var random = Random.secure();
    var seeds = <int>[];
    for (var i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }




String encodeBigInt(BigInt number) {
  final bytes = number.toRadixString(16).padLeft(64, '0').hexToBytes();
  return base64UrlEncode(bytes);
}

BigInt decodeBigInt(List<int> bytes) {
  final hex = bytes.map((e) => e.toRadixString(16).padLeft(2, '0')).join();
  return BigInt.parse(hex, radix: 16);
}

String encodePoint(ECPoint point) {
  final x = encodeBigInt(point.x!.toBigInteger()!);
  final y = encodeBigInt(point.y!.toBigInteger()!);
  return '$x$y';
}

extension HexConversion on String {
  Uint8List hexToBytes() {
    final len = length ~/ 2;
    final result = Uint8List(len);
    for (var i = 0; i < len; i++) {
      final sub = substring(i * 2, i * 2 + 2);
      result[i] = int.parse(sub, radix: 16);
    }
    return result;
  }
}

ECPoint decodePoint(String xy) {
  final x = decodeBigInt(base64Url.decode(xy.substring(0, 44)));
  final y = decodeBigInt(base64Url.decode(xy.substring(44)));
  return ECCurve_secp256k1().curve.decodePoint(Uint8List.fromList('$x$y'.hexToBytes()))!;
}
