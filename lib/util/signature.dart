import 'dart:typed_data';

import 'package:collection/collection.dart' show ListEquality;
import 'package:convert/convert.dart';
import 'package:eth_sig_util/model/ecdsa_signature.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';

import 'bigint.dart';
import 'bytes.dart';
import 'keccak.dart';
import 'utils.dart';

final ECDomainParameters _params = ECCurve_secp256k1();
final BigInt _halfCurveOrder = _params.n ~/ BigInt.two;

class SignatureUtil {
  static String sign(
      {required Uint8List message, required String privateKey, int? chainId}) {
    final sig =
        signToSignature(message, hexToBytes(privateKey), chainId: chainId);
    return concatSig(toBuffer(sig.r), toBuffer(sig.s), toBuffer(sig.v));
  }

  static ECDSASignature signToSignature(Uint8List message, Uint8List privateKey,
      {int? chainId}) {
    final digest = SHA256Digest();
    final signer = ECDSASigner(null, HMac(digest, 64));
    final key = ECPrivateKey(decodeBigInt(privateKey), _params);

    signer.init(true, PrivateKeyParameter(key));
    var sig = signer.generateSignature(message) as ECSignature;

    /*
	This is necessary because if a message can be signed by (r, s), it can also
	be signed by (r, -s (mod N)) which N being the order of the elliptic function
	used. In order to ensure transactions can't be tampered with (even though it
	would be harmless), Ethereum only accepts the signature with the lower value
	of s to make the signature for the message unique.
	More details at
	https://github.com/web3j/web3j/blob/master/crypto/src/main/java/org/web3j/crypto/ECDSASignature.java#L27
	 */
    if (sig.s.compareTo(_halfCurveOrder) > 0) {
      final canonicalisedS = _params.n - sig.s;
      sig = ECSignature(sig.r, canonicalisedS);
    }

    // Now we have to work backwards to figure out the recId needed to recover the signature.
    //https://github.com/web3j/web3j/blob/master/crypto/src/main/java/org/web3j/crypto/Sign.java
    final publicKey = privateKeyToPublicKey(privateKey);
    int recoveryId = -1;
    for (var i = 0; i < 2; i++) {
      final k = _recoverPublicKeyFromSignature(i, sig.r, sig.s, message);
      if (ListEquality().equals(k, publicKey)) {
        recoveryId = i;
        break;
      }
    }

    if (recoveryId == -1) {
      throw Exception(
          'Could not construct a recoverable key. This should never happen');
    }

    return ECDSASignature(
      sig.r,
      sig.s,
      chainId != null ? recoveryId + (chainId * 2 + 35) : recoveryId + 27,
    );
  }

  static Uint8List publicKeyToAddress(Uint8List publicKey) {
    assert(publicKey.length == 64);
    final hashed = keccak256(publicKey);
    assert(hashed.length == 32);
    return hashed.sublist(12, 32);
  }

  /// Generates a public key for the given private key using the ecdsa curve which
  /// Ethereum uses.
  static Uint8List privateKeyToPublicKey(Uint8List privateKey) {
    final privateKeyNum = decodeBigInt(privateKey);
    final p = _params.G * privateKeyNum;

    //skip the type flag, https://github.com/ethereumjs/ethereumjs-util/blob/master/index.js#L319
    return Uint8List.view(p!.getEncoded(false).buffer, 1);
  }

  static Uint8List? _recoverPublicKeyFromSignature(
      int recId, BigInt r, BigInt s, Uint8List message) {
    final n = _params.n;
    final i = BigInt.from(recId ~/ 2);
    final x = r + (i * n);

    //Parameter q of curve
    final prime = BigInt.parse(
        'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
        radix: 16);
    if (x.compareTo(prime) >= 0) return null;

    final R = _decompressKey(x, (recId & 1) == 1, _params.curve);
    final ECPoint? ecPoint = R * n;
    if (ecPoint == null || !ecPoint.isInfinity) return null;

    final e = decodeBigInt(message);

    final eInv = (BigInt.zero - e) % n;
    final rInv = r.modInverse(n);
    final srInv = (rInv * s) % n;
    final eInvrInv = (rInv * eInv) % n;

    final preQ = (_params.G * eInvrInv);
    if (preQ == null) return null;
    final q = preQ + (R * srInv);

    final bytes = q?.getEncoded(false);
    return bytes?.sublist(1);
  }

  static ECPoint _decompressKey(BigInt xBN, bool yBit, ECCurve c) {
    List<int> x9IntegerToBytes(BigInt s, int qLength) {
      //https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/asn1/x9/X9IntegerConverter.java#L45
      final bytes = encodeBigInt(s);

      if (qLength < bytes.length) {
        return bytes.sublist(0, bytes.length - qLength);
      } else if (qLength > bytes.length) {
        final tmp = List<int>.filled(qLength, 0);

        final offset = qLength - bytes.length;
        for (var i = 0; i < bytes.length; i++) {
          tmp[i + offset] = bytes[i];
        }

        return tmp;
      }

      return bytes;
    }

    final compEnc = x9IntegerToBytes(xBN, 1 + ((c.fieldSize + 7) ~/ 8));
    compEnc[0] = yBit ? 0x03 : 0x02;
    return c.decodePoint(compEnc)!;
  }

  static String concatSig(Uint8List r, Uint8List s, Uint8List v) {
    var rSig = fromSigned(r);
    var sSig = fromSigned(s);
    var vSig = bufferToInt(v);
    var rStr = _padWithZeroes(hex.encode(toUnsigned(rSig)), 64);
    var sStr = _padWithZeroes(hex.encode(toUnsigned(sSig)), 64);
    var vStr = stripHexPrefix(intToHex(vSig));
    return addHexPrefix(rStr + sStr + vStr);
  }

  static String _padWithZeroes(String number, int length) {
    var myString = '' + number;
    while (myString.length < length) {
      myString = '0' + myString;
    }
    return myString;
  }

  static ECDSASignature fromRpcSig(String sig) {
    Uint8List buf = toBuffer(sig);

    // NOTE: with potential introduction of chainId this might need to be updated
    if (buf.length != 65) {
      throw ArgumentError('Invalid signature length');
    }

    var v = buf[64];
    // support both versions of `eth_sign` responses
    if (v < 27) {
      v += 27;
    }

    return ECDSASignature(
      decodeBigInt(Uint8List.view(buf.buffer, 0, 32)),
      decodeBigInt(Uint8List.view(buf.buffer, 32, 32)),
      v,
    );
  }

  static Uint8List? recoverPublicKeyFromSignature(
      ECDSASignature sig, Uint8List message,
      {int? chainId}) {
    int recoveryId = _calculateSigRecovery(sig.v, chainId: chainId);
    if (!_isValidSigRecovery(recoveryId)) {
      throw ArgumentError("invalid signature v value");
    }

    if (!isValidSignature(sig.r, sig.s, sig.v, chainId: chainId)) {
      throw ArgumentError("invalid signature");
    }

    return _recoverPublicKeyFromSignature(recoveryId, sig.r, sig.s, message);
  }

  static int _calculateSigRecovery(int v, {int? chainId}) {
    return chainId != null ? v - (2 * chainId + 35) : v - 27;
  }

  static bool _isValidSigRecovery(int recoveryId) {
    return recoveryId == 0 || recoveryId == 1;
  }

  static bool isValidSignature(BigInt r, BigInt s, int v,
      {bool homesteadOrLater = true, int? chainId}) {
    var SECP256K1_N_DIV_2 = decodeBigInt(hex.decode(
        '7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0'));
    var SECP256K1_N = decodeBigInt(hex.decode(
        'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'));

    if (encodeBigInt(r).length != 32 || encodeBigInt(s).length != 32) {
      return false;
    }

    if (!_isValidSigRecovery(_calculateSigRecovery(v, chainId: chainId))) {
      return false;
    }

    if (r == BigInt.zero ||
        r > SECP256K1_N ||
        s == BigInt.zero ||
        s > SECP256K1_N) {
      return false;
    }

    if (homesteadOrLater && s > SECP256K1_N_DIV_2) {
      return false;
    }

    return true;
  }
}
