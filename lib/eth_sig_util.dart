library eth_sign_util;

import 'dart:typed_data';

import 'package:eth_sig_util/constant/typed_data_version.dart';
import 'package:eth_sig_util/util/signature.dart';
import 'package:eth_sig_util/util/signaturer1.dart';
import 'package:eth_sig_util/util/typed_data.dart';

export 'constant/typed_data_version.dart';
export 'util/abi.dart';
export 'util/signature.dart';
export 'util/typed_data.dart';

class EthSigUtil {
  /// Sign typed data, support all versions
  ///
  /// @param {String|Uint8List} private key - wallet's private key
  /// @param {String} jsonData - raw json of typed data
  /// @param {TypedDataVersion} version - typed data sign method version
  /// @returns {String} - signature
  static String signTypedData(
      {String? privateKey,
      Uint8List? privateKeyInBytes,
      required String jsonData,
      required TypedDataVersion version,
      bool useSecp256R1 = false}) {
    return useSecp256R1
        ? SignatureR1Util.sign(
            message:
                TypedDataUtil.hashMessage(jsonData: jsonData, version: version),
            privateKey: privateKey)
        : SignatureUtil.sign(
            message:
                TypedDataUtil.hashMessage(jsonData: jsonData, version: version),
            privateKey: privateKey);
  }

  /// Sign typed data, support all versions, this is sign personal message
  ///
  /// @param {String|Uint8List} private key - wallet's private key
  /// @param {String} jsonData - raw json of typed data
  /// @param {TypedDataVersion} version - typed data sign method version
  /// @returns {String} - signature
  static String signPersonalTypedData(
      {String? privateKey,
      Uint8List? privateKeyInBytes,
      required String jsonData,
      required TypedDataVersion version,
      bool useSecp256R1 = false}) {
    return useSecp256R1
        ? SignatureR1Util.signPersonalMessage(
            message:
                TypedDataUtil.hashMessage(jsonData: jsonData, version: version),
            privateKey: privateKey)
        : SignatureUtil.signPersonalMessage(
            message:
                TypedDataUtil.hashMessage(jsonData: jsonData, version: version),
            privateKey: privateKey);
  }

  /// Sign message
  ///
  /// @param {String|Uint8List} private key - wallet's private key
  /// @param {Uint8List} message - the message to sign
  /// @returns {String} - signature
  static String signMessage(
      {String? privateKey,
      Uint8List? privateKeyInBytes,
      required Uint8List message,
      bool useSecp256R1 = false}) {
    return useSecp256R1
        ? SignatureR1Util.sign(message: message, privateKey: privateKey)
        : SignatureUtil.sign(message: message, privateKey: privateKey);
  }

  /// Sign personal message, it's signMessage function but it's added prefix before
  ///
  /// @param {String|Uint8List} private key - wallet's private key
  /// @param {Uint8List} message - the message to sign
  /// @returns {String} - signature
  static String signPersonalMessage(
      {String? privateKey,
      Uint8List? privateKeyInBytes,
      required Uint8List message,
      bool useSecp256R1 = false}) {
    return useSecp256R1
        ? SignatureR1Util.signPersonalMessage(
            message: message, privateKey: privateKey)
        : SignatureUtil.signPersonalMessage(
            message: message, privateKey: privateKey);
  }

  /// Recover exactly sender address from signature and message
  ///
  /// @param {String} signature - the signature that was signed from the below message
  /// @param {Uint8List} message - the message of signature
  /// @returns {String} - wallet address which signed the above message to the above signature
  static String recoverSignature(
      {required String signature,
      required Uint8List message,
      bool useSecp256R1 = false}) {
    return useSecp256R1
        ? SignatureR1Util.ecRecover(
            signature: signature, message: message, isPersonalSign: false)
        : SignatureUtil.ecRecover(
            signature: signature, message: message, isPersonalSign: false);
  }

  /// Recover exactly sender address from personal signature and message
  ///
  /// @param {String} personal signature - the signature that was signed typed personal sign from the below message
  /// @param {Uint8List} message - the message of signature
  /// @returns {String} - wallet address which signed the above message to the above signature
  static String recoverPersonalSignature(
      {required String signature,
      required Uint8List message,
      bool useSecp256R1 = false}) {
    return useSecp256R1
        ? SignatureR1Util.ecRecover(
            signature: signature, message: message, isPersonalSign: true)
        : SignatureUtil.ecRecover(
            signature: signature, message: message, isPersonalSign: true);
  }
}
