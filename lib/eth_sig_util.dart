library eth_sign_util;

import 'dart:typed_data';

import 'package:eth_sig_util/constant/typed_data_version.dart';
import 'package:eth_sig_util/util/signature.dart';
import 'package:eth_sig_util/util/typed_data.dart';

export 'constant/typed_data_version.dart';
export 'util/abi.dart';
export 'util/signature.dart';
export 'util/typed_data.dart';

class EthSigUtil {
  /// Sign typed data, support all versions
  ///
  /// @param {String} private key - wallet's private key
  /// @param {String} jsonData - raw json of typed data
  /// @param {TypedDataVersion} version - typed data sign method version
  /// @returns {String} - signature
  static String signTypedData(
      {required String privateKey,
      required String jsonData,
      required TypedDataVersion version,
      int? chainId}) {
    return SignatureUtil.sign(
        message:
            TypedDataUtil.hashMessage(jsonData: jsonData, version: version),
        privateKey: privateKey,
        chainId: chainId);
  }

  /// Sign personal message, it's signMessage function but it's added prefix before
  ///
  /// @param {String} private key - wallet's private key
  /// @param {Uint8List} message - the message to sign
  /// @returns {String} - signature
  static String signPersonalMessage(
      {required String privateKey, required Uint8List message, int? chainId}) {
    return SignatureUtil.signPersonalMessage(
        message: message, privateKey: privateKey, chainId: chainId);
  }

  /// Sign message
  ///
  /// @param {String} private key - wallet's private key
  /// @param {Uint8List} message - the message to sign
  /// @returns {String} - signature
  static String signMessage(
      {required String privateKey, required Uint8List message, int? chainId}) {
    return SignatureUtil.sign(
        message: message, privateKey: privateKey, chainId: chainId);
  }

  /// Recover exactly sender address from signature and message
  ///
  /// @param {String} signature - the signature that was signed from the below message
  /// @param {Uint8List} message - the message of signature
  /// @returns {String} - wallet address which signed the above message to the above signature
  static String ecRecover(
      {required String signature, required Uint8List message}) {
    return SignatureUtil.ecRecover(signature: signature, message: message);
  }
}
