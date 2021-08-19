library eth_sign_util;

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
}
