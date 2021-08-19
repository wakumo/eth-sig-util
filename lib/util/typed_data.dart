import 'dart:convert';
import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:convert/convert.dart';
import 'package:eth_sig_util/eth_sig_util.dart';
import 'package:eth_sig_util/model/ecdsa_signature.dart';
import 'package:eth_sig_util/util/abi.dart';
import 'package:eth_sig_util/util/signature.dart';
import 'package:eth_sig_util/util/utils.dart';

import '../model/typed_data.dart';
import 'keccak.dart';

class TypedDataUtil {
  static Uint8List hashMessage(
      {required String jsonData,
      required TypedDataVersion version,
      int? chainId}) {
    late final rawTypedData;
    try {
      rawTypedData = jsonDecode(jsonData);
    } catch (_) {
      throw ArgumentError('jsonData format must be correct');
    }
    if (version == TypedDataVersion.V1) {
      late final List<EIP712TypedData> typedData;
      try {
        if (rawTypedData is List) {
          typedData =
              rawTypedData.map((e) => EIP712TypedData.fromJson(e)).toList();
        } else {
          typedData = [EIP712TypedData.fromJson(rawTypedData)];
        }
      } catch (_) {
        throw ArgumentError(
            'jsonData format is not corresponding to EIP712TypedData');
      }
      return TypedDataUtil.hashTypedDataV1(typedData);
    } else {
      late final typedData;
      try {
        typedData = TypedMessage.fromJson(rawTypedData);
      } catch (_) {
        throw ArgumentError(
            'jsonData format is not corresponding to TypedMessage');
      }
      return version == TypedDataVersion.V4
          ? TypedDataUtil.hashTypedDataV4(typedData)
          : TypedDataUtil.hashTypedDataV3(typedData);
    }
  }

  static Uint8List hashTypedDataV1(List<EIP712TypedData> typedData) {
    return typedSignatureHash(typedData);
  }

  static Uint8List hashTypedDataV3(TypedMessage typedData) {
    return hashTypedData(typedData, 'V3');
  }

  static Uint8List hashTypedDataV4(TypedMessage typedData) {
    return hashTypedData(typedData, 'V4');
  }

  static Uint8List? recoverPublicKey(
      dynamic data, String sig, TypedDataVersion version,
      {int? chainId}) {
    var sigParams = SignatureUtil.fromRpcSig(sig);
    var messageHash;
    switch (version) {
      case TypedDataVersion.V1:
        if (!(data is List<EIP712TypedData>)) {
          throw ArgumentError(
              'Recover public key version 1 required EIP712TypedData object');
        }
        messageHash = hashTypedDataV1(data);
        break;
      case TypedDataVersion.V3:
        if (!(data is TypedMessage)) {
          throw ArgumentError(
              'Recover public key version 3 required TypedMessage object');
        }
        messageHash = hashTypedDataV3(data);
        break;
      case TypedDataVersion.V4:
        if (!(data is TypedMessage)) {
          throw ArgumentError(
              'Recover public key version 4 required TypedMessage object');
        }
        messageHash = hashTypedDataV4(data);
        break;
    }
    return SignatureUtil.recoverPublicKeyFromSignature(
        ECDSASignature(sigParams.r, sigParams.s, sigParams.v), messageHash,
        chainId: chainId);
  }

  static Uint8List hashTypedData(TypedMessage typedData, String version) {
    var parts = BytesBuffer();
    parts.add(hex.decode('1901'));
    parts.add(
        hashStruct('EIP712Domain', typedData.domain, typedData.types, version));
    if (typedData.primaryType != 'EIP712Domain') {
      parts.add(hashStruct(
          typedData.primaryType, typedData.message, typedData.types, version));
    }
    return keccak256(parts.toBytes());
  }

  static Uint8List hashStruct(String primaryType, dynamic data,
      Map<String, List<TypedDataField>> types, String version) {
    return keccak256(encodeData(primaryType, data, types, version));
  }

  /// Hashes the type of an object
  static Uint8List hashType(String primaryType, dynamic types) {
    return keccak256(
        Uint8List.fromList(utf8.encode(encodeType(primaryType, types))));
  }

  static Uint8List encodeData(String primaryType, dynamic data,
      Map<String, List<TypedDataField>> types, String version) {
    if (!(data is Map<String, dynamic>) && !(data is EIP712Domain)) {
      throw ArgumentError("Unsupported data type");
    }

    final encodedTypes = <String>['bytes32'];
    List<dynamic> encodedValues = [];
    encodedValues.add(hashType(primaryType, types));

    if (version == 'V4') {
      List<dynamic> encodeField(String name, String type, dynamic value) {
        if (types[type] != null) {
          return [
            'bytes32',
            value == null // eslint-disable-line no-eq-null
                ? '0x0000000000000000000000000000000000000000000000000000000000000000'
                : keccak256((encodeData(type, value, types, version))),
          ];
        }

        if (value == null) {
          throw ArgumentError(
              'missing value for field ${name} of type ${type}');
        }

        if (type == 'bytes') {
          return ['bytes32', keccak256(value)];
        }

        if (type == 'string') {
          // convert string to buffer - prevents ethUtil from interpreting strings like '0xabcd' as hex
          if (value is String) {
            value = Uint8List.fromList(utf8.encode(value));
          }
          return ['bytes32', keccak256(value)];
        }

        if (type.lastIndexOf(']') == type.length - 1) {
          final parsedType = type.substring(0, type.lastIndexOf('['));
          final typeValuePairs = value
              .map(
                (item) => encodeField(name, parsedType, item),
              )
              .toList();

          final List<String> tList =
              (typeValuePairs as List).map((l) => l[0].toString()).toList();
          final List<dynamic> vList = typeValuePairs.map((l) => l[1]).toList();
          return [
            'bytes32',
            keccak256(
              AbiUtil.rawEncode(
                tList,
                vList,
              ),
            ),
          ];
        }

        return [type, value];
      }

      final fields = types[primaryType];
      fields?.forEach((field) {
        final List<dynamic> result = encodeField(
          field.name,
          field.type,
          data[field.name],
        );
        encodedTypes.add(result[0]);
        encodedValues.add(result[1]);
      });
    } else {
      types[primaryType]?.forEach((TypedDataField field) {
        var value = data[field.name];
        if (value != null) {
          if (field.type == 'bytes') {
            encodedTypes.add('bytes32');
            if (value is String) {
              if (isHexPrefixed(value)) {
                value = keccak256(hexToBytes(value));
              } else {
                value = keccak256(Uint8List.fromList(utf8.encode(value)));
              }
            }
            encodedValues.add(value);
          } else if (field.type == 'string') {
            encodedTypes.add('bytes32');
            // convert string to buffer - prevents ethUtil from interpreting strings like '0xabcd' as hex
            if (value is String) {
              value = Uint8List.fromList(utf8.encode(value));
            }
            value = keccak256(value);
            encodedValues.add(value);
          } else if (types[field.type] != null) {
            encodedTypes.add('bytes32');
            value = keccak256(encodeData(field.type, value, types, version));
            encodedValues.add(value);
          } else if (field.type.lastIndexOf(']') == field.type.length - 1) {
            throw new ArgumentError(
                'Arrays are unimplemented in encodeData; use V4 extension');
          } else {
            encodedTypes.add(field.type);
            encodedValues.add(value);
          }
        }
      });
    }

    return AbiUtil.rawEncode(encodedTypes, encodedValues);
  }

  /// Encodes the type of an object by encoding a comma delimited list of its members
  static String encodeType(
      String primaryType, Map<String, List<TypedDataField>> types) {
    var result = '';
    var deps = findTypeDependencies(primaryType, types);
    deps = deps.where((dep) => dep != primaryType).toList();
    deps.sort();
    deps.insert(0, primaryType);
    deps.forEach((dep) {
      if (!types.containsKey(dep)) {
        throw new ArgumentError('No type definition specified: ' + dep);
      }
      result += dep +
          '(' +
          types[dep]!.map((field) => field.type + ' ' + field.name).join(',') +
          ')';
    });
    return result;
  }

  /// Finds all types within a type defintion object
  ///
  /// @param {string} primaryType - Root type
  /// @param {Object} types - Type definitions
  /// @param {Array} results - current set of accumulated types
  /// @returns {Array} - Set of all types found in the type definition
  static List<String> findTypeDependencies(
      String primaryType, Map<String, List<TypedDataField>> types,
      {List<String>? results}) {
    if (results == null) {
      results = [];
    }
    if (results.contains(primaryType) || !types.containsKey(primaryType)) {
      return results;
    }
    results.add(primaryType);
    types[primaryType]?.forEach((TypedDataField field) {
      findTypeDependencies(field.type, types, results: results).forEach((dep) {
        if (!results!.contains(dep)) {
          results.add(dep);
        }
      });
    });
    return results;
  }

  static Uint8List typedSignatureHash(List<EIP712TypedData> typedData) {
    final data = typedData.map((e) {
      if (e.type == 'bytes') {
        if (isHexPrefixed(e.value)) {
          return hexToBytes(e.value);
        } else {
          return Uint8List.fromList(utf8.encode(e.value));
        }
      }
      return e.value;
    }).toList();
    final types = typedData.map((e) {
      return e.type;
    }).toList();
    final schema = typedData.map((e) {
      return '${e.type} ${e.name}';
    }).toList();

    return AbiUtil.soliditySHA3(
      ['bytes32', 'bytes32'],
      [
        AbiUtil.soliditySHA3(
            List.generate(typedData.length, (index) => 'string'), schema),
        AbiUtil.soliditySHA3(types, data),
      ],
    );
  }
}
