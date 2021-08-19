import 'dart:convert' show jsonDecode, utf8;
import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:convert/convert.dart' show hex;

import 'bigint.dart';
import 'bytes.dart';
import 'keccak.dart';
import 'utils.dart' as utils;

class AbiUtil {
  static Uint8List rawEncode(List<String> types, values) {
    var output = BytesBuffer();
    var data = BytesBuffer();

    var headLength = 0;

    types.forEach((type) {
      if (isArray(type)) {
        var size = parseTypeArray(type);

        if (size != null && size is int) {
          headLength += 32 * size;
        } else {
          headLength += 32;
        }
      } else {
        headLength += 32;
      }
    });

    for (var i = 0; i < types.length; i++) {
      var type = elementaryName(types[i]);
      var value = values[i];
      var cur = encodeSingle(type, value);

      // Use the head/tail method for storing dynamic data
      if (isDynamic(type)) {
        output.add(encodeSingle('uint256', headLength));
        data.add(cur);
        headLength += cur.length;
      } else {
        output.add(cur);
      }
    }

    output.add(data.toBytes());
    return output.toBytes();
  }

  static Uint8List encodeSingle(String type, dynamic arg) {
    var size, i;

    if (type == 'address') {
      return encodeSingle('uint160', parseNumber(arg));
    } else if (type == 'bool') {
      int? val;
      if (arg is int) {
        val = arg == 0 ? 0 : 1;
      } else if (arg is bool) {
        val = arg ? 1 : 0;
      } else if (arg is String) {
        val = arg.isEmpty ? 0 : 1;
      }
      return encodeSingle('uint8', val);
    } else if (type == 'string') {
      return encodeSingle('bytes', utf8.encode(arg));
    } else if (isArray(type)) {
      // this part handles fixed-length ([2]) and variable length ([]) arrays
      // NOTE: we catch here all calls to arrays, that simplifies the rest
      if (!(arg is List)) {
        throw new ArgumentError('Not an array?');
      }
      size = parseTypeArray(type);
      if (size != 'dynamic' && size != 0 && arg.length > size) {
        throw new ArgumentError('Elements exceed array size: ${size}');
      }
      var ret = BytesBuffer();
      type = type.substring(0, type.lastIndexOf('['));
      if (arg is String) {
        arg = jsonDecode(arg as String);
      }

      if (size == 'dynamic') {
        var length = encodeSingle('uint256', arg.length);
        ret.add(length);
      }
      arg.forEach((v) {
        ret.add(encodeSingle(type, v));
      });
      return ret.toBytes();
    } else if (type == 'bytes') {
      arg = toBuffer(arg);

      var ret = BytesBuffer();
      ret.add(encodeSingle('uint256', arg.length));
      ret.add(arg);

      final remainArgLength = (arg as Uint8List).length % 32;
      if (remainArgLength != 0) {
        ret.add(zeros(32 - remainArgLength));
      }

      return ret.toBytes();
    } else if (type.startsWith('bytes')) {
      size = parseTypeN(type);
      if (size < 1 || size > 32) {
        throw new ArgumentError('Invalid bytes<N> width: ${size}');
      }

      return setLengthRight(toBuffer(arg), 32);
    } else if (type.startsWith('uint')) {
      size = parseTypeN(type);
      if ((size % 8 > 0) || (size < 8) || (size > 256)) {
        throw new ArgumentError('Invalid uint<N> width: ${size}');
      }

      var num = parseNumber(arg);
      if (num.bitLength > size) {
        throw new ArgumentError(
            'Supplied uint exceeds width: ${size} vs ${num.bitLength}');
      }

      if (num < BigInt.zero) {
        throw new ArgumentError('Supplied uint is negative');
      }

      return encodeBigInt(num, length: 32);
    } else if (type.startsWith('int')) {
      size = parseTypeN(type);
      if ((size % 8 != 0) || (size < 8) || (size > 256)) {
        throw new ArgumentError('Invalid int<N> width: ${size}');
      }

      var num = parseNumber(arg);
      if (num.bitLength > size) {
        throw new ArgumentError(
            'Supplied int exceeds width: ${size} vs ${num.bitLength}');
      }

      return encodeBigInt(num.toUnsigned(256), length: 32);
    } else if (type.startsWith('ufixed')) {
      size = parseTypeNxM(type);

      var num = parseNumber(arg);

      if (num < BigInt.zero) {
        throw new ArgumentError('Supplied ufixed is negative');
      }

      return encodeSingle('uint256', num * BigInt.two.pow(size[1]));
    } else if (type.startsWith('fixed')) {
      size = parseTypeNxM(type);

      return encodeSingle('int256', parseNumber(arg) * BigInt.two.pow(size[1]));
    }

    throw new ArgumentError('Unsupported or invalid type: ' + type);
  }

  static Uint8List soliditySHA3(List<String> types, values) {
    return keccak256(solidityPack(types, values));
  }

  static Uint8List solidityPack(List<String> types, values) {
    if (types.length != values.length) {
      throw new ArgumentError('Number of types are not matching the values');
    }
    var ret = BytesBuffer();
    for (var i = 0; i < types.length; i++) {
      var type = elementaryName(types[i]);
      var value = values[i];
      ret.add(solidityHexValue(type, value, null));
    }
    return ret.toBytes();
  }

  static Uint8List solidityHexValue(String type, value, bitsize) {
    // pass in bitsize = null if use default bitsize
    var size, num;
    if (isArray(type)) {
      var subType = type.replaceAll('/\[.*?\]/', '');
      if (!isArray(subType)) {
        var arraySize = parseTypeArray(type);
        if (arraySize != 'dynamic' &&
            arraySize != 0 &&
            value.length > arraySize) {
          throw new ArgumentError('Elements exceed array size: ' + arraySize);
        }
      }
      var ret = BytesBuffer();
      value?.forEach((v) {
        ret.add(solidityHexValue(subType, v, 256));
      });
      return ret.toBytes();
    } else if (type == 'bytes') {
      return value;
    } else if (type == 'string') {
      return Uint8List.fromList(utf8.encode(value));
    } else if (type == 'bool') {
      bitsize = bitsize != null ? 256 : 8;
      var padding = List.generate((bitsize) / 4, (index) => '').join('0');
      return Uint8List.fromList(
          hex.decode(value ? padding + '1' : padding + '0'));
    } else if (type == 'address') {
      var bytesize = 20;
      if (bitsize != null) {
        bytesize = bitsize ~/ 8;
      }
      return setLengthLeft(value, bytesize);
    } else if (type.startsWith('bytes')) {
      size = parseTypeN(type);
      if (size < 1 || size > 32) {
        throw new ArgumentError('Invalid bytes<N> width: ' + size);
      }

      return setLengthRight(value, size);
    } else if (type.startsWith('uint')) {
      size = parseTypeN(type);
      if ((size % 8 != 0) || (size < 8) || (size > 256)) {
        throw new ArgumentError('Invalid uint<N> width: ' + size);
      }

      num = parseNumber(value);
      if (num.bitLength > size) {
        throw new ArgumentError(
            'Supplied uint exceeds width: ' + size + ' vs ' + num.bitLength);
      }

      bitsize = bitsize != null ? 256 : size;
      return encodeBigInt(num, length: bitsize ~/ 8);
    } else if (type.startsWith('int')) {
      size = parseTypeN(type);
      if ((size % 8 != 0) || (size < 8) || (size > 256)) {
        throw new ArgumentError('Invalid int<N> width: ' + size);
      }

      num = parseNumber(value);
      if (num.bitLength > size) {
        throw new ArgumentError(
            'Supplied int exceeds width: ' + size + ' vs ' + num.bitLength);
      }

      bitsize = bitsize != null ? 256 : size;
      return encodeBigInt(num.toUnsigned(size), length: bitsize ~/ 8);
    } else {
      // FIXME: support all other types
      throw new ArgumentError('Unsupported or invalid type: ' + type);
    }
  }

  static String elementaryName(String name) {
    if (name.startsWith('int[')) {
      return 'int256' + name.substring(3);
    } else if (name == 'int') {
      return 'int256';
    } else if (name.startsWith('uint[')) {
      return 'uint256' + name.substring(4);
    } else if (name == 'uint') {
      return 'uint256';
    } else if (name.startsWith('fixed[')) {
      return 'fixed128x128' + name.substring(5);
    } else if (name == 'fixed') {
      return 'fixed128x128';
    } else if (name.startsWith('ufixed[')) {
      return 'ufixed128x128' + name.substring(6);
    } else if (name == 'ufixed') {
      return 'ufixed128x128';
    }
    return name;
  }

  /// Parse N from type<N>
  static int parseTypeN(String type) {
    return int.parse(RegExp(r'^\D+(\d+)$').firstMatch(type)?.group(1) ?? '1',
        radix: 10);
  }

  /// Parse N,M from type<N>x<M>
  static List<int> parseTypeNxM(String type) {
    var tmp = RegExp(r'^\D+(\d+)x(\d+)$').firstMatch(type);
    return [
      int.parse(tmp?.group(1) ?? '1', radix: 10),
      int.parse(tmp?.group(2) ?? '1', radix: 10)
    ];
  }

  /// Parse N in type[<N>] where "type" can itself be an array type.
  static dynamic parseTypeArray(String type) {
    var tmp = RegExp(r'(.*)\[(.*?)\]$').firstMatch(type);
    if (tmp != null) {
      return tmp.group(2) == ''
          ? 'dynamic'
          : int.parse(tmp.group(2)!, radix: 10);
    }
    return null;
  }

  static BigInt parseNumber(dynamic arg) {
    if (arg is String) {
      if (utils.isHexPrefixed(arg)) {
        return decodeBigInt(hex.decode(utils.stripHexPrefix(arg)));
      } else {
        return BigInt.parse(arg, radix: 10);
      }
    } else if (arg is int) {
      return BigInt.from(arg);
    } else if (arg is BigInt) {
      return arg;
    } else {
      throw new ArgumentError('Argument is not a number');
    }
  }

  static bool isArray(String type) {
    return type.lastIndexOf(']') == type.length - 1;
  }

  /// Is a type dynamic?
  static bool isDynamic(String type) {
    // FIXME: handle all types? I don't think anything is missing now
    return (type == 'string') ||
        (type == 'bytes') ||
        (parseTypeArray(type) == 'dynamic');
  }
}
