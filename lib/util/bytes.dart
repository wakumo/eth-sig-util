import "dart:convert" show utf8, jsonEncode;
import "dart:typed_data";

import 'package:convert/convert.dart' show hex;

import './utils.dart' as utils;
import 'bigint.dart';

/// Returns a buffer filled with 0s.
Uint8List zeros(int bytes) {
  var buffer = Uint8List(bytes);
  buffer.fillRange(0, bytes, 0);
  return buffer;
}

/// Left Pads an [Uint8List] with leading zeros till it has [length] bytes.
/// Or it truncates the beginning if it exceeds.
Uint8List setLengthLeft(Uint8List msg, int length, {bool right = false}) {
  var buf = zeros(length);
  msg = toBuffer(msg);
  if (right) {
    if (msg.length < length) {
      buf.setAll(0, msg);
      return buf;
    }
    return msg.sublist(0, length);
  } else {
    if (msg.length < length) {
      buf.setAll(length - msg.length, msg);
      return buf;
    }
    return msg.sublist(msg.length - length);
  }
}

Uint8List setLength(Uint8List msg, int length, {bool right = false}) {
  return setLengthLeft(msg, length, right: right);
}

/// Right Pads an [Uint8List] with leading zeros till it has [length] bytes.
/// Or it truncates the beginning if it exceeds.
Uint8List setLengthRight(Uint8List msg, int length) {
  return setLength(msg, length, right: true);
}

/// Trims leading zeros from a [Uint8List].
Uint8List unpad(Uint8List a) {
  for (int i = 0; i < a.length; i++) {
    if (a[i] != 0) {
      return a.sublist(i);
    }
  }
  return Uint8List(0);
}

Uint8List stripZeros(Uint8List a) {
  return unpad(a);
}

String unpadString(String a) {
  a = utils.stripHexPrefix(a);
  for (int i = 0; i < a.length; i++) {
    if (a[i] != '0') {
      return a.substring(i);
    }
  }
  return '';
}

/// Attempts to turn a value into a [Uint8List]. As input it supports [Uint8List], [String], [int], [null], [BigInt] method.
Uint8List toBuffer(v) {
  if (!(v is Uint8List)) {
    if (v is List<int>) {
      v = Uint8List.fromList(v);
    } else if (v is String) {
      if (utils.isHexString(v)) {
        v = Uint8List.fromList(
            hex.decode(utils.padToEven(utils.stripHexPrefix(v))));
      } else {
        v = Uint8List.fromList(utf8.encode(v));
      }
    } else if (v is int) {
      v = utils.intToBuffer(v);
    } else if (v == null) {
      v = Uint8List(0);
    } else if (v is BigInt) {
      v = Uint8List.fromList(encodeBigInt(v));
    } else {
      throw 'invalid type';
    }
  }

  return v;
}

/// Converts a [Uint8List] to a [int].
int bufferToInt(Uint8List buf) {
  return decodeBigInt(toBuffer(buf)).toInt();
}

/// Converts a [Uint8List] into a hex [String].
String bufferToHex(Uint8List buf) {
  return '0x' + hex.encode(buf);
}

/// Interprets a [Uint8List] as a signed integer and returns a [BigInt]. Assumes 256-bit numbers.
BigInt fromSigned(Uint8List signedInt) {
  return decodeBigInt(signedInt).toSigned(256);
}

/// Converts a [BigInt] to an unsigned integer and returns it as a [Uint8List]. Assumes 256-bit numbers.
Uint8List toUnsigned(BigInt unsignedInt) {
  return encodeBigInt(unsignedInt.toUnsigned(256));
}

/// Adds "0x" to a given [String] if it does not already start with "0x".
String addHexPrefix(String str) {
  return utils.isHexPrefixed(str) ? str : '0x' + str;
}

/// Converts a [Uint8List] or [List<Uint8List>] to JSON.
baToJSON(ba) {
  return jsonEncode(_baToJSON(ba));
}

_baToJSON(ba) {
  if (ba is Uint8List) {
    return "0x${hex.encode(ba)}";
  } else if (ba is List) {
    var result = [];
    ba.forEach((x) => result.add(_baToJSON(x)));
    return result;
  }
}
