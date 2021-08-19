import 'dart:convert' show utf8;
import 'dart:typed_data';

import 'package:convert/convert.dart' show hex;

bool isHexPrefixed(String str) {
  return str.substring(0, 2) == '0x';
}

Uint8List hexToBytes(String hexStr) {
  final bytes = hex.decode(stripHexPrefix(hexStr));
  if (bytes is Uint8List) return bytes;
  return Uint8List.fromList(bytes);
}

String bytesToHex(List<int> bytes,
    {bool include0x = false,
      int? forcePadLength,
      bool padToEvenLength = false}) {
  var encoded = hex.encode(bytes);

  if (forcePadLength != null) {
    assert(forcePadLength >= encoded.length);

    final padding = forcePadLength - encoded.length;
    encoded = ('0' * padding) + encoded;
  }

  if (padToEvenLength && encoded.length % 2 != 0) {
    encoded = '0$encoded';
  }

  return (include0x ? '0x' : '') + encoded;
}

String stripHexPrefix(String str) {
  return isHexPrefixed(str) ? str.substring(2) : str;
}

/// Pads a [String] to have an even length
String padToEven(String value) {
  var a = "${value}";

  if (a.length % 2 == 1) {
    a = "0${a}";
  }

  return a;
}

/// Converts a [int] into a hex [String]
String intToHex(int i) {
  return "0x${i.toRadixString(16)}";
}

/// Converts an [int] to a [Uint8List]
Uint8List intToBuffer(int i) {
  return Uint8List.fromList(hex.decode(padToEven(intToHex(i).substring(2))));
}

/// Get the binary size of a string
int getBinarySize(String str) {
  return utf8.encode(str).length;
}

/// Returns TRUE if the first specified array contains all elements
/// from the second one. FALSE otherwise.
bool arrayContainsArray(List superset, List subset, {bool some: false}) {
  if (some) {
    return Set.from(superset).intersection(Set.from(subset)).length > 0;
  } else {
    return Set.from(superset).containsAll(subset);
  }
}

/// Should be called to get utf8 from it's hex representation
String toUtf8(String hexString) {
  var bufferValue = hex.decode(
      padToEven(stripHexPrefix(hexString).replaceAll(RegExp('^0+|0+\$'), '')));

  return utf8.decode(bufferValue);
}

/// Should be called to get ascii from it's hex representation
String toAscii(String hexString) {
  var start = hexString.startsWith(RegExp('^0x')) ? 2 : 0;
  return String.fromCharCodes(hex.decode(hexString.substring(start)));
}

/// Should be called to get hex representation (prefixed by 0x) of utf8 string
String fromUtf8(String stringValue) {
  var stringBuffer = utf8.encode(stringValue);

  return "0x${padToEven(hex.encode(stringBuffer)).replaceAll(RegExp('^0+|0+\$'), '')}";
}

/// Should be called to get hex representation (prefixed by 0x) of ascii string
String fromAscii(String stringValue) {
  var hexString = ''; // eslint-disable-line
  for (var i = 0; i < stringValue.length; i++) {
    // eslint-disable-line
    var code = stringValue.codeUnitAt(i);
    var n = hex.encode([code]);
    hexString += n.length < 2 ? "0$n" : n;
  }

  return "0x$hexString";
}

/// Is the string a hex string.
bool isHexString(String value, {int length = 0}) {
  if (!RegExp('^0x[0-9A-Fa-f]*\$').hasMatch(value)) {
    return false;
  }

  if (length > 0 && value.length != 2 + 2 * length) {
    return false;
  }

  return true;
}
