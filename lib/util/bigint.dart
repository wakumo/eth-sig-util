import 'dart:math';
import 'dart:typed_data';

final BigInt _byteMask = new BigInt.from(0xff);

BigInt decodeBigInt(List<int> bytes) {
  BigInt result = new BigInt.from(0);
  for (int i = 0; i < bytes.length; i++) {
    result += new BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
  }
  return result;
}

Uint8List encodeBigInt(BigInt input,
    {Endian endian = Endian.be, int length = 0}) {
  int byteLength = (input.bitLength + 7) >> 3;
  int reqLength = length > 0 ? length : max(1, byteLength);
  assert(byteLength <= reqLength, 'byte array longer than desired length');
  assert(reqLength > 0, 'Requested array length <= 0');

  var res = Uint8List(reqLength);
  res.fillRange(0, reqLength - byteLength, 0);

  var q = input;
  if (endian == Endian.be) {
    for (int i = 0; i < byteLength; i++) {
      res[reqLength - i - 1] = (q & _byteMask).toInt();
      q = q >> 8;
    }
    return res;
  } else {
    // FIXME: le
    throw UnimplementedError('little-endian is not supported');
  }
}

enum Endian {
  be,
  // FIXME: le
}
