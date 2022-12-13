import 'dart:convert';
import 'dart:io';

import 'package:eth_sig_util/eth_sig_util.dart';
import 'package:eth_sig_util/model/typed_data.dart';
import 'package:eth_sig_util/util/utils.dart';
import 'package:test/test.dart';

void main() {
  test('test encode tuple', () {
    final conditionTypes = [0, 1, 2];
    final conditions = [
      [
        0,
        '0x0000000000000000000000000000000000000000',
        BigInt.one.toSigned(256),
        BigInt.tryParse('100000000000000000')?.toSigned(256)
      ],
      [
        0,
        '0x0000000000000000000000000000000000000000',
        BigInt.one.toSigned(256),
        BigInt.tryParse('100000000000000000')?.toSigned(256)
      ],
      [
        0,
        '0x0000000000000000000000000000000000000000',
        BigInt.one.toSigned(256),
        BigInt.tryParse('100000000000000000')?.toSigned(256)
      ]
    ];
    final result = AbiUtil.rawEncode(
        ['uint8[]', 'tuple(uint8,address,uint256,uint256)[]'],
        [conditionTypes, conditions]);
    expect(bytesToHex(result),'');
  });
}
