import 'package:eth_sig_util/model/typed_data.dart';
import 'package:eth_sig_util/util/bytes.dart';
import 'package:eth_sig_util/util/typed_data.dart';
import 'package:test/test.dart';

void main() {
  test('unbound sign typed data utility functions', () {
    final Map<String, dynamic> rawTypedData = {
      "types": {
        "EIP712Domain": [
          {"name": "name", "type": "string"},
          {"name": "version", "type": "string"},
          {"name": "chainId", "type": "uint256"},
          {"name": "verifyingContract", "type": "address"}
        ],
        "Person": [
          {"name": "name", "type": "string"},
          {"name": "mother", "type": "Person"},
          {"name": "father", "type": "Person"}
        ]
      },
      "domain": {
        "name": "Family Tree",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
      },
      "primaryType": "Person",
      "message": {
        "name": "Jon",
        "mother": {
          "name": "Lyanna",
          "father": {"name": "Rickard"}
        },
        "father": {
          "name": "Rhaegar",
          "father": {"name": "Aeris II"}
        }
      }
    };

    final typedData = TypedMessage.fromJson(rawTypedData);
    expect(TypedDataUtil.encodeType('Person', typedData.types),
        'Person(string name,Person mother,Person father)');
    expect(bufferToHex(TypedDataUtil.hashType('Person', typedData.types)),
        '0x7c5c8e90cb92c8da53b893b24962513be98afcf1b57b00327ae4cc14e3a64116');
    expect(
        bufferToHex(
          TypedDataUtil.encodeData(
              'Person', typedData.message['mother'], typedData.types, 'V4'),
        ),
        '0x${[
          '7c5c8e90cb92c8da53b893b24962513be98afcf1b57b00327ae4cc14e3a64116',
          'afe4142a2b3e7b0503b44951e6030e0e2c5000ef83c61857e2e6003e7aef8570',
          '0000000000000000000000000000000000000000000000000000000000000000',
          '88f14be0dd46a8ec608ccbff6d3923a8b4e95cdfc9648f0db6d92a99a264cb36',
        ].join('')}');
    expect(
        bufferToHex(
          TypedDataUtil.hashStruct(
              'Person', typedData.message['mother'], typedData.types, 'V4'),
        ),
        '0x9ebcfbf94f349de50bcb1e3aa4f1eb38824457c99914fefda27dcf9f99f6178b');
    expect(
        bufferToHex(
          TypedDataUtil.encodeData(
              'Person', typedData.message['father'], typedData.types, 'V4'),
        ),
        '0x${[
          '7c5c8e90cb92c8da53b893b24962513be98afcf1b57b00327ae4cc14e3a64116',
          'b2a7c7faba769181e578a391a6a6811a3e84080c6a3770a0bf8a856dfa79d333',
          '0000000000000000000000000000000000000000000000000000000000000000',
          '02cc7460f2c9ff107904cff671ec6fee57ba3dd7decf999fe9fe056f3fd4d56e',
        ].join('')}');
    expect(
        bufferToHex(
          TypedDataUtil.hashStruct(
              'Person', typedData.message['father'], typedData.types, 'V4'),
        ),
        '0xb852e5abfeff916a30cb940c4e24c43cfb5aeb0fa8318bdb10dd2ed15c8c70d8');
    expect(
        bufferToHex(
          TypedDataUtil.encodeData(
            typedData.primaryType,
            typedData.message,
            typedData.types,
            'V4',
          ),
        ),
        '0x${[
          '7c5c8e90cb92c8da53b893b24962513be98afcf1b57b00327ae4cc14e3a64116',
          'e8d55aa98b6b411f04dbcf9b23f29247bb0e335a6bc5368220032fdcb9e5927f',
          '9ebcfbf94f349de50bcb1e3aa4f1eb38824457c99914fefda27dcf9f99f6178b',
          'b852e5abfeff916a30cb940c4e24c43cfb5aeb0fa8318bdb10dd2ed15c8c70d8',
        ].join('')}');
    expect(
        bufferToHex(
          TypedDataUtil.hashStruct(
            typedData.primaryType,
            typedData.message,
            typedData.types,
            'V4',
          ),
        ),
        '0xfdc7b6d35bbd81f7fa78708604f57569a10edff2ca329c8011373f0667821a45');
    expect(
        bufferToHex(
          TypedDataUtil.hashStruct(
              'EIP712Domain', typedData.domain, typedData.types, 'V4'),
        ),
        '0xfacb2c1888f63a780c84c216bd9a81b516fc501a19bae1fc81d82df590bbdc60');
    expect(bufferToHex(TypedDataUtil.hashTypedDataV4(typedData)),
        '0x807773b9faa9879d4971b43856c4d60c2da15c6f8c062bd9d33afefb756de19c');
  });
}
