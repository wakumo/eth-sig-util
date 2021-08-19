import 'dart:convert';
import 'dart:typed_data';

import 'package:eth_sig_util/eth_sig_util.dart';
import 'package:eth_sig_util/model/typed_data.dart';
import 'package:eth_sig_util/util/bytes.dart';
import 'package:eth_sig_util/util/keccak.dart';
import 'package:eth_sig_util/util/signature.dart';
import 'package:eth_sig_util/util/typed_data.dart';
import 'package:eth_sig_util/util/utils.dart';
import 'package:test/test.dart';

void main() {
  test('signTypedData and recoverTypedSignature V1 - single messages', () {
    final List<Map<String, dynamic>> rawTypedData = [
      {"type": "string", "name": "message", "value": "Hi, Alice!"}
    ];
    final jsonData = jsonEncode(rawTypedData);

    const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b';
    const privKeyHex =
        '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0';

    final signature = EthSigUtil.signTypedData(
        privateKey: privKeyHex,
        jsonData: jsonData,
        version: TypedDataVersion.V1);

    expect(signature,
        '0x49e75d475d767de7fcc67f521e0d86590723d872e6111e51c393e8c1e2f21d032dfaf5833af158915f035db6af4f37bf2d5d29781cd81f28a44c5cb4b9d241531b');

    final typedData =
        rawTypedData.map((e) => EIP712TypedData.fromJson(e)).toList();
    final recovered = TypedDataUtil.recoverPublicKey(
        typedData, signature, TypedDataVersion.V1);

    expect(address, bufferToHex(SignatureUtil.publicKeyToAddress(recovered!)));
  });
  //////////////////////////////////////////////////////////////////////////////
  test('signTypedData and recoverTypedSignature V1 - multiple messages', () {
    final List<Map<String, dynamic>> rawTypedData = [
      {"type": "string", "name": "message", "value": "Hi, Alice!"},
      {"type": "uint8", "name": "value", "value": 10}
    ];
    final jsonData = jsonEncode(rawTypedData);

    const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b';
    const privKeyHex =
        '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0';

    final signature = EthSigUtil.signTypedData(
        privateKey: privKeyHex,
        jsonData: jsonData,
        version: TypedDataVersion.V1);

    final typedData =
        rawTypedData.map((e) => EIP712TypedData.fromJson(e)).toList();
    final recovered = TypedDataUtil.recoverPublicKey(
        typedData, signature, TypedDataVersion.V1);

    expect(address, bufferToHex(SignatureUtil.publicKeyToAddress(recovered!)));
  });
  //////////////////////////////////////////////////////////////////////////////
  test('typedSignatureHash - single value', () {
    final rawTypedData = [
      {"type": "string", "name": "message", "value": "Hi, Alice!"}
    ];
    final typedData =
        rawTypedData.map((e) => EIP712TypedData.fromJson(e)).toList();
    final hash = TypedDataUtil.typedSignatureHash(typedData);
    expect(bufferToHex(hash),
        '0x14b9f24872e28cc49e72dc104d7380d8e0ba84a3fe2e712704bcac66a5702bd5');
  });
  //////////////////////////////////////////////////////////////////////////////
  test('typedSignatureHash - multiple values', () {
    final rawTypedData = [
      {"type": "string", "name": "message", "value": "Hi, Alice!"},
      {"type": "uint8", "name": "value", "value": 10}
    ];
    final typedData =
        rawTypedData.map((e) => EIP712TypedData.fromJson(e)).toList();
    final hash = TypedDataUtil.typedSignatureHash(typedData);
    expect(bufferToHex(hash),
        '0xf7ad23226db5c1c00ca0ca1468fd49c8f8bbc1489bc1c382de5adc557a69c229');
  });
  //////////////////////////////////////////////////////////////////////////////
  test('typedSignatureHash - bytes', () {
    final rawTypedData = [
      {"type": "bytes", "name": "message", "value": "0xdeadbeaf"}
    ];
    final typedData =
        rawTypedData.map((e) => EIP712TypedData.fromJson(e)).toList();
    final hash = TypedDataUtil.typedSignatureHash(typedData);
    expect(bufferToHex(hash),
        '0x6c69d03412450b174def7d1e48b3bcbbbd8f51df2e76e2c5b3a5d951125be3a9');
  });
  //////////////////////////////////////////////////////////////////////////////
  test('signedTypeData', () {
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
          {"name": "wallet", "type": "address"}
        ],
        "Mail": [
          {"name": "from", "type": "Person"},
          {"name": "to", "type": "Person"},
          {"name": "contents", "type": "string"}
        ]
      },
      "primaryType": "Mail",
      "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
      },
      "message": {
        "from": {
          "name": "Cow",
          "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
        },
        "to": {
          "name": "Bob",
          "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
        },
        "contents": "Hello, Bob!"
      }
    };
    final jsonData = jsonEncode(rawTypedData);
    final privateKey = keccak256(Uint8List.fromList(utf8.encode('cow')));

    final sig = EthSigUtil.signTypedData(
        privateKey: bytesToHex(privateKey),
        jsonData: jsonData,
        version: TypedDataVersion.V3);

    expect(sig,
        '0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c');
  });
  //////////////////////////////////////////////////////////////////////////////
  test('signedTypeData with bytes', () {
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
          {"name": "wallet", "type": "address"}
        ],
        "Mail": [
          {"name": "from", "type": "Person"},
          {"name": "to", "type": "Person"},
          {"name": "contents", "type": "string"},
          {"name": "payload", "type": "bytes"}
        ]
      },
      "primaryType": "Mail",
      "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
      },
      "message": {
        "from": {
          "name": "Cow",
          "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
        },
        "to": {
          "name": "Bob",
          "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
        },
        "contents": "Hello, Bob!",
        "payload":
            "0x25192142931f380985072cdd991e37f65cf8253ba7a0e675b54163a1d133b8ca"
      }
    };
    final jsonData = jsonEncode(rawTypedData);
    final privateKey = keccak256(Uint8List.fromList(utf8.encode('cow')));

    final sig = EthSigUtil.signTypedData(
        privateKey: bytesToHex(privateKey),
        jsonData: jsonData,
        version: TypedDataVersion.V3);

    expect(sig,
        '0xdd17ea877a7da411c85ff94bc54180631d0e86efdcd68876aeb2e051417b68e76be6858d67b20baf7be9c6402d49930bfea2535e9ae150e85838ee265094fd081b');
  });
  //////////////////////////////////////////////////////////////////////////////
  test('signedTypeData_v4', () {
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
          {"name": "wallets", "type": "address[]"}
        ],
        "Mail": [
          {"name": "from", "type": "Person"},
          {"name": "to", "type": "Person[]"},
          {"name": "contents", "type": "string"}
        ],
        "Group": [
          {"name": "name", "type": "string"},
          {"name": "members", "type": "Person[]"}
        ]
      },
      "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
      },
      "primaryType": "Mail",
      "message": {
        "from": {
          "name": "Cow",
          "wallets": [
            "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
            "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"
          ]
        },
        "to": [
          {
            "name": "Bob",
            "wallets": [
              "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
              "0xB0BdaBea57B0BDABeA57b0bdABEA57b0BDabEa57",
              "0xB0B0b0b0b0b0B000000000000000000000000000"
            ]
          }
        ],
        "contents": "Hello, Bob!"
      }
    };
    final jsonData = jsonEncode(rawTypedData);
    final privateKey = keccak256(Uint8List.fromList(utf8.encode('cow')));

    final sig = EthSigUtil.signTypedData(
        privateKey: bytesToHex(privateKey),
        jsonData: jsonData,
        version: TypedDataVersion.V4);

    expect(sig,
        '0x65cbd956f2fae28a601bebc9b906cea0191744bd4c4247bcd27cd08f8eb6b71c78efdf7a31dc9abee78f492292721f362d296cf86b4538e07b51303b67f749061b');
  });
  //////////////////////////////////////////////////////////////////////////////
  test('signedTypeMessage V4 with recursive types', () {
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
    final jsonData = jsonEncode(rawTypedData);
    final privateKey = keccak256(Uint8List.fromList(utf8.encode('dragon')));

    final sig = EthSigUtil.signTypedData(
        privateKey: bytesToHex(privateKey),
        jsonData: jsonData,
        version: TypedDataVersion.V4);

    expect(sig,
        '0xf2ec61e636ff7bb3ac8bc2a4cc2c8b8f635dd1b2ec8094c963128b358e79c85c5ca6dd637ed7e80f0436fe8fce39c0e5f2082c9517fe677cc2917dcd6c84ba881c');
  });
}
