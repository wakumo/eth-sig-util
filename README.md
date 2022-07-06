# eth_sig_util

Ethereum signature utility porting from JS

This lib came from the demand of our project [Avacus](https://avacus.cc)

Inspired by Dart ethereum_util but no longer active and not yet supported for V1 and V4

## Features
- Sign typed message (Typed Data follow EIP712 standard)
- Sign personal typed message (Typed Data follow EIP712 standard)
- Sign message
- Sign personal message
- Recover public address from signature (personal_ecRecover)

## Usage
```dart
import 'package:eth_sig_util/eth_sig_util.dart';

String signature = EthSigUtil.signTypedData(privateKey: '4af...bb0', jsonData: '{...}', version: TypedDataVersion.V4);

String signature = EthSigUtil.signPersonalTypedData(privateKey: '4af...bb0', jsonData: '{...}', version: TypedDataVersion.V4);

String signature = EthSigUtil.signMessage(privateKey: '4af...bb0', message: []);

String signature = EthSigUtil.signPersonalMessage(privateKey: '4af...bb0', message: []);

String address = EthSigUtil.recoverSignature(signature: '0x84ea3...', message: []);

String address = EthSigUtil.recoverPersonalSignature(signature: '0x84ea3...', message: []);
```