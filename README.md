# eth_sig_util

Ethereum signature utility porting from JS

This lib came from the demand of project and main focus on sign typed data firstly

Inspired by Dart ethereum_util but no longer working and not yet supported for V1 and V4

## Features
- Sign typed data EIP712 V1, V3, V4

## Usage
```dart
import 'package:eth_sig_util/eth_sig_util.dart';

String signature = EthSigUtil.signTypedData(privateKey: '4af...bb0', jsonData: '{...}', version: TypedDataVersion.V4);
```