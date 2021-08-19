import 'package:equatable/equatable.dart';

class ECDSASignature extends Equatable {
  final BigInt r;
  final BigInt s;
  final int v;

  ECDSASignature(this.r, this.s, this.v);

  @override
  List<Object?> get props => [r, s, v];
}