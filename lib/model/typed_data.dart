/// For typed data V1
class EIP712TypedData {
  String name;
  String type;
  dynamic value;

  EIP712TypedData({required this.name, required this.type, this.value});

  factory EIP712TypedData.fromJson(Map<String, dynamic> json) =>
      EIP712TypedData(
          name: json['name'] as String,
          type: json['type'] as String,
          value: json['value']);

  Map<String, dynamic> toJson() =>
      <String, dynamic>{'name': name, 'type': type, 'value': value};
}

/// For typed data V3, V4
class TypedMessage {
  Map<String, List<TypedDataField>> types;
  String primaryType;
  EIP712Domain? domain;
  Map<String, dynamic> message;

  TypedMessage(
      {required this.types,
      required this.primaryType,
      required this.domain,
      required this.message});

  factory TypedMessage.fromJson(Map<String, dynamic> json) => TypedMessage(
      types: (json['types'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            (e as List)
                .map((e) => TypedDataField.fromJson(e as Map<String, dynamic>))
                .toList()),
      ),
      primaryType: json['primaryType'] as String,
      domain: json['domain'] == null
          ? null
          : EIP712Domain.fromJson(json['domain'] as Map<String, dynamic>),
      message: json['message'] as Map<String, dynamic>);

  Map<String, dynamic> toJson() => <String, dynamic>{
        'types': types,
        'primaryType': primaryType,
        'domain': domain,
        'message': message
      };
}

class TypedDataField {
  String name;
  String type;

  TypedDataField({required this.name, required this.type});

  factory TypedDataField.fromJson(Map<String, dynamic> json) => TypedDataField(
      name: json['name'] as String, type: json['type'] as String);

  Map<String, dynamic> toJson() =>
      <String, dynamic>{'name': name, 'type': type};
}

class EIP712Domain {
  String? name;
  String? version;
  int? chainId;
  String? verifyingContract;

  EIP712Domain(
      {required this.name,
      required this.version,
      required this.chainId,
      required this.verifyingContract});

  dynamic operator [](String key) {
    switch (key) {
      case 'name':
        return name;
      case 'version':
        return version;
      case 'chainId':
        return chainId;
      case 'verifyingContract':
        return verifyingContract;
      default:
        throw ArgumentError("Key ${key} is invalid");
    }
  }

  factory EIP712Domain.fromJson(Map<String, dynamic> json) => EIP712Domain(
      name: json['name'] as String,
      version: json['version'] as String,
      chainId: json['chainId'] is int
          ? json['chainId']
          : int.tryParse(json['chainId']),
      verifyingContract: json['verifyingContract'] as String);

  Map<String, dynamic> toJson() => <String, dynamic>{
        'name': name,
        'version': version,
        'chainId': chainId,
        'verifyingContract': verifyingContract
      };
}
