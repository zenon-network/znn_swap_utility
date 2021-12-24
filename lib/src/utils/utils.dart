import 'dart:typed_data';

import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/export.dart';

List<int> doubleSHA256(List<int> bytes) {
  var first = SHA256Digest().process(Uint8List.fromList(bytes));
  var second = SHA256Digest().process(first);
  return second.toList();
}

var _byteMask = BigInt.from(0xff);

Uint8List encodeBigInt(BigInt number) {
  var size = (number.bitLength + 7) >> 3;

  var result = Uint8List(size);
  for (var i = 0; i < size; i++) {
    result[size - i - 1] = (number & _byteMask).toInt();
    number = number >> 8;
  }

  return result;
}

List<int> hash160(List<int> bytes) {
  List<int> shaHash = SHA256Digest().process(Uint8List.fromList(bytes));
  var ripeHash = RIPEMD160Digest().process(shaHash as Uint8List);
  return ripeHash.toList();
}
