import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:znn_swap_utility/src/utils/exceptions.dart';
import 'package:znn_swap_utility/src/utils/utils.dart';

var alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

List<int?> decode(String input) {
  if (input.isEmpty) {
    return <int>[];
  }
  var encodedInput = utf8.encode(input);
  var uintAlphabet = utf8.encode(alphabet);
  var indexes = List<int?>.filled(128, null)..fillRange(0, 128, -1);
  for (var i = 0; i < alphabet.length; i++) {
    indexes[uintAlphabet[i]] = i;
  }
  var input58 = List<int?>.filled(encodedInput.length, null);
  input58.fillRange(0, input58.length, 0);
  for (var i = 0; i < encodedInput.length; ++i) {
    var c = encodedInput[i];
    var digit = c < 128 ? indexes[c]! : -1;
    if (digit < 0) {
      var buff = List<int?>.filled(1, null)..add(c);
      var invalidChar = utf8.decode(buff as List<int>);
      throw IllegalCharacterException(
          'Illegal character ' + invalidChar + ' at position ' + i.toString());
    }
    input58[i] = digit;
  }
  var zeros = 0;
  while (zeros < input58.length && input58[zeros] == 0) {
    ++zeros;
  }
  var decoded = List<int?>.filled(encodedInput.length, null);
  decoded.fillRange(0, decoded.length, 0);
  var outputStart = decoded.length;
  for (var inputStart = zeros; inputStart < input58.length;) {
    decoded[--outputStart] = divmod(input58, inputStart, 58, 256);
    if (input58[inputStart] == 0) {
      ++inputStart;
    }
  }
  while (outputStart < decoded.length && decoded[outputStart] == 0) {
    ++outputStart;
  }
  return decoded.sublist(outputStart - zeros, decoded.length);
}

int divmod(List<int?> number, int firstDigit, int base, int divisor) {
  var remainder = 0;
  for (var i = firstDigit; i < number.length; i++) {
    var digit = number[i]! & 0xFF;
    var temp = remainder * base + digit;
    number[i] = temp ~/ divisor;
    remainder = temp % divisor;
  }
  return remainder.toSigned(8);
}

Uint8List encode(List<int?> encodedInput) {
  var uintAlphabet = utf8.encode(alphabet);
  var encodedZero = uintAlphabet[0];
  if (encodedInput.isEmpty) {
    return <int>[] as Uint8List;
  }
  var zeros = 0;
  while (zeros < encodedInput.length && encodedInput[zeros] == 0) {
    ++zeros;
  }
  var encoded = Uint8List(encodedInput.length * 2);
  var outputStart = encoded.length;
  for (var inputStart = zeros; inputStart < encodedInput.length;) {
    encoded[--outputStart] =
        uintAlphabet[divmod(encodedInput, inputStart, 256, 58)];
    if (encodedInput[inputStart] == 0) {
      ++inputStart;
    }
  }
  while (outputStart < encoded.length && encoded[outputStart] == encodedZero) {
    ++outputStart;
  }
  while (--zeros >= 0) {
    encoded[--outputStart] = encodedZero;
  }
  return encoded.sublist(outputStart, encoded.length);
}

List<int?> decodeChecked(String input) {
  var decoded = decode(input);
  if (decoded.length < 4) throw InvalidKeyException('Input too short');
  var data = decoded.sublist(0, decoded.length - 4);
  var checksum = decoded.sublist(decoded.length - 4, decoded.length);
  var actualChecksum =
      doubleSHA256(List<int>.generate(data.length, (index) => data[index]!))
          .sublist(0, 4);
  var byteConverted = actualChecksum.map((elem) => elem.toSigned(8));
  if (!IterableEquality().equals(checksum, byteConverted)) {
    throw InvalidChecksumException('Checksum does not validate');
  }
  return data;
}
