import 'dart:math';
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:znn_swap_utility/src/crypto/pub_key.dart';
import 'package:znn_swap_utility/src/encoding/base58check.dart' as base58;
import 'package:znn_swap_utility/src/utils/exceptions.dart';

/// Manages an ECDSA private key.
///
/// Zenon Core s ECDSA for it's public/private key cryptography.
/// Specifically it uses the [secp256k1] elliptic curve.
///
/// This class wraps cryptographic operations related to ECDSA from the
/// [PointyCastle](https://pub.dev/packages/pointycastle) library/package.
class ZNNPrivateKey {
  final _domainParams = ECDomainParameters('secp256k1');
  final _secureRandom = FortunaRandom();

  var _hasCompressedPubKey = false;
  var random = Random.secure();

  BigInt? _d;
  late ECPrivateKey _ecPrivateKey;
  ZNNPublicKey? _znnPublicKey;

  /// Constructs a  random private key
  ZNNPrivateKey() {
    var keyParams = ECKeyGeneratorParameters(ECCurve_secp256k1());
    _secureRandom.seed(KeyParameter(_seed()));

    var generator = ECKeyGenerator();
    generator.init(ParametersWithRandom(keyParams, _secureRandom));

    var retry = 256;
    late AsymmetricKeyPair keypair;
    while (retry > 0) {
      keypair = generator.generateKeyPair();
      ECPrivateKey key = keypair.privateKey as ECPrivateKey;
      if (key.d!.bitLength == 256) {
        break;
      } else {
        retry--;
      }
    }

    _hasCompressedPubKey = true;
    _ecPrivateKey = keypair.privateKey as ECPrivateKey;
    _d = _ecPrivateKey.d;

    if (_d!.bitLength != 256) {
      throw InvalidKeyException(
          "Failed to generate a valid private key after 256 iterations. Try again");
    }

    _znnPublicKey = ZNNPublicKey.fromPrivateKey(this);
  }

  /// Constructs a  Private Key from a Big Integer.
  ///
  /// [privateKey] - The private key as a Big Integer value. Remember that in
  /// ECDSA we compute the public key (Q) as `Q = d * G`
  ZNNPrivateKey.fromBigInt(BigInt privateKey) {
    _ecPrivateKey = _privateKeyFromBigInt(privateKey);
    _d = privateKey;
    _hasCompressedPubKey = true;
    _znnPublicKey = ZNNPublicKey.fromPrivateKey(this);
  }

  /// Construct a  Private Key from the hexadecimal value representing the
  /// BigInt value of (d) in ` Q = d * G `
  ///
  /// [prvHex] = The BigInt representation of the private key as a hexadecimal string
  ZNNPrivateKey.fromHex(String prvHex) {
    var d = BigInt.parse(prvHex, radix: 16);
    _hasCompressedPubKey = true;
    _ecPrivateKey = _privateKeyFromBigInt(d);
    _d = d;
    _znnPublicKey = ZNNPublicKey.fromPrivateKey(this);
  }

  /// Construct a  Private Key from the WIF encoded format.
  ///
  /// WIF is an abbreviation for Wallet Import Format. It is a format based on base58-encoding
  /// a private key so as to make it resistant to accidental user error in copying it. A wallet
  /// should be able to verify that the WIF format represents a valid private key.
  ///
  /// [wifKey] - The private key in WIF-encoded format. See [this bitcoin wiki entry](https://en.bitcoin.it/wiki/Wallet_import_format)
  ZNNPrivateKey.fromWIF(String wifKey) {
    if (wifKey.length != 51 && wifKey.length != 52) {
      throw InvalidKeyException(
          'Valid keys are either 51 or 52 bytes in length');
    }

    var versionAndDataBytes = base58.decodeChecked(wifKey);

    switch (wifKey[0]) {
      case 'W':
        {
          if (wifKey.length != 52) {
            throw InvalidKeyException(
                'Compressed private keys have a length of 52 bytes');
          }
          break;
        }
      case 'X':
        {
          if (wifKey.length != 52) {
            throw InvalidKeyException(
                'Compressed private keys have a length of 52 bytes');
          }
          break;
        }
    }

    var versionStripped =
        versionAndDataBytes.sublist(1, versionAndDataBytes.length);

    if (versionStripped.length == 33) {
      if (versionStripped[32] != 0x01) {
        throw InvalidKeyException(
            'Compressed keys must have the last byte set as 0x01. The byte supplied is [${versionStripped[32]}]');
      }
      versionStripped = versionStripped.sublist(0, 32);
      _hasCompressedPubKey = true;
    } else {
      _hasCompressedPubKey = false;
    }

    var strippedHex =
        HEX.encode(versionStripped.map((elem) => elem!.toUnsigned(8)).toList());
    var d = BigInt.parse(strippedHex, radix: 16);
    _ecPrivateKey = _privateKeyFromBigInt(d);
    _d = d;
    _znnPublicKey = ZNNPublicKey.fromPrivateKey(this);
  }

  /// Returns the *naked* private key Big Integer value as a hexadecimal string
  String toHex() {
    return _d!.toRadixString(16);
  }

  Uint8List _seed() {
    var random = Random.secure();
    var seed = List<int>.generate(32, (_) => random.nextInt(256));
    return Uint8List.fromList(seed);
  }

  ECPrivateKey _privateKeyFromBigInt(BigInt d) {
    if (d == BigInt.zero) {
      throw InvalidParameterException(
          'Zero is a bad value for a private key. Pick something else.');
    }

    return ECPrivateKey(d, _domainParams);
  }

  /// Returns the *naked* private key Big Integer value as a Big Integer
  BigInt? get privateKey {
    return _d;
  }

  /// Returns the [ZNNPublicKey] corresponding to this ECDSA private key
  /// NOTE: `Q = d * G` where *Q* is the public key, *d* is the private key and `G` is the curve's Generator
  ZNNPublicKey? get publicKey {
    return _znnPublicKey;
  }

  /// Returns true if the corresponding public key for this private key is in *compressed* format
  bool get isCompressed {
    return _hasCompressedPubKey;
  }
}
