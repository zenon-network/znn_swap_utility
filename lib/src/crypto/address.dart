import 'dart:convert';
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:znn_swap_utility/src/crypto/pub_key.dart';
import 'package:znn_swap_utility/src/encoding/base58check.dart' as base58check;
import 'package:znn_swap_utility/src/utils/utils.dart';

enum AddressType { pubKeyHash }

class Address {
  String? _publicKeyHash;
  int? _version;

  /// Constructs a new Address object
  ///
  /// [address] is the base58encoded Zenon address.
  Address(String address) {
    _fromBase58(address);
  }

  /// Constructs a new Address object from a public key.
  ///
  /// [hexPubKey] is the hexadecimal encoding of a public key.
  Address.fromHex(String hexPubKey) {
    _createFromHex(hexPubKey);
  }

  /// Constructs a new Address object from the public key
  ///
  /// [pubKey] - The public key
  Address.fromPublicKey(ZNNPublicKey pubKey) {
    _createFromHex(pubKey.toHex());
  }

  /// Constructs a new Address object from a compressed public key value
  ///
  /// [pubKeyBytes] is a byte-buffer of a public key
  Address.fromCompressedPubKey(List<int> pubKeyBytes) {
    _createFromHex(HEX.encode(pubKeyBytes));
    _publicKeyHash = HEX.encode(hash160(pubKeyBytes));
  }

  /// Constructs a new Address object from a base58-encoded string.
  Address.fromBase58(String base58Address) {
    if (base58Address.length == 25 || base58Address.length == 34) {
      _fromBase58(base58Address);
    } else {
      throw Exception(
          'Address should be 25 bytes long. Only [${base58Address.length}] bytes long.');
    }
  }

  String toBase58() {
    // A stringified buffer is: 1 byte version + data bytes + 4 bytes check code (a truncated hash)
    var rawHash = Uint8List.fromList(HEX.decode(_publicKeyHash!));

    return _getEncoded(rawHash);
  }

  /// Serialise this address object to a base58-encoded string.
  /// This method is an alias for the [toBase58()] method
  @override
  String toString() {
    return toBase58();
  }

  /// Returns the public key hash [ripemd160(sha256(public_key))] encoded as a  hexadecimal string
  String? toHex() {
    return _publicKeyHash;
  }

  String _getEncoded(List<int> hashAddress) {
    var addressBytes =
        List<int>.generate(1 + hashAddress.length + 4, (index) => 0);
    addressBytes[0] = _version!;

    //copy all of raw address content, taking care not to
    //overwrite the version byte at start
    addressBytes.fillRange(1, addressBytes.length, 0);
    addressBytes.setRange(1, hashAddress.length + 1, hashAddress);

    //checksum calculation, doubleSha everything except the last four checksum bytes
    var doubleShaAddr =
        doubleSHA256(addressBytes.sublist(0, hashAddress.length + 1));
    var checksum =
        doubleShaAddr.sublist(0, 4).map((elem) => elem.toSigned(8)).toList();

    addressBytes.setRange(
        hashAddress.length + 1, addressBytes.length, checksum);
    var encoded = base58check.encode(addressBytes);
    var utf8Decoded = utf8.decode(encoded);

    return utf8Decoded;
  }

  void _fromBase58(String address) {
    address = address.trim();

    var versionAndDataBytes = base58check.decodeChecked(address);
    var versionByte = versionAndDataBytes[0]!.toUnsigned(8);

    _version = versionByte & 0xFF;

    var stripVersion =
        versionAndDataBytes.sublist(1, versionAndDataBytes.length);
    _publicKeyHash =
        HEX.encode(stripVersion.map((elem) => elem!.toUnsigned(8)).toList());
  }

  /// This method retrieves the version byte corresponding to the NetworkAddressType
  ///
  /// [type] - The network address type
  ///
  /// Returns the version byte to prepend to a serialized [Address]
  void _createFromHex(String hexPubKey) {
    var versionByte = 80;

    _version = versionByte & 0XFF;
    _publicKeyHash = HEX.encode(hash160(HEX.decode(hexPubKey)));
  }

  /// Returns a hash of the Public Key
  ///
  /// The [sha256] digest of the public key is computed, and the result of that
  /// computation is then passed to the [ripemd160] digest function.
  ///
  /// The returned value is HEX-encoded
  String? get address => _publicKeyHash;

  /// An alias for the [address] property
  String? get pubKeyHash160 => _publicKeyHash;
}
