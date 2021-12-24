import 'dart:convert';

import 'package:hex/hex.dart';
import 'package:znn_swap_utility/src/crypto/prv_key.dart';
import 'package:znn_swap_utility/src/crypto/pub_key.dart';
import 'package:znn_swap_utility/src/crypto/signing.dart';
import 'package:znn_swap_utility/src/utils/utils.dart';

class Message {
  List<int>? _message;

  final magicBytes = 'Zenon secp256k1 signature:';

  /// A double-sha256 digest similar to Bitcoin Signed Messages
  List<int> magicHash() {
    var prefix1 = magicBytes.length;
    var prefix2 = _message!.length;
    var buf =
        HEX.encode([prefix1] + utf8.encode(magicBytes) + [prefix2] + _message!);
    var hash = doubleSHA256(HEX.decode(buf));
    return hash;
  }

  /// Constructs a new Message object
  ///
  /// [message] - UTF-8 encoded byte buffer containing the message
  Message(List<int> message) {
    _message = message;
  }

  /// Sign the message using the private key
  ///
  /// [privateKey] - The private key to use in signing the message
  String sign(ZNNPrivateKey privateKey) {
    ZNNSignature signature = ZNNSignature.fromPrivateKey(privateKey);
    signature.sign(HEX.encode(magicHash()), forCompact: true);
    List<int> compactSig = signature.toCompact();
    return base64Encode(compactSig);
  }

  /// Verify that this message was signed by the owner of public key in [publicKey]
  ///
  /// [publicKey] - Public key to be used in signature verification
  ///
  /// [sigBuffer] - Base64-encoded Compact Signature
  ///
  /// Returns *true* if the signature is successfully verified using the public key, *false* otherwise.
  bool verifyFromPublicKey(ZNNPublicKey publicKey, String sigBuffer) {
    ZNNSignature signature =
        ZNNSignature.fromCompact(base64Decode(sigBuffer), magicHash());

    ZNNPublicKey recoveredKey = signature.publicKey;

    // Sanity check on public key
    if (recoveredKey.point != publicKey.point) {
      return false;
    }

    return _verify(signature);
  }

  bool _verify(ZNNSignature signature) {
    var hash = magicHash();

    return signature.verify(HEX.encode(hash));
  }

  /// The message we are signing/verifying
  List<int> get message => _message!;
}
