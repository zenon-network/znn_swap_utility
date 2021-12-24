import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'package:sprintf/sprintf.dart';
import 'package:znn_swap_utility/src/crypto/prv_key.dart';
import 'package:znn_swap_utility/src/crypto/pub_key.dart';
import 'package:znn_swap_utility/src/utils/exceptions.dart';

class ZNNSignature {
  final ECDomainParameters _domainParams = ECDomainParameters('secp256k1');
  static final SHA256Digest _sha256Digest = SHA256Digest();
  final ECDSASigner _dsaSigner = ECDSASigner(null, HMac(_sha256Digest, 64));

  ECSignature? _signature;
  BigInt? _r;
  BigInt? _s;
  String? _rHex;
  String? _sHex;
  int? _i;
  bool _compressed = false;

  ZNNPrivateKey? _privateKey;
  ZNNPublicKey? _publicKey;

  /// Construct a  instance from the R and S components of an ECDSA signature.
  ///
  /// [r] - The r component of the signature
  ///
  /// [s] - The s component of the signature
  ZNNSignature.fromECParams(this._r, this._s) {
    _signature = ECSignature(_r!, _s!);
  }

  /// Constructs a signature from it's DER-encoded form
  ///
  /// [derBuffer] - Hex-encoded DER string containing the signature
  ZNNSignature.fromDER(String derBuffer, {ZNNPublicKey? publicKey}) {
    _publicKey = publicKey;
    _parseDER(derBuffer);
  }

  /// Construct a signature instance from a PrivateKey for signing purposes.
  ZNNSignature.fromPrivateKey(ZNNPrivateKey privateKey) {
    ECPrivateKey prvKey = ECPrivateKey(privateKey.privateKey, _domainParams);

    _privateKey = privateKey;
    _compressed = privateKey.isCompressed;

    _dsaSigner.init(true, PrivateKeyParameter(prvKey));
  }

  /// Constructs a signature instance from PublicKey for verification *ONLY*.
  ZNNSignature.fromPublicKey(ZNNPublicKey publicKey) {
    ECPublicKey pubKey = ECPublicKey(publicKey.point, _domainParams);
    _publicKey = publicKey;
    _dsaSigner.init(false, PublicKeyParameter(pubKey));
  }

  /// Construct the Signature and recover the public key.
  /// With the public key recovered we can use this signature for *verification only*
  ///
  /// This paper (section 4.1.6) describes an algorithm for recovering the public key from an ECDSA signature:
  /// (http://www.secg.org/sec1-v2.pdf)
  ///
  /// [buffer] - Signature in Compact Signature form
  ///
  /// [signedMessage] - Message signed with the signature in [buffer]
  ///
  ZNNSignature.fromCompact(List<int> buffer, List<int> signedMessage) {
    var compressed = true;
    var i = buffer.sublist(0, 1)[0] - 27 - 4;
    if (i < 0) {
      compressed = false;
      i = i + 4;
    }

    var b2 = buffer.sublist(1, 33);
    var b3 = buffer.sublist(33, 65);

    if (![0, 1, 2, 3].contains(i)) {
      throw SignatureException('i must be 0, 1, 2, or 3');
    }

    if (b2.length != 32) {
      throw SignatureException('r must be 32 bytes');
    }

    if (b3.length != 32) {
      throw SignatureException('s must be 32 bytes');
    }

    _compressed = compressed;
    _i = i;

    var tmp = HEX.encode(b2);
    _r = BigInt.parse(tmp, radix: 16);
    tmp = HEX.encode(b3);
    _s = BigInt.parse(tmp, radix: 16);

    _rHex = _r!.toRadixString(16);
    _sHex = _s!.toRadixString(16);

    _signature = ECSignature(_r!, _s!);

    _publicKey = _recoverPublicKey(i, signedMessage);
    _dsaSigner.init(false,
        PublicKeyParameter(ECPublicKey(_publicKey!.point, _domainParams)));
  }

  /// Renders the signature in *compact* form.
  ///
  /// Returns a buffer containing the ECDSA signature in compact format allowing for
  /// public key recovery. See the [fromCompact()] constructor
  List<int> toCompact() {
    if (![0, 1, 2, 3].contains(_i)) {
      throw SignatureException('i must be equal to 0, 1, 2, or 3');
    }

    var val = _i! + 27 + 4;
    if (!_compressed) {
      val = val - 4;
    }

    var b1 = [val];

    var b2Padded =
        sprintf("%064s", [_r!.toRadixString(16)]).replaceAll(' ', '0');
    var b2 = HEX.decode(b2Padded);
    var b3Padded =
        sprintf("%064s", [_s!.toRadixString(16)]).replaceAll(' ', '0');
    var b3 = HEX.decode(b3Padded);
    return b1 + b2 + b3;
  }

  /// Verify that the provided message was signed using this signature
  ///
  /// [message] - The message to verify as a hexadecimal string
  bool verify(String message) {
    //expecting a String here is confusing. Make it a List<int> so the caller
    //can be forced to do hex encoding via HEX.encode(utf8.encode())
    if (_signature == null) {
      throw SignatureException('Signature is not initialized');
    }

    var decodedMessage = Uint8List.fromList(HEX.decode(message).toList());

    return _dsaSigner.verifySignature(decodedMessage, _signature!);
  }

  /// Signs a message and optionally also calculates the first byte needed for compact format rendering.
  ///
  /// *NOTE:* - subsequent
  ///
  /// [message] - The message to sign
  ///
  /// [forCompact] - If *true* then we perform additional calculation of first byte needed to render the signature in compact format with [toCompact()]
  String sign(String message, {bool forCompact = false}) {
    if (_privateKey == null) {
      throw SignatureException(
          'Missing private key. Initialise this signature instance using fromPrivateKey()');
    }

    List<int> decodedMessage = Uint8List.fromList(HEX.decode(message).toList());

    _signature = _dsaSigner.generateSignature(decodedMessage as Uint8List)
        as ECSignature?;
    _r = _signature!.r;
    _s = _signature!.s;
    _rHex = _r!.toRadixString(16);
    _sHex = _s!.toRadixString(16);

    _toLowS();

    if (forCompact) {
      _calculateI(decodedMessage);
    }

    return toString();
  }

  @override
  String toString() {
    if (_signature == null) {
      return '';
    }

    return HEX.encode(toDER());
  }

  /// Renders the signature as a DER-encoded byte buffer
  List<int> toDER() {
    var seq = ASN1Sequence();
    seq.add(ASN1Integer(_r));
    seq.add(ASN1Integer(_s));

    return seq.encode();
  }

  /// Comparable to bitcoin's IsLowDERSignature. Returns true if the signature has a 'low' S-value.
  ///
  /// See also ECDSA signature algorithm which enforces
  /// See also BIP 62, 'low S values in signatures'
  bool hasLowS() {
    var hex =
        '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0';

    if (_s! < (BigInt.from(1)) || _s! > (BigInt.parse(hex, radix: 16))) {
      return false;
    }

    return true;
  }

  // side-effects on _i
  void _calculateI(List<int> decodedMessage) {
    var pubKey = _privateKey!.publicKey;
    for (var i = 0; i < 4; i++) {
      _i = i;
      ZNNPublicKey qPrime;
      try {
        qPrime = _recoverPublicKey(i, decodedMessage);
      } catch (e) {
        continue;
      }

      if (qPrime.point == pubKey!.point) {
        _compressed = qPrime.isCompressed;
        return;
      }
    }

    _i = -1;
    throw SignatureException('Unable to find valid recovery factor');
  }

  ZNNPublicKey _recoverPublicKey(int i, List<int> hashBuffer) {
    if (![0, 1, 2, 3].contains(i)) {
      throw SignatureException('i must be equal to 0, 1, 2, or 3');
    }

    var tmp = HEX.encode(hashBuffer);
    var e = BigInt.parse(tmp, radix: 16);

    var r = this.r;
    var s = this.s;

    // The more significant bit specifies whether we should use the
    // first or second candidate key.
    var isSecondKey = i >> 1 != 0;

    var n = _domainParams.n;
    var G = _domainParams.G;

    // 1.1 Let x = r + jn
    var x = isSecondKey ? r + n : r;
    var yTilde = i & 1;
    var R = _domainParams.curve.decompressPoint(yTilde, x);

    // 1.4 Check that nR is at infinity
    var nR = (R * n)!;

    if (!nR.isInfinity) {
      throw SignatureException('nR is not a valid curve point');
    }

    // Compute -e from e
    var eNeg = -e % n;

    // 1.6.1 Compute Q = r^-1 (sR - eG)
    var rInv = r.modInverse(n);
    var Q = (((R * s)! + G * eNeg)! * rInv)!;

    return ZNNPublicKey.fromXY(Q.x!.toBigInteger()!, Q.y!.toBigInteger()!,
        compressed: _compressed);
  }

  void _toLowS() {
    if (_s == null) return;

    // enforce low s
    // see BIP 62, 'low S values in signatures'
    if (_s! >
        BigInt.parse(
            '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0',
            radix: 16)) {
      _s = _domainParams.n - _s!;
    }
  }

  void _parseDER(derBuffer) {
    try {
      var parser = ASN1Parser(HEX.decode(derBuffer) as Uint8List?);

      var seq = parser.nextObject() as ASN1Sequence;

      var rVal = seq.elements![0] as ASN1Integer;
      var sVal = seq.elements![1] as ASN1Integer;

      _rHex = HEX.encode(rVal.valueBytes!);
      _sHex = HEX.encode(sVal.valueBytes!);

      _r = BigInt.parse(_rHex!, radix: 16);
      _s = BigInt.parse(_sHex!, radix: 16);

      _signature = ECSignature(r, s);
    } catch (e) {
      throw SignatureException(e.toString());
    }
  }

  /// Returns the signature's *S* value
  BigInt get s => _s!;

  /// Returns the signature's *R* value
  BigInt get r => _r!;

  /// Returns the public key that will be used to verify signatures
  ZNNPublicKey get publicKey => _publicKey!;

  int? get i => _i;

  /// Returns the signature's *S* value as a hexadecimal string
  String? get sHex => _sHex!;

  /// Returns the signature's *R* value as a hexadecimal string
  String? get rHex => _rHex!;
}
