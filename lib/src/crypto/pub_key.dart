import 'package:hex/hex.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:znn_swap_utility/src/crypto/prv_key.dart';
import 'package:znn_swap_utility/src/utils/exceptions.dart';
import 'package:znn_swap_utility/src/utils/utils.dart';

/// Manages an ECDSA public key.
///
/// Zenon uses ECDSA for it's public/private key cryptography.
/// Specifically it uses the `secp256k1` elliptic curve.
///
/// This class wraps cryptographic operations related to ECDSA from the
/// [PointyCastle](https://pub.dev/packages/pointycastle) library/package.
class ZNNPublicKey {
  final _domainParams = ECDomainParameters('secp256k1');

  ECPoint? _point;

  /// Creates a  public key from it's corresponding ECDSA private key.
  ///
  /// NOTE: public key *Q* is computed as `Q = d * G` where *d* is the private key
  /// and *G* is the elliptic curve Generator.
  ///
  /// [prvKey] - The private key who's *d*-value we will use.
  ZNNPublicKey.fromPrivateKey(ZNNPrivateKey prvKey) {
    var decodedPrvKey = encodeBigInt(prvKey.privateKey!);
    var hexPrvKey = HEX.encode(decodedPrvKey);
    var actualKey = hexPrvKey;
    var point = (_domainParams.G * BigInt.parse(actualKey, radix: 16))!;
    if (point.x == null && point.y == null) {
      throw InvalidPointException(
          'Cannot generate point from private key. Private key greater than N?');
    }
    var finalPoint = _domainParams.curve.createPoint(point.x!.toBigInteger()!,
        point.y!.toBigInteger()!, prvKey.isCompressed);
    _checkIfOnCurve(finalPoint);
    _point = finalPoint;
  }

  /// Creates a public key instance from the ECDSA public key's `x-coordinate`
  ///
  /// ECDSA has some cool properties. Because we are dealing with an elliptic curve in a plane,
  /// the public key *Q* has (x,y) cartesian coordinates.
  /// It is possible to reconstruct the full public key from only it's `x-coordinate`
  /// *IFF* one knows whether the Y-Value is *odd* or *even*.
  ///
  /// [xValue] - The Big Integer value of the `x-coordinate` in hexadecimal format
  ///
  /// [oddYValue] - *true* if the corresponding `y-coordinate` is even, *false* otherwise
  ZNNPublicKey.fromX(String xValue, bool oddYValue) {
    _point = _getPointFromX(xValue, oddYValue);
  }

  /// Creates a  public key from it's known *(x,y)* coordinates.
  ///
  /// [x] - X coordinate of the public key
  ///
  /// [y] - Y coordinate of the public key
  ///
  /// [compressed] = Specifies whether we will render this point in it's
  /// compressed form by default with [toString()]. See [getEncoded()] to
  /// learn more about compressed public keys.
  ZNNPublicKey.fromXY(BigInt x, BigInt y, {bool compressed = true}) {
    var point = _domainParams.curve.createPoint(x, y, compressed);
    _checkIfOnCurve(point);
    _point = point;
  }

  /// Reconstructs a public key from a DER-encoding.
  ///
  /// [buffer] - Byte array containing public key in DER format.
  ///
  /// [strict] - If *true* then we enforce strict DER encoding rules. Defaults to *true*.
  ZNNPublicKey.fromDER(List<int> buffer, {bool strict = true}) {
    if (buffer.isEmpty) {
      throw InvalidParameterException('Empty compressed DER buffer');
    }
    _point = _transformDER(buffer, strict);
    if (_point!.isInfinity) {
      throw InvalidPointException(
          'That public key generates point at infinity');
    }
    if (_point!.y!.toBigInteger() == BigInt.zero) {
      throw InvalidPointException('Invalid Y value for this public key');
    }
    _checkIfOnCurve(_point!);
  }

  /// Reconstruct a public key from the hexadecimal format of it's DER-encoding.
  ///
  /// [pubKey] - The DER-encoded public key as a hexadecimal string
  ///
  /// [strict] - If *true* then we enforce strict DER encoding rules. Defaults to *true*.
  ZNNPublicKey.fromHex(String pubKey, {bool strict = true}) {
    if (pubKey.trim() == '') {
      throw InvalidParameterException('Empty compressed public key string');
    }
    _point = _transformDER(HEX.decode(pubKey), strict);
    if (_point!.isInfinity) {
      throw InvalidPointException(
          'That public key generates point at infinity');
    }
    if (_point!.y!.toBigInteger() == BigInt.zero) {
      throw InvalidPointException('Invalid Y value for this public key');
    }
    _checkIfOnCurve(_point!);
  }

  /// Validates that the DER-encoded hexadecimal string contains a valid
  /// public key.
  ///
  /// [pubKey] - The DER-encoded public key as a hexadecimal string
  ///
  /// Returns *true* if the public key is valid, *false* otherwise.
  static bool isValid(String pubKey) {
    try {
      ZNNPublicKey.fromHex(pubKey);
    } catch (err) {
      return false;
    }
    return true;
  }

  /// Returns the *naked* public key value as either an (x,y) coordinate
  /// or in a compact format using elliptic-curve point-compression.
  ///
  /// With EC point compression it is possible to reduce by half the
  /// space occupied by a point, by taking advantage of a EC-curve property.
  /// Specifically it is possible to recover the `y-coordinate` *IFF* the
  /// `x-coordinate` is known *AND* we know whether the `y-coordinate` is
  /// *odd* or *even*.
  ///
  /// [compressed] - If *true* the 'naked' public key value is returned in
  /// compact format where the first byte is either 'odd' or 'even' followed
  /// by the `x-coordinate`. If *false*, the full *(x,y)* coordinate pair will
  /// be returned.
  ///
  /// NOTE: The first byte will contain either an odd number or an even number,
  /// but this number is *NOT* a boolean flag.
  String getEncoded(bool compressed) {
    return HEX.encode(_point!.getEncoded(compressed));
  }

  /// Returns the 'naked' public key value. Point compression is determined by
  /// the default parameter in the constructor. If you want to enforce a specific preference
  /// for the encoding, you can use the [getEncoded()] function instead.
  @override
  String toString() {
    if (_point == null) {
      return '';
    }
    return HEX.encode(_point!.getEncoded(_point!.isCompressed));
  }

  /// Alias for the [toString()] method.
  String toHex() => toString();

  ECPoint _transformDER(List<int> buf, bool strict) {
    BigInt x;
    BigInt y;
    List<int> xBuf;
    List<int> yBuf;
    ECPoint point;

    if (buf[0] == 0x04 || (!strict && (buf[0] == 0x06 || buf[0] == 0x07))) {
      xBuf = buf.sublist(1, 33);
      yBuf = buf.sublist(33, 65);
      if (xBuf.length != 32 || yBuf.length != 32 || buf.length != 65) {
        throw InvalidPointException('Length of x and y must be 32 bytes');
      }
      x = BigInt.parse(HEX.encode(xBuf), radix: 16);
      y = BigInt.parse(HEX.encode(yBuf), radix: 16);

      point = _domainParams.curve.createPoint(x, y);
    } else if (buf[0] == 0x03 || buf[0] == 0x02) {
      xBuf = buf.sublist(1);
      x = BigInt.parse(HEX.encode(xBuf), radix: 16);

      var yTilde = buf[0] & 1;
      point = _domainParams.curve.decompressPoint(yTilde, x);
    } else {
      throw InvalidPointException('Invalid DER format public key');
    }
    return point;
  }

  ECPoint _getPointFromX(String xValue, bool oddYValue) {
    int prefixByte;
    if (oddYValue) {
      prefixByte = 0x03;
    } else {
      prefixByte = 0x02;
    }

    var encoded = HEX.decode(xValue);
    var addressBytes = List<int?>.filled(1 + encoded.length, null);
    addressBytes[0] = prefixByte;
    addressBytes.setRange(1, addressBytes.length, encoded);

    return _decodePoint(HEX.encode(List<int>.from(addressBytes)));
  }

  ECPoint _decodePoint(String pkHex) {
    if (pkHex.trim() == '') {
      throw InvalidParameterException('Empty compressed public key string');
    }

    var encoded = HEX.decode(pkHex);
    try {
      var point = _domainParams.curve.decodePoint(encoded)!;
      if (point.isCompressed && encoded.length != 33) {
        throw InvalidParameterException(
            'Compressed public keys must be 33 bytes long. Yours is [${encoded.length}]');
      } else if (!point.isCompressed && encoded.length != 65) {
        throw InvalidParameterException(
            'Uncompressed public keys must be 65 bytes long. Yours is [${encoded.length}]');
      }
      _checkIfOnCurve(point);
      return point;
    } on ArgumentError catch (err) {
      throw InvalidPointException(err.message);
    }
  }

  String _compressPoint(ECPoint point) {
    return HEX.encode(point.getEncoded(true));
  }

  bool _checkIfOnCurve(ECPoint point) {
    var x = _domainParams.curve.fromBigInteger(point.x!.toBigInteger()!);
    var alpha =
        (x * ((x * x) + _domainParams.curve.a!)) + _domainParams.curve.b!;
    var beta = alpha.sqrt();
    if (beta == null) {
      throw InvalidPointException('This point is not on the curve');
    }
    var compressedPoint = _compressPoint(point);
    var checkPoint =
        _domainParams.curve.decodePoint(HEX.decode(compressedPoint))!;
    if (checkPoint.y!.toBigInteger() != point.y!.toBigInteger()) {
      throw InvalidPointException('This point is not on the curve');
    }

    return (point.x!.toBigInteger() == BigInt.zero) &&
        (point.y!.toBigInteger() == BigInt.zero);
  }

  /// Returns the (x,y) coordinates of this public key as an [ECPoint].
  /// The author dislikes leaking the wrapped PointyCastle implementation, but is too
  /// lazy to write his own Point implementation.
  ECPoint? get point {
    return _point;
  }

  /// Returns *true* if this public key will render using EC point compression by
  /// default when one calls the [toString()] or [toHex()] methods.
  /// Returns *false* otherwise.
  bool get isCompressed {
    return _point!.isCompressed;
  }
}
