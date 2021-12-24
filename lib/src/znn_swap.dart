import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:aes_crypt_null_safe/aes_crypt_null_safe.dart';
import 'package:crypto/crypto.dart';
import 'package:hex/hex.dart';
import 'package:path/path.dart';
import 'package:znn_swap_utility/src/crypto/address.dart';
import 'package:znn_swap_utility/src/crypto/message.dart';
import 'package:znn_swap_utility/src/crypto/pbkdf2.dart';
import 'package:znn_swap_utility/src/crypto/prv_key.dart';
import 'package:znn_swap_utility/src/crypto/pub_key.dart';
import 'package:znn_swap_utility/src/utils/exceptions.dart';

const retrieveLegacyPillarMessage = 'ZNN swap retrieve legacy pillar';
const retrieveAssetsMessage = 'ZNN swap retrieve assets';
const legacyPillarMessageType = 1;
const assetsMessageType = 2;
const checksumLen = 64;
const wifLen = 52;

ZNNPrivateKey _decrypt(String passphrase, String encryptedLegacyPrivateKey) {
  var generator = PBKDF2();
  var salt = 'znn';
  var key = generator.generateKey(passphrase, salt, 120000, 32);
  var iv = generator.generateKey(
      String.fromCharCodes(passphrase.codeUnits.reversed), salt, 120000, 32);

  var crypt = AesCrypt();
  crypt.aesSetKeys(
      Uint8List.fromList(key), Uint8List.fromList(iv).sublist(0, 16));
  crypt.aesSetMode(AesMode.cbc);

  var sourceData = base64.decode(encryptedLegacyPrivateKey);

  // Decrypt the data and extract the private key
  try {
    return ZNNPrivateKey.fromWIF(
        utf8.decode(crypt.aesDecrypt(sourceData)).substring(0, wifLen));
  } catch (exception) {
    throw InvalidKeyException(
        'Invalid decryption passphrase, please check again');
  }
}

class _SignParams {
  int messageType;
  String passphrase;
  String alphanetAddress;

  _SignParams(this.messageType, this.passphrase, this.alphanetAddress);
}

class _SignParamsAsync {
  _SignParams signParams;
  SwapFileEntry swapFileEntry;
  SendPort sendPort;

  _SignParamsAsync(this.signParams, this.swapFileEntry, this.sendPort);
}

class _SignResponse {
  String signature;
  String pubKey;

  _SignResponse(this.signature, this.pubKey);
}

void _signAsyncFunction(_SignParamsAsync signParamsAsync) {
  var signature =
      signParamsAsync.swapFileEntry._sign(signParamsAsync.signParams);
  signParamsAsync.sendPort.send(signature);
}

class SwapFileEntry {
  String address;
  String keyIdHashHex;
  String encryptedPrvKeyB64;
  String pubKeyB64;

  SwapFileEntry._fromEntry(this.address, String pubKeyB64, List<String> content)
      : pubKeyB64 = '',
        encryptedPrvKeyB64 = content[0],
        keyIdHashHex = content[1];

  Map<String, dynamic> toJson() {
    final data = <String, dynamic>{};
    data['address'] = address;
    data['keyIdHashHex'] = keyIdHashHex;
    data['encryptedPubKeyB64'] = encryptedPrvKeyB64;
    data['pubKeyB64'] = pubKeyB64;
    return data;
  }

  List<int> _getMessageAssets(String alphanetAddress) {
    return utf8.encode(
        retrieveAssetsMessage + ' ' + pubKeyB64 + ' ' + alphanetAddress);
  }

  List<int> _getMessageLegacyPillar(String alphanetAddress) {
    return utf8.encode(
        retrieveLegacyPillarMessage + ' ' + pubKeyB64 + ' ' + alphanetAddress);
  }

  Message _getMessage(int type, String alphanetAddress) {
    if (type == assetsMessageType) {
      return Message(_getMessageAssets(alphanetAddress));
    } else {
      return Message(_getMessageLegacyPillar(alphanetAddress));
    }
  }

  _SignResponse _sign(_SignParams signParams) {
    var privateKey = _decrypt(signParams.passphrase, encryptedPrvKeyB64);
    pubKeyB64 =
        base64Encode(HEX.decode(privateKey.publicKey!.getEncoded(false)));
    return _SignResponse(
        _getMessage(signParams.messageType, signParams.alphanetAddress)
            .sign(privateKey),
        pubKeyB64);
  }

  Future<_SignResponse> _signAsync(_SignParams signParams) {
    final port = ReceivePort();
    Isolate.spawn<_SignParamsAsync>(
        _signAsyncFunction, _SignParamsAsync(signParams, this, port.sendPort),
        onError: port.sendPort, onExit: port.sendPort);

    var completer = Completer<_SignResponse>();
    late StreamSubscription sub;

    sub = port.listen((data) async {
      if (data != null) {
        if (data is List<dynamic>) {
          var e = data[0];
          if (e is String &&
              e == 'Invalid decryption passphrase, please check again') {
            completer.completeError(InvalidKeyException(e));
          } else {
            completer.completeError('unknown isolate data $data');
          }
        } else if (data is _SignResponse) {
          pubKeyB64 = data.pubKey;
          completer.complete(data);
        } else {
          completer.completeError('unknown isolate data $data');
        }
        await sub.cancel();
      }
    }, onError: (error) {
      print('Error received: ${error.toString()}');
    });

    return completer.future;
  }

  String signAssets(String passphrase, String alphanetAddress) {
    return _sign(_SignParams(assetsMessageType, passphrase, alphanetAddress))
        .signature;
  }

  String signLegacyPillar(String passphrase, String alphanetAddress) {
    return _sign(
            _SignParams(legacyPillarMessageType, passphrase, alphanetAddress))
        .signature;
  }

  Future<String> signAssetsAsync(
      String passphrase, String alphanetAddress) async {
    return (await _signAsync(
            _SignParams(assetsMessageType, passphrase, alphanetAddress)))
        .signature;
  }

  Future<String> signLegacyPillarAsync(
      String passphrase, String alphanetAddress) async {
    return (await _signAsync(
            _SignParams(legacyPillarMessageType, passphrase, alphanetAddress)))
        .signature;
  }

  void canDecryptWith(String passphrase) {
    try {
      signLegacyPillar(passphrase, '');
    } catch (e) {
      rethrow;
    }
  }

  Future<void> canDecryptWithAsync(String passphrase) async {
    try {
      await signLegacyPillarAsync(passphrase, '');
    } catch (e) {
      rethrow;
    }
  }
}

/// [parseLegacyJson] interprets the verified json-content into a [List<SwapFileEntry>]
List<SwapFileEntry> _parseLegacyJson(Map<dynamic, dynamic> legacyJson) {
  var result = List.empty(growable: true);

  legacyJson.forEach((key, content) {
    var address = Address.fromHex(
        ZNNPublicKey.fromHex(HEX.encode(base64.decode(key))).getEncoded(true));
    result.add(SwapFileEntry._fromEntry(
        address.toString(), key, List<String>.from(content)));
  });

  return List<SwapFileEntry>.from(result);
}

/// Reads and parses a wallet-swap-file.
/// Checks if the checksum at the end of the file is valid.
/// Returns a list of all the entries.
Future<List<SwapFileEntry>> readSwapFile(String swapWalletPath) async {
  var swapWallet = File(swapWalletPath);

  if (extension(swapWallet.path) == '.swp') {
  } else {
    throw InvalidParameterException('The file must have the extension swp');
  }

  if (swapWallet.existsSync()) {
    var fileData = (await swapWallet.readAsString()).trim();
    var extractedHash = fileData.substring(fileData.length - checksumLen);
    var jsonData = fileData.substring(0, fileData.length - checksumLen);
    var hash = sha256.convert(utf8.encode(jsonData)).toString();
    if (jsonData.isNotEmpty && extractedHash == hash) {
      var parsedJson = json.decode(jsonData) as Map;
      return _parseLegacyJson(parsedJson);
    } else {
      throw InvalidChecksumException('Invalid swap wallet checksum');
    }
  } else {
    throw InvalidPathException(
        'The swap wallet cannot be found at the following path ' +
            swapWallet.path);
  }
}
