import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart' as path;

typedef _ExportSwapFunc = Pointer<Utf8> Function(
    Pointer<Utf8> walletPath, Pointer<Utf8> passphrase);
typedef _ExportSwap = Pointer<Utf8> Function(
    Pointer<Utf8> walletPath, Pointer<Utf8> passphrase);

_ExportSwapFunc? _exportWalletFunction;

// Loads the dynamic ExportWallet library and maps the required functions.
// Throws if fails.
// Called automatically from `exportSwapFile` if not called in advance.
void initializeExportWallet() {
  var insideSwapUtility =
      path.join('znn_swap_utility', 'lib', 'src', 'export_wallet', 'blobs');
  var currentPathListParts = path.split(Directory.current.path);
  currentPathListParts.removeLast();
  var executablePathListParts = path.split(Platform.resolvedExecutable);
  executablePathListParts.removeLast();
  var possiblePaths = List<String>.empty(growable: true);
  possiblePaths.add(Directory.current.path);
  possiblePaths.add(path.joinAll(executablePathListParts));
  executablePathListParts.removeLast();
  possiblePaths
      .add(path.join(path.joinAll(executablePathListParts), 'Resources'));
  possiblePaths
      .add(path.join(path.joinAll(currentPathListParts), insideSwapUtility));
  possiblePaths.add(path.join(
      path.joinAll(currentPathListParts), 'packages', insideSwapUtility));

  var libraryPath = '';
  var found = false;

  for (var currentPath in possiblePaths) {
    libraryPath = path.join(currentPath, 'libExportWallet.so');

    if (Platform.isMacOS) {
      libraryPath = path.join(currentPath, 'libExportWallet.dylib');
    }
    if (Platform.isWindows) {
      libraryPath = path.join(currentPath, 'libExportWallet.dll');
    }

    var libFile = File(libraryPath);

    if (libFile.existsSync()) {
      found = true;
      break;
    }
  }

  if (!found) {
    throw "Could not find the ExportWallet shared library";
  }

  // Open the dynamic library
  final dylib = DynamicLibrary.open(libraryPath);

  // Look up the CPP function 'exportSwapFile'
  final exportSwapPointer =
      dylib.lookup<NativeFunction<_ExportSwapFunc>>('exportSwapFile');
  _exportWalletFunction = exportSwapPointer.asFunction<_ExportSwap>();
}

class _ExportSwapFunctionArguments {
  final String walletPath;
  final String passphrase;
  final SendPort sendPort;

  _ExportSwapFunctionArguments(this.walletPath, this.passphrase, this.sendPort);
}

void _exportWalletFunc(_ExportSwapFunctionArguments args) {
  initializeExportWallet();

  final Pointer<Utf8> ret = _exportWalletFunction!(
      args.walletPath.toString().toNativeUtf8(),
      args.passphrase.toString().toNativeUtf8());

  var utf8 = ret.toDartString();
  args.sendPort.send(utf8);
}

// if it returns "" then it created wallet.swp otherwise will return the error
Future<String> exportSwapFile(String walletPath, String passphrase) async {
  if (_exportWalletFunction == null) {
    initializeExportWallet();
  }

  final port = ReceivePort();
  final args =
      _ExportSwapFunctionArguments(walletPath, passphrase, port.sendPort);
  Isolate? isolate = await Isolate.spawn<_ExportSwapFunctionArguments>(
      _exportWalletFunc, args,
      onError: port.sendPort, onExit: port.sendPort);
  StreamSubscription? sub;
  var completer = Completer<String>();

  sub = port.listen((data) async {
    if (data != null) {
      var ans = data.toString();
      print(ans);
      completer.complete(ans);
      await sub?.cancel();
      if (isolate != null) {
        isolate!.kill(priority: Isolate.immediate);
        isolate = null;
      }
    }
  });
  return completer.future;
}
