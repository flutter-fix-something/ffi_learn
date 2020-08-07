import 'dart:async';
import 'dart:typed_data';
import 'package:flutter/services.dart';
import 'dart:ffi'; // For FFI
import 'dart:io'; // For Platform.isX
import 'package:ffi/ffi.dart' show Utf8, allocate;

final DynamicLibrary nativeAddLib = Platform.isAndroid
    ? DynamicLibrary.open("libnative_add.so")
    : DynamicLibrary.process();

typedef NativeAddFunc = Int32 Function(Int32, Int32);
typedef AddFunc = int Function(int, int);

typedef NativeAddFunc2 = Pointer<Utf8> Function(Pointer<Utf8>, Int32);
typedef AddFunc2 = Pointer<Utf8> Function(Pointer<Utf8>, int);

// OK
final AddFunc nativeAdd = nativeAddLib
    .lookup<NativeFunction<NativeAddFunc>>("native_add")
    .asFunction();

// 找不到方法
final AddFunc2 nativeAdd2 =
    nativeAddLib.lookup<NativeFunction<NativeAddFunc2>>("reverse").asFunction();

typedef U8ListTrans = Pointer<Uint8> Function(Pointer<Uint8>, Int32);
typedef TransFunc = Pointer<Uint8> Function(Pointer<Uint8>, int);

final TransFunc transU8List = nativeAddLib
    .lookup<NativeFunction<U8ListTrans>>('u8List_trans')
    .asFunction();

class Uint8Utils extends Struct {
  static Pointer<Uint8> toPointer(Uint8List uint8list) {
    final Pointer<Uint8> result = allocate<Uint8>(count: uint8list.length);
    final Uint8List buffer = result.asTypedList(uint8list.length + 1);
    for (var i = 0; i < uint8list.length; i++) {
      buffer[i] = uint8list[i];
    }
    return result;
  }

  static Uint8List toUint8List(Pointer<Uint8> pointer, int length) {
    final buffer = pointer.asTypedList(length);
    return Uint8List.fromList(buffer);
  }
}

typedef EncryptFunc = int Function(
  Pointer<Utf8> key,
  Pointer<Utf8> nonce,
  Pointer<Utf8> adata,
  int adataLen,
  Pointer<Utf8> payload,
  int payloadLen,
  int micLen,
  Pointer<Utf8> outbuf,
);

typedef NativeEncryptFunc = Int64 Function(
  Pointer<Utf8> key,
  Pointer<Utf8> nonce,
  Pointer<Utf8> adata,
  Int64 adataLen,
  Pointer<Utf8> payload,
  Int64 payloadLen,
  Int64 micLen,
  Pointer<Utf8> outbuf,
);

final aesCcmEncryptPointer =
    nativeAddLib.lookup<NativeFunction<NativeEncryptFunc>>(
  "aes_ccm_encrypt",
);

final EncryptFunc aesCcmEncrypt = aesCcmEncryptPointer.asFunction();

class NativeAdd {
  static const MethodChannel _channel = const MethodChannel('native_add');

  static Future<String> get platformVersion async {
    final String version = await _channel.invokeMethod('getPlatformVersion');
    return version;
  }

  static int encrypt() {
    if (aesCcmEncrypt == null) {
      return -999;
    }
    var res = aesCcmEncrypt(
      Utf8.toUtf8('1234124'),
      Utf8.toUtf8('124124'),
      Utf8.toUtf8('123123'),
      12,
      Utf8.toUtf8('123123'),
      12,
      12,
      Utf8.toUtf8('123123'),
    );

    return res;
  }

  static String add2() {
    var res = nativeAdd2?.call(Utf8.toUtf8('string'), 3);

    return Utf8.fromUtf8(res);
  }
}
