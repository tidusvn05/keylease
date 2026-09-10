import 'dart:convert';
import 'dart:ffi';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

// The C surface of crates/keylease-mobile. Kept deliberately small: requests
// and responses are the same JSON the desktop socket carries, dispatched by the
// same Rust code, so the two transports cannot answer differently.

typedef _OpenNative =
    Uint64 Function(Pointer<Uint8>, IntPtr, Pointer<Pointer<Uint8>>, Pointer<IntPtr>);
typedef _OpenDart =
    int Function(Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<IntPtr>);

typedef _CallNative =
    Int32 Function(
      Uint64,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
    );
typedef _CallDart =
    int Function(
      int,
      Pointer<Uint8>,
      int,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
    );

typedef _HandleNative = Int32 Function(Uint64);
typedef _HandleDart = int Function(int);

typedef _FreeNative = Void Function(Pointer<Uint8>, IntPtr);
typedef _FreeDart = void Function(Pointer<Uint8>, int);

/// Raised when the library reports it produced no response at all.
///
/// Distinct from a protocol error, which arrives as an ordinary
/// `{"ok":false,...}` envelope.
class KeyLeaseFfiFailure implements Exception {
  const KeyLeaseFfiFailure(this.operation);

  final String operation;

  @override
  String toString() => 'The vault library failed during $operation.';
}

/// Direct bindings. Runs on whichever thread calls it.
///
/// Do not use from the UI isolate: unlocking runs Argon2id over 64 MiB and
/// takes roughly half a second to two seconds on a phone. See [VaultIsolate].
class KeyLeaseFfi {
  KeyLeaseFfi(DynamicLibrary library)
    : _open = library.lookupFunction<_OpenNative, _OpenDart>('keylease_open'),
      _call = library.lookupFunction<_CallNative, _CallDart>('keylease_call'),
      _provision = library.lookupFunction<_CallNative, _CallDart>(
        'keylease_provision',
      ),
      _lock = library.lookupFunction<_HandleNative, _HandleDart>(
        'keylease_lock',
      ),
      _close = library.lookupFunction<_HandleNative, _HandleDart>(
        'keylease_close',
      ),
      _free = library.lookupFunction<_FreeNative, _FreeDart>('keylease_free');

  factory KeyLeaseFfi.open() =>
      KeyLeaseFfi(DynamicLibrary.open('libkeylease_mobile.so'));

  final _OpenDart _open;
  final _CallDart _call;
  final _CallDart _provision;
  final _HandleDart _lock;
  final _HandleDart _close;
  final _FreeDart _free;

  int _handle = 0;

  bool get isOpen => _handle != 0;

  /// Opens the vault at [databasePath] and returns the response envelope.
  Map<String, dynamic> openVault(String databasePath) {
    final bytes = utf8.encode(databasePath);
    final input = calloc<Uint8>(bytes.length);
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<IntPtr>();
    try {
      input.asTypedList(bytes.length).setAll(0, bytes);
      _handle = _open(input, bytes.length, outPtr, outLen);
      return _takeResponse(outPtr, outLen, 'open');
    } finally {
      calloc.free(input);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  Map<String, dynamic> call(Map<String, dynamic> request) =>
      _send(_call, request, 'call');

  Map<String, dynamic> provision(Map<String, dynamic> request) =>
      _send(_provision, request, 'provision');

  void lock() {
    if (_handle != 0) _lock(_handle);
  }

  void close() {
    if (_handle == 0) return;
    _close(_handle);
    _handle = 0;
  }

  Map<String, dynamic> _send(
    _CallDart fn,
    Map<String, dynamic> request,
    String operation,
  ) {
    final bytes = utf8.encode(jsonEncode(request));
    final input = calloc<Uint8>(bytes.length);
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<IntPtr>();
    try {
      input.asTypedList(bytes.length).setAll(0, bytes);
      final status = fn(_handle, input, bytes.length, outPtr, outLen);
      if (status != 0) throw KeyLeaseFfiFailure(operation);
      return _takeResponse(outPtr, outLen, operation);
    } finally {
      // The request may carry a master password: overwrite the native copy
      // before releasing it rather than leaving it in freed memory.
      input.asTypedList(bytes.length).fillRange(0, bytes.length, 0);
      calloc.free(input);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  Map<String, dynamic> _takeResponse(
    Pointer<Pointer<Uint8>> outPtr,
    Pointer<IntPtr> outLen,
    String operation,
  ) {
    final buffer = outPtr.value;
    final length = outLen.value;
    if (buffer == nullptr || length == 0) throw KeyLeaseFfiFailure(operation);
    try {
      final decoded = jsonDecode(utf8.decode(buffer.asTypedList(length)));
      if (decoded is! Map<String, dynamic>) {
        throw KeyLeaseFfiFailure(operation);
      }
      return decoded;
    } finally {
      // Zeroises before deallocating; see keylease_free.
      _free(buffer, length);
    }
  }
}

/// Requests sent to the worker isolate.
enum _Op { open, call, provision, lock, close }

class _Request {
  const _Request(this.id, this.op, this.payload);
  final int id;
  final _Op op;
  final Object? payload;
}

class _Response {
  const _Response(this.id, this.value, this.error);
  final int id;
  final Map<String, dynamic>? value;
  final Object? error;
}

/// Owns the vault on a worker isolate.
///
/// Every FFI call blocks its calling thread — `keylease_call` runs the Rust
/// dispatch to completion — so they must not run on the UI isolate. One
/// long-lived worker also matches the store's real concurrency: `NativeStore`
/// is a single mutex, so there is nothing to gain from more.
class VaultIsolate {
  VaultIsolate._(this._send, this._responses, this._isolate);

  final SendPort _send;
  final Stream<_Response> _responses;
  final Isolate _isolate;
  int _nextId = 1;

  static Future<VaultIsolate> spawn() async {
    final ready = ReceivePort();
    final isolate = await Isolate.spawn(_worker, ready.sendPort);
    final broadcast = ready.asBroadcastStream();
    final send = await broadcast.first as SendPort;
    return VaultIsolate._(
      send,
      broadcast.where((m) => m is _Response).cast<_Response>(),
      isolate,
    );
  }

  Future<Map<String, dynamic>> openVault(String databasePath) =>
      _dispatch(_Op.open, databasePath);

  Future<Map<String, dynamic>> call(Map<String, dynamic> request) =>
      _dispatch(_Op.call, request);

  Future<Map<String, dynamic>> provision(Map<String, dynamic> request) =>
      _dispatch(_Op.provision, request);

  Future<void> lock() => _dispatch(_Op.lock, null);

  Future<void> dispose() async {
    await _dispatch(_Op.close, null);
    _isolate.kill(priority: Isolate.immediate);
  }

  Future<Map<String, dynamic>> _dispatch(_Op op, Object? payload) async {
    final id = _nextId++;
    _send.send(_Request(id, op, payload));
    final response = await _responses.firstWhere((r) => r.id == id);
    if (response.error case final error?) throw error;
    return response.value ?? const {};
  }

  static void _worker(SendPort ready) {
    final port = ReceivePort();
    ready.send(port.sendPort);
    final ffi = KeyLeaseFfi.open();

    port.listen((message) {
      final request = message as _Request;
      try {
        final value = switch (request.op) {
          _Op.open => ffi.openVault(request.payload! as String),
          _Op.call => ffi.call(request.payload! as Map<String, dynamic>),
          _Op.provision => ffi.provision(
            request.payload! as Map<String, dynamic>,
          ),
          _Op.lock => (() {
            ffi.lock();
            return <String, dynamic>{};
          })(),
          _Op.close => (() {
            ffi.close();
            return <String, dynamic>{};
          })(),
        };
        ready.send(_Response(request.id, value, null));
      } catch (error) {
        ready.send(_Response(request.id, null, error));
      }
    });
  }
}
