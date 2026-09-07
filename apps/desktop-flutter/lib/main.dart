import 'package:material_ui/material_ui.dart';

import 'app/keylease_app.dart';

export 'app/keylease_app.dart' show KeyLeaseApp;
export 'core/rpc/keylease_rpc.dart'
    show KeyLeaseException, KeyLeaseErrorCode, KeyLeaseRpc;

void main() => runApp(const KeyLeaseApp());
