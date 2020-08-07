import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:native_add/native_add.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String _platformVersion = 'Unknown';

  @override
  void initState() {
    super.initState();
    initPlatformState();
  }

  // Platform messages are asynchronous, so we initialize in an async method.
  Future<void> initPlatformState() async {
    String platformVersion;
    // Platform messages may fail, so we use a try/catch PlatformException.
    try {
      platformVersion = await NativeAdd.platformVersion;
    } on PlatformException {
      platformVersion = 'Failed to get platform version.';
    }

    // If the widget was removed from the tree while the asynchronous platform
    // message was in flight, we want to discard the reply rather than calling
    // setState to update our non-existent appearance.
    if (!mounted) return;

    setState(() {
      _platformVersion = platformVersion;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: Center(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.center,
            mainAxisAlignment: MainAxisAlignment.center,
            children: <Widget>[
              FlatButton(
                color: Colors.orange,
                onPressed: () async {
                  var res = NativeAdd.encrypt();
                  print(res);
                },
                child: Text('NativeAdd.encrypt()'),
              ),
              FlatButton(
                color: Colors.orange,
                onPressed: () {
                  var res = nativeAdd(1, 2);
                  print(res);
                },
                child: Text('nativeAdd'),
              ),
              FlatButton(
                color: Colors.orange,
                onPressed: () {
                  var res = NativeAdd.add2();
                  print(res);
                },
                child: Text('nativeAdd2'),
              ),
              FlatButton(
                color: Colors.orange,
                onPressed: () {
                  final src = Uint8List.fromList(List.filled(20, 3));
                  print('src = $src');
                  final pointer = transU8List(Uint8Utils.toPointer(src), 20);
                  final result = Uint8Utils.toUint8List(pointer, 20);
                  print('handle src result : $result');
                },
                child: Text('trans'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
