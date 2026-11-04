'use strict';
// Trimmed but format-faithful `dumpsys package` samples (Android 11-14 style).
function dump({ pkg = 'com.example.app', flags = 'HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP', minSdk = 23, targetSdk = 33, extra = '' } = {}) {
    return `Activity Resolver Table:
  Non-Data Actions:
      android.intent.action.MAIN:
        3f2a1b5 ${pkg}/.MainActivity filter 1c2d3e4
          Action: "android.intent.action.MAIN"
          Category: "android.intent.category.LAUNCHER"
  Schemes:
      myapp:
        a1b2c3d ${pkg}/.DeepLinkActivity filter d4e5f60
          Action: "android.intent.action.VIEW"
          Category: "android.intent.category.DEFAULT"
          Category: "android.intent.category.BROWSABLE"
          Scheme: "myapp"
          Authority: "open": -1
      https:
        a1b2c3d ${pkg}/.DeepLinkActivity filter 77aa881
          Action: "android.intent.action.VIEW"
          Category: "android.intent.category.BROWSABLE"
          Scheme: "https"
          Authority: "example.com": -1
Receiver Resolver Table:
  Non-Data Actions:
      com.example.ACTION_SYNC:
        9f9f9f9 ${pkg}/.SyncReceiver filter 5555555
          Action: "com.example.ACTION_SYNC"
        8e8e8e8 ${pkg}/.ProtectedReceiver filter 6666666 permission android.permission.BIND_JOB_SERVICE
          Action: "com.example.PROTECTED"
Service Resolver Table:
  Non-Data Actions:
      com.example.SERVICE:
        7d7d7d7 ${pkg}/.SyncService filter 4444444
          Action: "com.example.SERVICE"
        6c6c6c6 com.other.lib/.ForeignService filter 3333333
          Action: "com.other.lib.SERVICE"
Registered ContentProviders:
  ${pkg}/.DataProvider:
    Provider{abcdef ${pkg}/.DataProvider}
ContentProvider Authorities:
  [${pkg}.provider]:
    Provider{abcdef ${pkg}/.DataProvider}
Packages:
  Package [${pkg}] (deadbeef):
    userId=10234
    codePath=/data/app/~~xyz==/${pkg}-abc==
    versionCode=42 minSdk=${minSdk} targetSdk=${targetSdk}
    versionName=1.4.2
    flags=[ ${flags} ]
    privateFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE ]
    dataDir=/data/user/0/${pkg}
    firstInstallTime=2024-01-02 10:00:00
    lastUpdateTime=2024-03-04 11:30:00
    installerPackageName=com.android.vending
    signatures=PackageSignatures{1a2b3c4 version:3, signatures:[5d6e7f8], past signatures:[]}
    requested permissions:
      android.permission.CAMERA
      android.permission.INTERNET
    install permissions:
      android.permission.INTERNET: granted=true
    User 0: ceDataInode=1234 installed=true hidden=false
      runtime permissions:
        android.permission.CAMERA: granted=true, flags=[ USER_SET ]
        android.permission.ACCESS_FINE_LOCATION: granted=true, flags=[ USER_SET ]
        android.permission.READ_CONTACTS: granted=false, flags=[ USER_SET ]
${extra}`;
}
module.exports = { dump };
