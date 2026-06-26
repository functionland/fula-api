#
# CocoaPods specification for fula_client
#
# Downloads pre-built XCFramework from GitHub Releases to keep pub.dev package small.
#

Pod::Spec.new do |s|
  s.name             = 'fula_client'
  s.version          = '0.6.18'
  s.summary          = 'Flutter SDK for Fula decentralized storage'
  s.description      = <<-DESC
    A Flutter plugin providing client-side encryption, metadata privacy,
    and secure file sharing for Fula decentralized storage.
  DESC
  s.homepage         = 'https://fx.land'
  s.license          = { :type => 'Apache-2.0', :file => '../LICENSE' }
  s.author           = { 'Functionland' => 'info@fx.land' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'

  s.dependency 'Flutter'
  s.platform = :ios, '12.0'

  # Flutter.framework does not contain a i386 slice
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386'
  }

  # -force_load must be in user_target_xcconfig (not pod_target_xcconfig) because
  # it needs to apply to the main app target that does the final linking.
  # This ensures all FFI symbols are included even if they appear "unused"
  # (they're called from Dart, not from Objective-C/Swift, so linker would strip them)
  # Use SDK-specific paths because XCFramework has different directories for device vs simulator
  s.user_target_xcconfig = {
    'OTHER_LDFLAGS[sdk=iphoneos*]' => '$(inherited) -force_load "${PODS_ROOT}/../.symlinks/plugins/fula_client/ios/Frameworks/FulaFlutter.xcframework/ios-arm64/libfula_flutter.a"',
    'OTHER_LDFLAGS[sdk=iphonesimulator*]' => '$(inherited) -force_load "${PODS_ROOT}/../.symlinks/plugins/fula_client/ios/Frameworks/FulaFlutter.xcframework/ios-arm64_x86_64-simulator/libfula_flutter.a"'
  }
  s.swift_version = '5.0'

  # Download XCFramework from GitHub Releases during pod install
  s.prepare_command = <<-CMD
    curl -L "https://github.com/functionland/fula-api/releases/download/v#{s.version}/ios-libs.zip" -o ios-libs.zip
    unzip -o ios-libs.zip -d .
    rm ios-libs.zip
  CMD

  # Include the downloaded XCFramework
  s.vendored_frameworks = 'Frameworks/FulaFlutter.xcframework'

  # Link required system frameworks
  s.frameworks = 'Security', 'SystemConfiguration'
  s.libraries = 'c++', 'resolv'
end
