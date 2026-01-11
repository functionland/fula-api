#
# CocoaPods specification for fula_client
#
# This spec packages the pre-built Rust XCFramework for iOS.
# The library is built by the CI/CD pipeline and included in the package.
#

Pod::Spec.new do |s|
  s.name             = 'fula_client'
  s.version          = '0.2.2'
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
  s.swift_version = '5.0'

  # Include the pre-built XCFramework (supports device + simulator)
  s.vendored_frameworks = 'Frameworks/FulaFlutter.xcframework'

  # Link required system frameworks
  s.frameworks = 'Security', 'SystemConfiguration'
  s.libraries = 'c++', 'resolv'
end
