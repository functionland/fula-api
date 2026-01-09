#
# CocoaPods specification for fula_client
#
# This spec packages the pre-built Rust static library for iOS.
# The library is built by the CI/CD pipeline and included in the package.
#

Pod::Spec.new do |s|
  s.name             = 'fula_client'
  s.version          = '0.1.0'
  s.summary          = 'Flutter SDK for Fula decentralized storage'
  s.description      = <<-DESC
    A Flutter plugin providing client-side encryption, metadata privacy,
    and secure file sharing for Fula decentralized storage.
  DESC
  s.homepage         = 'https://fx.land'
  s.license          = { :type => 'MIT', :file => '../LICENSE' }
  s.author           = { 'Functionland' => 'info@fx.land' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'

  s.dependency 'Flutter'
  s.platform = :ios, '12.0'

  # Flutter.framework does not contain a i386 slice
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386',
    'OTHER_LDFLAGS' => '-force_load $(PODS_TARGET_SRCROOT)/libfula_flutter.a'
  }
  s.swift_version = '5.0'

  # Include the pre-built static library
  # Note: The library is still named libfula_flutter.a as it comes from the Rust crate
  s.vendored_libraries = 'libfula_flutter.a'

  # Link required system frameworks
  s.frameworks = 'Security', 'SystemConfiguration'
  s.libraries = 'c++', 'resolv'
end
