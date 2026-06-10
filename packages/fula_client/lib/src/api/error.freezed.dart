// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'error.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$FulaError {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'FulaError()';
}


}

/// @nodoc
class $FulaErrorCopyWith<$Res>  {
$FulaErrorCopyWith(FulaError _, $Res Function(FulaError) __);
}


/// Adds pattern-matching-related methods to [FulaError].
extension FulaErrorPatterns on FulaError {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( FulaError_Network value)?  network,TResult Function( FulaError_NotFound value)?  notFound,TResult Function( FulaError_BucketNotFound value)?  bucketNotFound,TResult Function( FulaError_AccessDenied value)?  accessDenied,TResult Function( FulaError_Encryption value)?  encryption,TResult Function( FulaError_InvalidConfig value)?  invalidConfig,TResult Function( FulaError_UploadFailed value)?  uploadFailed,TResult Function( FulaError_DownloadFailed value)?  downloadFailed,TResult Function( FulaError_XmlParse value)?  xmlParse,TResult Function( FulaError_InvalidResponse value)?  invalidResponse,TResult Function( FulaError_ShareError value)?  shareError,TResult Function( FulaError_RotationError value)?  rotationError,TResult Function( FulaError_ForestError value)?  forestError,TResult Function( FulaError_CacheBudgetExceeded value)?  cacheBudgetExceeded,TResult Function( FulaError_CacheError value)?  cacheError,TResult Function( FulaError_UsersIndexResolutionFailed value)?  usersIndexResolutionFailed,TResult Function( FulaError_WireVersionUnsupported value)?  wireVersionUnsupported,TResult Function( FulaError_SequenceRegression value)?  sequenceRegression,TResult Function( FulaError_Internal value)?  internal,TResult Function( FulaError_Cancelled value)?  cancelled,required TResult orElse(),}){
final _that = this;
switch (_that) {
case FulaError_Network() when network != null:
return network(_that);case FulaError_NotFound() when notFound != null:
return notFound(_that);case FulaError_BucketNotFound() when bucketNotFound != null:
return bucketNotFound(_that);case FulaError_AccessDenied() when accessDenied != null:
return accessDenied(_that);case FulaError_Encryption() when encryption != null:
return encryption(_that);case FulaError_InvalidConfig() when invalidConfig != null:
return invalidConfig(_that);case FulaError_UploadFailed() when uploadFailed != null:
return uploadFailed(_that);case FulaError_DownloadFailed() when downloadFailed != null:
return downloadFailed(_that);case FulaError_XmlParse() when xmlParse != null:
return xmlParse(_that);case FulaError_InvalidResponse() when invalidResponse != null:
return invalidResponse(_that);case FulaError_ShareError() when shareError != null:
return shareError(_that);case FulaError_RotationError() when rotationError != null:
return rotationError(_that);case FulaError_ForestError() when forestError != null:
return forestError(_that);case FulaError_CacheBudgetExceeded() when cacheBudgetExceeded != null:
return cacheBudgetExceeded(_that);case FulaError_CacheError() when cacheError != null:
return cacheError(_that);case FulaError_UsersIndexResolutionFailed() when usersIndexResolutionFailed != null:
return usersIndexResolutionFailed(_that);case FulaError_WireVersionUnsupported() when wireVersionUnsupported != null:
return wireVersionUnsupported(_that);case FulaError_SequenceRegression() when sequenceRegression != null:
return sequenceRegression(_that);case FulaError_Internal() when internal != null:
return internal(_that);case FulaError_Cancelled() when cancelled != null:
return cancelled(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( FulaError_Network value)  network,required TResult Function( FulaError_NotFound value)  notFound,required TResult Function( FulaError_BucketNotFound value)  bucketNotFound,required TResult Function( FulaError_AccessDenied value)  accessDenied,required TResult Function( FulaError_Encryption value)  encryption,required TResult Function( FulaError_InvalidConfig value)  invalidConfig,required TResult Function( FulaError_UploadFailed value)  uploadFailed,required TResult Function( FulaError_DownloadFailed value)  downloadFailed,required TResult Function( FulaError_XmlParse value)  xmlParse,required TResult Function( FulaError_InvalidResponse value)  invalidResponse,required TResult Function( FulaError_ShareError value)  shareError,required TResult Function( FulaError_RotationError value)  rotationError,required TResult Function( FulaError_ForestError value)  forestError,required TResult Function( FulaError_CacheBudgetExceeded value)  cacheBudgetExceeded,required TResult Function( FulaError_CacheError value)  cacheError,required TResult Function( FulaError_UsersIndexResolutionFailed value)  usersIndexResolutionFailed,required TResult Function( FulaError_WireVersionUnsupported value)  wireVersionUnsupported,required TResult Function( FulaError_SequenceRegression value)  sequenceRegression,required TResult Function( FulaError_Internal value)  internal,required TResult Function( FulaError_Cancelled value)  cancelled,}){
final _that = this;
switch (_that) {
case FulaError_Network():
return network(_that);case FulaError_NotFound():
return notFound(_that);case FulaError_BucketNotFound():
return bucketNotFound(_that);case FulaError_AccessDenied():
return accessDenied(_that);case FulaError_Encryption():
return encryption(_that);case FulaError_InvalidConfig():
return invalidConfig(_that);case FulaError_UploadFailed():
return uploadFailed(_that);case FulaError_DownloadFailed():
return downloadFailed(_that);case FulaError_XmlParse():
return xmlParse(_that);case FulaError_InvalidResponse():
return invalidResponse(_that);case FulaError_ShareError():
return shareError(_that);case FulaError_RotationError():
return rotationError(_that);case FulaError_ForestError():
return forestError(_that);case FulaError_CacheBudgetExceeded():
return cacheBudgetExceeded(_that);case FulaError_CacheError():
return cacheError(_that);case FulaError_UsersIndexResolutionFailed():
return usersIndexResolutionFailed(_that);case FulaError_WireVersionUnsupported():
return wireVersionUnsupported(_that);case FulaError_SequenceRegression():
return sequenceRegression(_that);case FulaError_Internal():
return internal(_that);case FulaError_Cancelled():
return cancelled(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( FulaError_Network value)?  network,TResult? Function( FulaError_NotFound value)?  notFound,TResult? Function( FulaError_BucketNotFound value)?  bucketNotFound,TResult? Function( FulaError_AccessDenied value)?  accessDenied,TResult? Function( FulaError_Encryption value)?  encryption,TResult? Function( FulaError_InvalidConfig value)?  invalidConfig,TResult? Function( FulaError_UploadFailed value)?  uploadFailed,TResult? Function( FulaError_DownloadFailed value)?  downloadFailed,TResult? Function( FulaError_XmlParse value)?  xmlParse,TResult? Function( FulaError_InvalidResponse value)?  invalidResponse,TResult? Function( FulaError_ShareError value)?  shareError,TResult? Function( FulaError_RotationError value)?  rotationError,TResult? Function( FulaError_ForestError value)?  forestError,TResult? Function( FulaError_CacheBudgetExceeded value)?  cacheBudgetExceeded,TResult? Function( FulaError_CacheError value)?  cacheError,TResult? Function( FulaError_UsersIndexResolutionFailed value)?  usersIndexResolutionFailed,TResult? Function( FulaError_WireVersionUnsupported value)?  wireVersionUnsupported,TResult? Function( FulaError_SequenceRegression value)?  sequenceRegression,TResult? Function( FulaError_Internal value)?  internal,TResult? Function( FulaError_Cancelled value)?  cancelled,}){
final _that = this;
switch (_that) {
case FulaError_Network() when network != null:
return network(_that);case FulaError_NotFound() when notFound != null:
return notFound(_that);case FulaError_BucketNotFound() when bucketNotFound != null:
return bucketNotFound(_that);case FulaError_AccessDenied() when accessDenied != null:
return accessDenied(_that);case FulaError_Encryption() when encryption != null:
return encryption(_that);case FulaError_InvalidConfig() when invalidConfig != null:
return invalidConfig(_that);case FulaError_UploadFailed() when uploadFailed != null:
return uploadFailed(_that);case FulaError_DownloadFailed() when downloadFailed != null:
return downloadFailed(_that);case FulaError_XmlParse() when xmlParse != null:
return xmlParse(_that);case FulaError_InvalidResponse() when invalidResponse != null:
return invalidResponse(_that);case FulaError_ShareError() when shareError != null:
return shareError(_that);case FulaError_RotationError() when rotationError != null:
return rotationError(_that);case FulaError_ForestError() when forestError != null:
return forestError(_that);case FulaError_CacheBudgetExceeded() when cacheBudgetExceeded != null:
return cacheBudgetExceeded(_that);case FulaError_CacheError() when cacheError != null:
return cacheError(_that);case FulaError_UsersIndexResolutionFailed() when usersIndexResolutionFailed != null:
return usersIndexResolutionFailed(_that);case FulaError_WireVersionUnsupported() when wireVersionUnsupported != null:
return wireVersionUnsupported(_that);case FulaError_SequenceRegression() when sequenceRegression != null:
return sequenceRegression(_that);case FulaError_Internal() when internal != null:
return internal(_that);case FulaError_Cancelled() when cancelled != null:
return cancelled(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( String field0)?  network,TResult Function( String bucket,  String key)?  notFound,TResult Function( String field0)?  bucketNotFound,TResult Function( String field0)?  accessDenied,TResult Function( String field0)?  encryption,TResult Function( String field0)?  invalidConfig,TResult Function( String field0)?  uploadFailed,TResult Function( String field0)?  downloadFailed,TResult Function( String field0)?  xmlParse,TResult Function( String field0)?  invalidResponse,TResult Function( String field0)?  shareError,TResult Function( String field0)?  rotationError,TResult Function( String field0)?  forestError,TResult Function( BigInt size,  BigInt budget)?  cacheBudgetExceeded,TResult Function( String field0)?  cacheError,TResult Function( String field0)?  usersIndexResolutionFailed,TResult Function( String context,  String postcardError)?  wireVersionUnsupported,TResult Function( BigInt observed,  BigInt highestSeen,  String channel)?  sequenceRegression,TResult Function( String field0)?  internal,TResult Function()?  cancelled,required TResult orElse(),}) {final _that = this;
switch (_that) {
case FulaError_Network() when network != null:
return network(_that.field0);case FulaError_NotFound() when notFound != null:
return notFound(_that.bucket,_that.key);case FulaError_BucketNotFound() when bucketNotFound != null:
return bucketNotFound(_that.field0);case FulaError_AccessDenied() when accessDenied != null:
return accessDenied(_that.field0);case FulaError_Encryption() when encryption != null:
return encryption(_that.field0);case FulaError_InvalidConfig() when invalidConfig != null:
return invalidConfig(_that.field0);case FulaError_UploadFailed() when uploadFailed != null:
return uploadFailed(_that.field0);case FulaError_DownloadFailed() when downloadFailed != null:
return downloadFailed(_that.field0);case FulaError_XmlParse() when xmlParse != null:
return xmlParse(_that.field0);case FulaError_InvalidResponse() when invalidResponse != null:
return invalidResponse(_that.field0);case FulaError_ShareError() when shareError != null:
return shareError(_that.field0);case FulaError_RotationError() when rotationError != null:
return rotationError(_that.field0);case FulaError_ForestError() when forestError != null:
return forestError(_that.field0);case FulaError_CacheBudgetExceeded() when cacheBudgetExceeded != null:
return cacheBudgetExceeded(_that.size,_that.budget);case FulaError_CacheError() when cacheError != null:
return cacheError(_that.field0);case FulaError_UsersIndexResolutionFailed() when usersIndexResolutionFailed != null:
return usersIndexResolutionFailed(_that.field0);case FulaError_WireVersionUnsupported() when wireVersionUnsupported != null:
return wireVersionUnsupported(_that.context,_that.postcardError);case FulaError_SequenceRegression() when sequenceRegression != null:
return sequenceRegression(_that.observed,_that.highestSeen,_that.channel);case FulaError_Internal() when internal != null:
return internal(_that.field0);case FulaError_Cancelled() when cancelled != null:
return cancelled();case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( String field0)  network,required TResult Function( String bucket,  String key)  notFound,required TResult Function( String field0)  bucketNotFound,required TResult Function( String field0)  accessDenied,required TResult Function( String field0)  encryption,required TResult Function( String field0)  invalidConfig,required TResult Function( String field0)  uploadFailed,required TResult Function( String field0)  downloadFailed,required TResult Function( String field0)  xmlParse,required TResult Function( String field0)  invalidResponse,required TResult Function( String field0)  shareError,required TResult Function( String field0)  rotationError,required TResult Function( String field0)  forestError,required TResult Function( BigInt size,  BigInt budget)  cacheBudgetExceeded,required TResult Function( String field0)  cacheError,required TResult Function( String field0)  usersIndexResolutionFailed,required TResult Function( String context,  String postcardError)  wireVersionUnsupported,required TResult Function( BigInt observed,  BigInt highestSeen,  String channel)  sequenceRegression,required TResult Function( String field0)  internal,required TResult Function()  cancelled,}) {final _that = this;
switch (_that) {
case FulaError_Network():
return network(_that.field0);case FulaError_NotFound():
return notFound(_that.bucket,_that.key);case FulaError_BucketNotFound():
return bucketNotFound(_that.field0);case FulaError_AccessDenied():
return accessDenied(_that.field0);case FulaError_Encryption():
return encryption(_that.field0);case FulaError_InvalidConfig():
return invalidConfig(_that.field0);case FulaError_UploadFailed():
return uploadFailed(_that.field0);case FulaError_DownloadFailed():
return downloadFailed(_that.field0);case FulaError_XmlParse():
return xmlParse(_that.field0);case FulaError_InvalidResponse():
return invalidResponse(_that.field0);case FulaError_ShareError():
return shareError(_that.field0);case FulaError_RotationError():
return rotationError(_that.field0);case FulaError_ForestError():
return forestError(_that.field0);case FulaError_CacheBudgetExceeded():
return cacheBudgetExceeded(_that.size,_that.budget);case FulaError_CacheError():
return cacheError(_that.field0);case FulaError_UsersIndexResolutionFailed():
return usersIndexResolutionFailed(_that.field0);case FulaError_WireVersionUnsupported():
return wireVersionUnsupported(_that.context,_that.postcardError);case FulaError_SequenceRegression():
return sequenceRegression(_that.observed,_that.highestSeen,_that.channel);case FulaError_Internal():
return internal(_that.field0);case FulaError_Cancelled():
return cancelled();}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( String field0)?  network,TResult? Function( String bucket,  String key)?  notFound,TResult? Function( String field0)?  bucketNotFound,TResult? Function( String field0)?  accessDenied,TResult? Function( String field0)?  encryption,TResult? Function( String field0)?  invalidConfig,TResult? Function( String field0)?  uploadFailed,TResult? Function( String field0)?  downloadFailed,TResult? Function( String field0)?  xmlParse,TResult? Function( String field0)?  invalidResponse,TResult? Function( String field0)?  shareError,TResult? Function( String field0)?  rotationError,TResult? Function( String field0)?  forestError,TResult? Function( BigInt size,  BigInt budget)?  cacheBudgetExceeded,TResult? Function( String field0)?  cacheError,TResult? Function( String field0)?  usersIndexResolutionFailed,TResult? Function( String context,  String postcardError)?  wireVersionUnsupported,TResult? Function( BigInt observed,  BigInt highestSeen,  String channel)?  sequenceRegression,TResult? Function( String field0)?  internal,TResult? Function()?  cancelled,}) {final _that = this;
switch (_that) {
case FulaError_Network() when network != null:
return network(_that.field0);case FulaError_NotFound() when notFound != null:
return notFound(_that.bucket,_that.key);case FulaError_BucketNotFound() when bucketNotFound != null:
return bucketNotFound(_that.field0);case FulaError_AccessDenied() when accessDenied != null:
return accessDenied(_that.field0);case FulaError_Encryption() when encryption != null:
return encryption(_that.field0);case FulaError_InvalidConfig() when invalidConfig != null:
return invalidConfig(_that.field0);case FulaError_UploadFailed() when uploadFailed != null:
return uploadFailed(_that.field0);case FulaError_DownloadFailed() when downloadFailed != null:
return downloadFailed(_that.field0);case FulaError_XmlParse() when xmlParse != null:
return xmlParse(_that.field0);case FulaError_InvalidResponse() when invalidResponse != null:
return invalidResponse(_that.field0);case FulaError_ShareError() when shareError != null:
return shareError(_that.field0);case FulaError_RotationError() when rotationError != null:
return rotationError(_that.field0);case FulaError_ForestError() when forestError != null:
return forestError(_that.field0);case FulaError_CacheBudgetExceeded() when cacheBudgetExceeded != null:
return cacheBudgetExceeded(_that.size,_that.budget);case FulaError_CacheError() when cacheError != null:
return cacheError(_that.field0);case FulaError_UsersIndexResolutionFailed() when usersIndexResolutionFailed != null:
return usersIndexResolutionFailed(_that.field0);case FulaError_WireVersionUnsupported() when wireVersionUnsupported != null:
return wireVersionUnsupported(_that.context,_that.postcardError);case FulaError_SequenceRegression() when sequenceRegression != null:
return sequenceRegression(_that.observed,_that.highestSeen,_that.channel);case FulaError_Internal() when internal != null:
return internal(_that.field0);case FulaError_Cancelled() when cancelled != null:
return cancelled();case _:
  return null;

}
}

}

/// @nodoc


class FulaError_Network extends FulaError {
  const FulaError_Network(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_NetworkCopyWith<FulaError_Network> get copyWith => _$FulaError_NetworkCopyWithImpl<FulaError_Network>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_Network&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.network(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_NetworkCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_NetworkCopyWith(FulaError_Network value, $Res Function(FulaError_Network) _then) = _$FulaError_NetworkCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_NetworkCopyWithImpl<$Res>
    implements $FulaError_NetworkCopyWith<$Res> {
  _$FulaError_NetworkCopyWithImpl(this._self, this._then);

  final FulaError_Network _self;
  final $Res Function(FulaError_Network) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_Network(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_NotFound extends FulaError {
  const FulaError_NotFound({required this.bucket, required this.key}): super._();
  

 final  String bucket;
 final  String key;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_NotFoundCopyWith<FulaError_NotFound> get copyWith => _$FulaError_NotFoundCopyWithImpl<FulaError_NotFound>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_NotFound&&(identical(other.bucket, bucket) || other.bucket == bucket)&&(identical(other.key, key) || other.key == key));
}


@override
int get hashCode => Object.hash(runtimeType,bucket,key);

@override
String toString() {
  return 'FulaError.notFound(bucket: $bucket, key: $key)';
}


}

/// @nodoc
abstract mixin class $FulaError_NotFoundCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_NotFoundCopyWith(FulaError_NotFound value, $Res Function(FulaError_NotFound) _then) = _$FulaError_NotFoundCopyWithImpl;
@useResult
$Res call({
 String bucket, String key
});




}
/// @nodoc
class _$FulaError_NotFoundCopyWithImpl<$Res>
    implements $FulaError_NotFoundCopyWith<$Res> {
  _$FulaError_NotFoundCopyWithImpl(this._self, this._then);

  final FulaError_NotFound _self;
  final $Res Function(FulaError_NotFound) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? bucket = null,Object? key = null,}) {
  return _then(FulaError_NotFound(
bucket: null == bucket ? _self.bucket : bucket // ignore: cast_nullable_to_non_nullable
as String,key: null == key ? _self.key : key // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_BucketNotFound extends FulaError {
  const FulaError_BucketNotFound(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_BucketNotFoundCopyWith<FulaError_BucketNotFound> get copyWith => _$FulaError_BucketNotFoundCopyWithImpl<FulaError_BucketNotFound>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_BucketNotFound&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.bucketNotFound(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_BucketNotFoundCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_BucketNotFoundCopyWith(FulaError_BucketNotFound value, $Res Function(FulaError_BucketNotFound) _then) = _$FulaError_BucketNotFoundCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_BucketNotFoundCopyWithImpl<$Res>
    implements $FulaError_BucketNotFoundCopyWith<$Res> {
  _$FulaError_BucketNotFoundCopyWithImpl(this._self, this._then);

  final FulaError_BucketNotFound _self;
  final $Res Function(FulaError_BucketNotFound) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_BucketNotFound(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_AccessDenied extends FulaError {
  const FulaError_AccessDenied(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_AccessDeniedCopyWith<FulaError_AccessDenied> get copyWith => _$FulaError_AccessDeniedCopyWithImpl<FulaError_AccessDenied>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_AccessDenied&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.accessDenied(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_AccessDeniedCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_AccessDeniedCopyWith(FulaError_AccessDenied value, $Res Function(FulaError_AccessDenied) _then) = _$FulaError_AccessDeniedCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_AccessDeniedCopyWithImpl<$Res>
    implements $FulaError_AccessDeniedCopyWith<$Res> {
  _$FulaError_AccessDeniedCopyWithImpl(this._self, this._then);

  final FulaError_AccessDenied _self;
  final $Res Function(FulaError_AccessDenied) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_AccessDenied(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_Encryption extends FulaError {
  const FulaError_Encryption(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_EncryptionCopyWith<FulaError_Encryption> get copyWith => _$FulaError_EncryptionCopyWithImpl<FulaError_Encryption>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_Encryption&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.encryption(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_EncryptionCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_EncryptionCopyWith(FulaError_Encryption value, $Res Function(FulaError_Encryption) _then) = _$FulaError_EncryptionCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_EncryptionCopyWithImpl<$Res>
    implements $FulaError_EncryptionCopyWith<$Res> {
  _$FulaError_EncryptionCopyWithImpl(this._self, this._then);

  final FulaError_Encryption _self;
  final $Res Function(FulaError_Encryption) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_Encryption(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_InvalidConfig extends FulaError {
  const FulaError_InvalidConfig(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_InvalidConfigCopyWith<FulaError_InvalidConfig> get copyWith => _$FulaError_InvalidConfigCopyWithImpl<FulaError_InvalidConfig>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_InvalidConfig&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.invalidConfig(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_InvalidConfigCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_InvalidConfigCopyWith(FulaError_InvalidConfig value, $Res Function(FulaError_InvalidConfig) _then) = _$FulaError_InvalidConfigCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_InvalidConfigCopyWithImpl<$Res>
    implements $FulaError_InvalidConfigCopyWith<$Res> {
  _$FulaError_InvalidConfigCopyWithImpl(this._self, this._then);

  final FulaError_InvalidConfig _self;
  final $Res Function(FulaError_InvalidConfig) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_InvalidConfig(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_UploadFailed extends FulaError {
  const FulaError_UploadFailed(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_UploadFailedCopyWith<FulaError_UploadFailed> get copyWith => _$FulaError_UploadFailedCopyWithImpl<FulaError_UploadFailed>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_UploadFailed&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.uploadFailed(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_UploadFailedCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_UploadFailedCopyWith(FulaError_UploadFailed value, $Res Function(FulaError_UploadFailed) _then) = _$FulaError_UploadFailedCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_UploadFailedCopyWithImpl<$Res>
    implements $FulaError_UploadFailedCopyWith<$Res> {
  _$FulaError_UploadFailedCopyWithImpl(this._self, this._then);

  final FulaError_UploadFailed _self;
  final $Res Function(FulaError_UploadFailed) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_UploadFailed(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_DownloadFailed extends FulaError {
  const FulaError_DownloadFailed(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_DownloadFailedCopyWith<FulaError_DownloadFailed> get copyWith => _$FulaError_DownloadFailedCopyWithImpl<FulaError_DownloadFailed>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_DownloadFailed&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.downloadFailed(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_DownloadFailedCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_DownloadFailedCopyWith(FulaError_DownloadFailed value, $Res Function(FulaError_DownloadFailed) _then) = _$FulaError_DownloadFailedCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_DownloadFailedCopyWithImpl<$Res>
    implements $FulaError_DownloadFailedCopyWith<$Res> {
  _$FulaError_DownloadFailedCopyWithImpl(this._self, this._then);

  final FulaError_DownloadFailed _self;
  final $Res Function(FulaError_DownloadFailed) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_DownloadFailed(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_XmlParse extends FulaError {
  const FulaError_XmlParse(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_XmlParseCopyWith<FulaError_XmlParse> get copyWith => _$FulaError_XmlParseCopyWithImpl<FulaError_XmlParse>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_XmlParse&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.xmlParse(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_XmlParseCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_XmlParseCopyWith(FulaError_XmlParse value, $Res Function(FulaError_XmlParse) _then) = _$FulaError_XmlParseCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_XmlParseCopyWithImpl<$Res>
    implements $FulaError_XmlParseCopyWith<$Res> {
  _$FulaError_XmlParseCopyWithImpl(this._self, this._then);

  final FulaError_XmlParse _self;
  final $Res Function(FulaError_XmlParse) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_XmlParse(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_InvalidResponse extends FulaError {
  const FulaError_InvalidResponse(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_InvalidResponseCopyWith<FulaError_InvalidResponse> get copyWith => _$FulaError_InvalidResponseCopyWithImpl<FulaError_InvalidResponse>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_InvalidResponse&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.invalidResponse(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_InvalidResponseCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_InvalidResponseCopyWith(FulaError_InvalidResponse value, $Res Function(FulaError_InvalidResponse) _then) = _$FulaError_InvalidResponseCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_InvalidResponseCopyWithImpl<$Res>
    implements $FulaError_InvalidResponseCopyWith<$Res> {
  _$FulaError_InvalidResponseCopyWithImpl(this._self, this._then);

  final FulaError_InvalidResponse _self;
  final $Res Function(FulaError_InvalidResponse) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_InvalidResponse(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_ShareError extends FulaError {
  const FulaError_ShareError(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_ShareErrorCopyWith<FulaError_ShareError> get copyWith => _$FulaError_ShareErrorCopyWithImpl<FulaError_ShareError>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_ShareError&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.shareError(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_ShareErrorCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_ShareErrorCopyWith(FulaError_ShareError value, $Res Function(FulaError_ShareError) _then) = _$FulaError_ShareErrorCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_ShareErrorCopyWithImpl<$Res>
    implements $FulaError_ShareErrorCopyWith<$Res> {
  _$FulaError_ShareErrorCopyWithImpl(this._self, this._then);

  final FulaError_ShareError _self;
  final $Res Function(FulaError_ShareError) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_ShareError(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_RotationError extends FulaError {
  const FulaError_RotationError(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_RotationErrorCopyWith<FulaError_RotationError> get copyWith => _$FulaError_RotationErrorCopyWithImpl<FulaError_RotationError>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_RotationError&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.rotationError(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_RotationErrorCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_RotationErrorCopyWith(FulaError_RotationError value, $Res Function(FulaError_RotationError) _then) = _$FulaError_RotationErrorCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_RotationErrorCopyWithImpl<$Res>
    implements $FulaError_RotationErrorCopyWith<$Res> {
  _$FulaError_RotationErrorCopyWithImpl(this._self, this._then);

  final FulaError_RotationError _self;
  final $Res Function(FulaError_RotationError) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_RotationError(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_ForestError extends FulaError {
  const FulaError_ForestError(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_ForestErrorCopyWith<FulaError_ForestError> get copyWith => _$FulaError_ForestErrorCopyWithImpl<FulaError_ForestError>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_ForestError&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.forestError(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_ForestErrorCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_ForestErrorCopyWith(FulaError_ForestError value, $Res Function(FulaError_ForestError) _then) = _$FulaError_ForestErrorCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_ForestErrorCopyWithImpl<$Res>
    implements $FulaError_ForestErrorCopyWith<$Res> {
  _$FulaError_ForestErrorCopyWithImpl(this._self, this._then);

  final FulaError_ForestError _self;
  final $Res Function(FulaError_ForestError) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_ForestError(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_CacheBudgetExceeded extends FulaError {
  const FulaError_CacheBudgetExceeded({required this.size, required this.budget}): super._();
  

 final  BigInt size;
 final  BigInt budget;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_CacheBudgetExceededCopyWith<FulaError_CacheBudgetExceeded> get copyWith => _$FulaError_CacheBudgetExceededCopyWithImpl<FulaError_CacheBudgetExceeded>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_CacheBudgetExceeded&&(identical(other.size, size) || other.size == size)&&(identical(other.budget, budget) || other.budget == budget));
}


@override
int get hashCode => Object.hash(runtimeType,size,budget);

@override
String toString() {
  return 'FulaError.cacheBudgetExceeded(size: $size, budget: $budget)';
}


}

/// @nodoc
abstract mixin class $FulaError_CacheBudgetExceededCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_CacheBudgetExceededCopyWith(FulaError_CacheBudgetExceeded value, $Res Function(FulaError_CacheBudgetExceeded) _then) = _$FulaError_CacheBudgetExceededCopyWithImpl;
@useResult
$Res call({
 BigInt size, BigInt budget
});




}
/// @nodoc
class _$FulaError_CacheBudgetExceededCopyWithImpl<$Res>
    implements $FulaError_CacheBudgetExceededCopyWith<$Res> {
  _$FulaError_CacheBudgetExceededCopyWithImpl(this._self, this._then);

  final FulaError_CacheBudgetExceeded _self;
  final $Res Function(FulaError_CacheBudgetExceeded) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? size = null,Object? budget = null,}) {
  return _then(FulaError_CacheBudgetExceeded(
size: null == size ? _self.size : size // ignore: cast_nullable_to_non_nullable
as BigInt,budget: null == budget ? _self.budget : budget // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class FulaError_CacheError extends FulaError {
  const FulaError_CacheError(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_CacheErrorCopyWith<FulaError_CacheError> get copyWith => _$FulaError_CacheErrorCopyWithImpl<FulaError_CacheError>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_CacheError&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.cacheError(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_CacheErrorCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_CacheErrorCopyWith(FulaError_CacheError value, $Res Function(FulaError_CacheError) _then) = _$FulaError_CacheErrorCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_CacheErrorCopyWithImpl<$Res>
    implements $FulaError_CacheErrorCopyWith<$Res> {
  _$FulaError_CacheErrorCopyWithImpl(this._self, this._then);

  final FulaError_CacheError _self;
  final $Res Function(FulaError_CacheError) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_CacheError(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_UsersIndexResolutionFailed extends FulaError {
  const FulaError_UsersIndexResolutionFailed(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_UsersIndexResolutionFailedCopyWith<FulaError_UsersIndexResolutionFailed> get copyWith => _$FulaError_UsersIndexResolutionFailedCopyWithImpl<FulaError_UsersIndexResolutionFailed>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_UsersIndexResolutionFailed&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.usersIndexResolutionFailed(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_UsersIndexResolutionFailedCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_UsersIndexResolutionFailedCopyWith(FulaError_UsersIndexResolutionFailed value, $Res Function(FulaError_UsersIndexResolutionFailed) _then) = _$FulaError_UsersIndexResolutionFailedCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_UsersIndexResolutionFailedCopyWithImpl<$Res>
    implements $FulaError_UsersIndexResolutionFailedCopyWith<$Res> {
  _$FulaError_UsersIndexResolutionFailedCopyWithImpl(this._self, this._then);

  final FulaError_UsersIndexResolutionFailed _self;
  final $Res Function(FulaError_UsersIndexResolutionFailed) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_UsersIndexResolutionFailed(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_WireVersionUnsupported extends FulaError {
  const FulaError_WireVersionUnsupported({required this.context, required this.postcardError}): super._();
  

 final  String context;
 final  String postcardError;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_WireVersionUnsupportedCopyWith<FulaError_WireVersionUnsupported> get copyWith => _$FulaError_WireVersionUnsupportedCopyWithImpl<FulaError_WireVersionUnsupported>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_WireVersionUnsupported&&(identical(other.context, context) || other.context == context)&&(identical(other.postcardError, postcardError) || other.postcardError == postcardError));
}


@override
int get hashCode => Object.hash(runtimeType,context,postcardError);

@override
String toString() {
  return 'FulaError.wireVersionUnsupported(context: $context, postcardError: $postcardError)';
}


}

/// @nodoc
abstract mixin class $FulaError_WireVersionUnsupportedCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_WireVersionUnsupportedCopyWith(FulaError_WireVersionUnsupported value, $Res Function(FulaError_WireVersionUnsupported) _then) = _$FulaError_WireVersionUnsupportedCopyWithImpl;
@useResult
$Res call({
 String context, String postcardError
});




}
/// @nodoc
class _$FulaError_WireVersionUnsupportedCopyWithImpl<$Res>
    implements $FulaError_WireVersionUnsupportedCopyWith<$Res> {
  _$FulaError_WireVersionUnsupportedCopyWithImpl(this._self, this._then);

  final FulaError_WireVersionUnsupported _self;
  final $Res Function(FulaError_WireVersionUnsupported) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? context = null,Object? postcardError = null,}) {
  return _then(FulaError_WireVersionUnsupported(
context: null == context ? _self.context : context // ignore: cast_nullable_to_non_nullable
as String,postcardError: null == postcardError ? _self.postcardError : postcardError // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_SequenceRegression extends FulaError {
  const FulaError_SequenceRegression({required this.observed, required this.highestSeen, required this.channel}): super._();
  

 final  BigInt observed;
 final  BigInt highestSeen;
 final  String channel;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_SequenceRegressionCopyWith<FulaError_SequenceRegression> get copyWith => _$FulaError_SequenceRegressionCopyWithImpl<FulaError_SequenceRegression>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_SequenceRegression&&(identical(other.observed, observed) || other.observed == observed)&&(identical(other.highestSeen, highestSeen) || other.highestSeen == highestSeen)&&(identical(other.channel, channel) || other.channel == channel));
}


@override
int get hashCode => Object.hash(runtimeType,observed,highestSeen,channel);

@override
String toString() {
  return 'FulaError.sequenceRegression(observed: $observed, highestSeen: $highestSeen, channel: $channel)';
}


}

/// @nodoc
abstract mixin class $FulaError_SequenceRegressionCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_SequenceRegressionCopyWith(FulaError_SequenceRegression value, $Res Function(FulaError_SequenceRegression) _then) = _$FulaError_SequenceRegressionCopyWithImpl;
@useResult
$Res call({
 BigInt observed, BigInt highestSeen, String channel
});




}
/// @nodoc
class _$FulaError_SequenceRegressionCopyWithImpl<$Res>
    implements $FulaError_SequenceRegressionCopyWith<$Res> {
  _$FulaError_SequenceRegressionCopyWithImpl(this._self, this._then);

  final FulaError_SequenceRegression _self;
  final $Res Function(FulaError_SequenceRegression) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? observed = null,Object? highestSeen = null,Object? channel = null,}) {
  return _then(FulaError_SequenceRegression(
observed: null == observed ? _self.observed : observed // ignore: cast_nullable_to_non_nullable
as BigInt,highestSeen: null == highestSeen ? _self.highestSeen : highestSeen // ignore: cast_nullable_to_non_nullable
as BigInt,channel: null == channel ? _self.channel : channel // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_Internal extends FulaError {
  const FulaError_Internal(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaError_InternalCopyWith<FulaError_Internal> get copyWith => _$FulaError_InternalCopyWithImpl<FulaError_Internal>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_Internal&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaError.internal(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaError_InternalCopyWith<$Res> implements $FulaErrorCopyWith<$Res> {
  factory $FulaError_InternalCopyWith(FulaError_Internal value, $Res Function(FulaError_Internal) _then) = _$FulaError_InternalCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaError_InternalCopyWithImpl<$Res>
    implements $FulaError_InternalCopyWith<$Res> {
  _$FulaError_InternalCopyWithImpl(this._self, this._then);

  final FulaError_Internal _self;
  final $Res Function(FulaError_Internal) _then;

/// Create a copy of FulaError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaError_Internal(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FulaError_Cancelled extends FulaError {
  const FulaError_Cancelled(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaError_Cancelled);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'FulaError.cancelled()';
}


}




// dart format on
