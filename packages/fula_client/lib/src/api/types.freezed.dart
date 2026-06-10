// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'types.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$FulaReadFreshness {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaReadFreshness);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'FulaReadFreshness()';
}


}

/// @nodoc
class $FulaReadFreshnessCopyWith<$Res>  {
$FulaReadFreshnessCopyWith(FulaReadFreshness _, $Res Function(FulaReadFreshness) __);
}


/// Adds pattern-matching-related methods to [FulaReadFreshness].
extension FulaReadFreshnessPatterns on FulaReadFreshness {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( FulaReadFreshness_Live value)?  live,TResult Function( FulaReadFreshness_Cached value)?  cached,TResult Function( FulaReadFreshness_StaleByDesign value)?  staleByDesign,TResult Function( FulaReadFreshness_StaleByOutage value)?  staleByOutage,required TResult orElse(),}){
final _that = this;
switch (_that) {
case FulaReadFreshness_Live() when live != null:
return live(_that);case FulaReadFreshness_Cached() when cached != null:
return cached(_that);case FulaReadFreshness_StaleByDesign() when staleByDesign != null:
return staleByDesign(_that);case FulaReadFreshness_StaleByOutage() when staleByOutage != null:
return staleByOutage(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( FulaReadFreshness_Live value)  live,required TResult Function( FulaReadFreshness_Cached value)  cached,required TResult Function( FulaReadFreshness_StaleByDesign value)  staleByDesign,required TResult Function( FulaReadFreshness_StaleByOutage value)  staleByOutage,}){
final _that = this;
switch (_that) {
case FulaReadFreshness_Live():
return live(_that);case FulaReadFreshness_Cached():
return cached(_that);case FulaReadFreshness_StaleByDesign():
return staleByDesign(_that);case FulaReadFreshness_StaleByOutage():
return staleByOutage(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( FulaReadFreshness_Live value)?  live,TResult? Function( FulaReadFreshness_Cached value)?  cached,TResult? Function( FulaReadFreshness_StaleByDesign value)?  staleByDesign,TResult? Function( FulaReadFreshness_StaleByOutage value)?  staleByOutage,}){
final _that = this;
switch (_that) {
case FulaReadFreshness_Live() when live != null:
return live(_that);case FulaReadFreshness_Cached() when cached != null:
return cached(_that);case FulaReadFreshness_StaleByDesign() when staleByDesign != null:
return staleByDesign(_that);case FulaReadFreshness_StaleByOutage() when staleByOutage != null:
return staleByOutage(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function()?  live,TResult Function( BigInt observedAt)?  cached,TResult Function( BigInt snapshotAgeSecs)?  staleByDesign,TResult Function( BigInt snapshotAgeSecs)?  staleByOutage,required TResult orElse(),}) {final _that = this;
switch (_that) {
case FulaReadFreshness_Live() when live != null:
return live();case FulaReadFreshness_Cached() when cached != null:
return cached(_that.observedAt);case FulaReadFreshness_StaleByDesign() when staleByDesign != null:
return staleByDesign(_that.snapshotAgeSecs);case FulaReadFreshness_StaleByOutage() when staleByOutage != null:
return staleByOutage(_that.snapshotAgeSecs);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function()  live,required TResult Function( BigInt observedAt)  cached,required TResult Function( BigInt snapshotAgeSecs)  staleByDesign,required TResult Function( BigInt snapshotAgeSecs)  staleByOutage,}) {final _that = this;
switch (_that) {
case FulaReadFreshness_Live():
return live();case FulaReadFreshness_Cached():
return cached(_that.observedAt);case FulaReadFreshness_StaleByDesign():
return staleByDesign(_that.snapshotAgeSecs);case FulaReadFreshness_StaleByOutage():
return staleByOutage(_that.snapshotAgeSecs);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function()?  live,TResult? Function( BigInt observedAt)?  cached,TResult? Function( BigInt snapshotAgeSecs)?  staleByDesign,TResult? Function( BigInt snapshotAgeSecs)?  staleByOutage,}) {final _that = this;
switch (_that) {
case FulaReadFreshness_Live() when live != null:
return live();case FulaReadFreshness_Cached() when cached != null:
return cached(_that.observedAt);case FulaReadFreshness_StaleByDesign() when staleByDesign != null:
return staleByDesign(_that.snapshotAgeSecs);case FulaReadFreshness_StaleByOutage() when staleByOutage != null:
return staleByOutage(_that.snapshotAgeSecs);case _:
  return null;

}
}

}

/// @nodoc


class FulaReadFreshness_Live extends FulaReadFreshness {
  const FulaReadFreshness_Live(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaReadFreshness_Live);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'FulaReadFreshness.live()';
}


}




/// @nodoc


class FulaReadFreshness_Cached extends FulaReadFreshness {
  const FulaReadFreshness_Cached({required this.observedAt}): super._();
  

 final  BigInt observedAt;

/// Create a copy of FulaReadFreshness
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaReadFreshness_CachedCopyWith<FulaReadFreshness_Cached> get copyWith => _$FulaReadFreshness_CachedCopyWithImpl<FulaReadFreshness_Cached>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaReadFreshness_Cached&&(identical(other.observedAt, observedAt) || other.observedAt == observedAt));
}


@override
int get hashCode => Object.hash(runtimeType,observedAt);

@override
String toString() {
  return 'FulaReadFreshness.cached(observedAt: $observedAt)';
}


}

/// @nodoc
abstract mixin class $FulaReadFreshness_CachedCopyWith<$Res> implements $FulaReadFreshnessCopyWith<$Res> {
  factory $FulaReadFreshness_CachedCopyWith(FulaReadFreshness_Cached value, $Res Function(FulaReadFreshness_Cached) _then) = _$FulaReadFreshness_CachedCopyWithImpl;
@useResult
$Res call({
 BigInt observedAt
});




}
/// @nodoc
class _$FulaReadFreshness_CachedCopyWithImpl<$Res>
    implements $FulaReadFreshness_CachedCopyWith<$Res> {
  _$FulaReadFreshness_CachedCopyWithImpl(this._self, this._then);

  final FulaReadFreshness_Cached _self;
  final $Res Function(FulaReadFreshness_Cached) _then;

/// Create a copy of FulaReadFreshness
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? observedAt = null,}) {
  return _then(FulaReadFreshness_Cached(
observedAt: null == observedAt ? _self.observedAt : observedAt // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class FulaReadFreshness_StaleByDesign extends FulaReadFreshness {
  const FulaReadFreshness_StaleByDesign({required this.snapshotAgeSecs}): super._();
  

 final  BigInt snapshotAgeSecs;

/// Create a copy of FulaReadFreshness
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaReadFreshness_StaleByDesignCopyWith<FulaReadFreshness_StaleByDesign> get copyWith => _$FulaReadFreshness_StaleByDesignCopyWithImpl<FulaReadFreshness_StaleByDesign>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaReadFreshness_StaleByDesign&&(identical(other.snapshotAgeSecs, snapshotAgeSecs) || other.snapshotAgeSecs == snapshotAgeSecs));
}


@override
int get hashCode => Object.hash(runtimeType,snapshotAgeSecs);

@override
String toString() {
  return 'FulaReadFreshness.staleByDesign(snapshotAgeSecs: $snapshotAgeSecs)';
}


}

/// @nodoc
abstract mixin class $FulaReadFreshness_StaleByDesignCopyWith<$Res> implements $FulaReadFreshnessCopyWith<$Res> {
  factory $FulaReadFreshness_StaleByDesignCopyWith(FulaReadFreshness_StaleByDesign value, $Res Function(FulaReadFreshness_StaleByDesign) _then) = _$FulaReadFreshness_StaleByDesignCopyWithImpl;
@useResult
$Res call({
 BigInt snapshotAgeSecs
});




}
/// @nodoc
class _$FulaReadFreshness_StaleByDesignCopyWithImpl<$Res>
    implements $FulaReadFreshness_StaleByDesignCopyWith<$Res> {
  _$FulaReadFreshness_StaleByDesignCopyWithImpl(this._self, this._then);

  final FulaReadFreshness_StaleByDesign _self;
  final $Res Function(FulaReadFreshness_StaleByDesign) _then;

/// Create a copy of FulaReadFreshness
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? snapshotAgeSecs = null,}) {
  return _then(FulaReadFreshness_StaleByDesign(
snapshotAgeSecs: null == snapshotAgeSecs ? _self.snapshotAgeSecs : snapshotAgeSecs // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class FulaReadFreshness_StaleByOutage extends FulaReadFreshness {
  const FulaReadFreshness_StaleByOutage({required this.snapshotAgeSecs}): super._();
  

 final  BigInt snapshotAgeSecs;

/// Create a copy of FulaReadFreshness
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaReadFreshness_StaleByOutageCopyWith<FulaReadFreshness_StaleByOutage> get copyWith => _$FulaReadFreshness_StaleByOutageCopyWithImpl<FulaReadFreshness_StaleByOutage>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaReadFreshness_StaleByOutage&&(identical(other.snapshotAgeSecs, snapshotAgeSecs) || other.snapshotAgeSecs == snapshotAgeSecs));
}


@override
int get hashCode => Object.hash(runtimeType,snapshotAgeSecs);

@override
String toString() {
  return 'FulaReadFreshness.staleByOutage(snapshotAgeSecs: $snapshotAgeSecs)';
}


}

/// @nodoc
abstract mixin class $FulaReadFreshness_StaleByOutageCopyWith<$Res> implements $FulaReadFreshnessCopyWith<$Res> {
  factory $FulaReadFreshness_StaleByOutageCopyWith(FulaReadFreshness_StaleByOutage value, $Res Function(FulaReadFreshness_StaleByOutage) _then) = _$FulaReadFreshness_StaleByOutageCopyWithImpl;
@useResult
$Res call({
 BigInt snapshotAgeSecs
});




}
/// @nodoc
class _$FulaReadFreshness_StaleByOutageCopyWithImpl<$Res>
    implements $FulaReadFreshness_StaleByOutageCopyWith<$Res> {
  _$FulaReadFreshness_StaleByOutageCopyWithImpl(this._self, this._then);

  final FulaReadFreshness_StaleByOutage _self;
  final $Res Function(FulaReadFreshness_StaleByOutage) _then;

/// Create a copy of FulaReadFreshness
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? snapshotAgeSecs = null,}) {
  return _then(FulaReadFreshness_StaleByOutage(
snapshotAgeSecs: null == snapshotAgeSecs ? _self.snapshotAgeSecs : snapshotAgeSecs // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc
mixin _$FulaReadSource {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaReadSource);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'FulaReadSource()';
}


}

/// @nodoc
class $FulaReadSourceCopyWith<$Res>  {
$FulaReadSourceCopyWith(FulaReadSource _, $Res Function(FulaReadSource) __);
}


/// Adds pattern-matching-related methods to [FulaReadSource].
extension FulaReadSourcePatterns on FulaReadSource {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( FulaReadSource_Master value)?  master,TResult Function( FulaReadSource_LocalCache value)?  localCache,TResult Function( FulaReadSource_Gateway value)?  gateway,required TResult orElse(),}){
final _that = this;
switch (_that) {
case FulaReadSource_Master() when master != null:
return master(_that);case FulaReadSource_LocalCache() when localCache != null:
return localCache(_that);case FulaReadSource_Gateway() when gateway != null:
return gateway(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( FulaReadSource_Master value)  master,required TResult Function( FulaReadSource_LocalCache value)  localCache,required TResult Function( FulaReadSource_Gateway value)  gateway,}){
final _that = this;
switch (_that) {
case FulaReadSource_Master():
return master(_that);case FulaReadSource_LocalCache():
return localCache(_that);case FulaReadSource_Gateway():
return gateway(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( FulaReadSource_Master value)?  master,TResult? Function( FulaReadSource_LocalCache value)?  localCache,TResult? Function( FulaReadSource_Gateway value)?  gateway,}){
final _that = this;
switch (_that) {
case FulaReadSource_Master() when master != null:
return master(_that);case FulaReadSource_LocalCache() when localCache != null:
return localCache(_that);case FulaReadSource_Gateway() when gateway != null:
return gateway(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function()?  master,TResult Function()?  localCache,TResult Function( String field0)?  gateway,required TResult orElse(),}) {final _that = this;
switch (_that) {
case FulaReadSource_Master() when master != null:
return master();case FulaReadSource_LocalCache() when localCache != null:
return localCache();case FulaReadSource_Gateway() when gateway != null:
return gateway(_that.field0);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function()  master,required TResult Function()  localCache,required TResult Function( String field0)  gateway,}) {final _that = this;
switch (_that) {
case FulaReadSource_Master():
return master();case FulaReadSource_LocalCache():
return localCache();case FulaReadSource_Gateway():
return gateway(_that.field0);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function()?  master,TResult? Function()?  localCache,TResult? Function( String field0)?  gateway,}) {final _that = this;
switch (_that) {
case FulaReadSource_Master() when master != null:
return master();case FulaReadSource_LocalCache() when localCache != null:
return localCache();case FulaReadSource_Gateway() when gateway != null:
return gateway(_that.field0);case _:
  return null;

}
}

}

/// @nodoc


class FulaReadSource_Master extends FulaReadSource {
  const FulaReadSource_Master(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaReadSource_Master);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'FulaReadSource.master()';
}


}




/// @nodoc


class FulaReadSource_LocalCache extends FulaReadSource {
  const FulaReadSource_LocalCache(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaReadSource_LocalCache);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'FulaReadSource.localCache()';
}


}




/// @nodoc


class FulaReadSource_Gateway extends FulaReadSource {
  const FulaReadSource_Gateway(this.field0): super._();
  

 final  String field0;

/// Create a copy of FulaReadSource
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FulaReadSource_GatewayCopyWith<FulaReadSource_Gateway> get copyWith => _$FulaReadSource_GatewayCopyWithImpl<FulaReadSource_Gateway>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FulaReadSource_Gateway&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'FulaReadSource.gateway(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $FulaReadSource_GatewayCopyWith<$Res> implements $FulaReadSourceCopyWith<$Res> {
  factory $FulaReadSource_GatewayCopyWith(FulaReadSource_Gateway value, $Res Function(FulaReadSource_Gateway) _then) = _$FulaReadSource_GatewayCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$FulaReadSource_GatewayCopyWithImpl<$Res>
    implements $FulaReadSource_GatewayCopyWith<$Res> {
  _$FulaReadSource_GatewayCopyWithImpl(this._self, this._then);

  final FulaReadSource_Gateway _self;
  final $Res Function(FulaReadSource_Gateway) _then;

/// Create a copy of FulaReadSource
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(FulaReadSource_Gateway(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc
mixin _$MasterHealthEvent {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MasterHealthEvent);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'MasterHealthEvent()';
}


}

/// @nodoc
class $MasterHealthEventCopyWith<$Res>  {
$MasterHealthEventCopyWith(MasterHealthEvent _, $Res Function(MasterHealthEvent) __);
}


/// Adds pattern-matching-related methods to [MasterHealthEvent].
extension MasterHealthEventPatterns on MasterHealthEvent {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( MasterHealthEvent_Online value)?  online,TResult Function( MasterHealthEvent_OfflineFallbackActive value)?  offlineFallbackActive,TResult Function( MasterHealthEvent_SeverelyDegraded value)?  severelyDegraded,required TResult orElse(),}){
final _that = this;
switch (_that) {
case MasterHealthEvent_Online() when online != null:
return online(_that);case MasterHealthEvent_OfflineFallbackActive() when offlineFallbackActive != null:
return offlineFallbackActive(_that);case MasterHealthEvent_SeverelyDegraded() when severelyDegraded != null:
return severelyDegraded(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( MasterHealthEvent_Online value)  online,required TResult Function( MasterHealthEvent_OfflineFallbackActive value)  offlineFallbackActive,required TResult Function( MasterHealthEvent_SeverelyDegraded value)  severelyDegraded,}){
final _that = this;
switch (_that) {
case MasterHealthEvent_Online():
return online(_that);case MasterHealthEvent_OfflineFallbackActive():
return offlineFallbackActive(_that);case MasterHealthEvent_SeverelyDegraded():
return severelyDegraded(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( MasterHealthEvent_Online value)?  online,TResult? Function( MasterHealthEvent_OfflineFallbackActive value)?  offlineFallbackActive,TResult? Function( MasterHealthEvent_SeverelyDegraded value)?  severelyDegraded,}){
final _that = this;
switch (_that) {
case MasterHealthEvent_Online() when online != null:
return online(_that);case MasterHealthEvent_OfflineFallbackActive() when offlineFallbackActive != null:
return offlineFallbackActive(_that);case MasterHealthEvent_SeverelyDegraded() when severelyDegraded != null:
return severelyDegraded(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function()?  online,TResult Function( String reason)?  offlineFallbackActive,TResult Function( String reason)?  severelyDegraded,required TResult orElse(),}) {final _that = this;
switch (_that) {
case MasterHealthEvent_Online() when online != null:
return online();case MasterHealthEvent_OfflineFallbackActive() when offlineFallbackActive != null:
return offlineFallbackActive(_that.reason);case MasterHealthEvent_SeverelyDegraded() when severelyDegraded != null:
return severelyDegraded(_that.reason);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function()  online,required TResult Function( String reason)  offlineFallbackActive,required TResult Function( String reason)  severelyDegraded,}) {final _that = this;
switch (_that) {
case MasterHealthEvent_Online():
return online();case MasterHealthEvent_OfflineFallbackActive():
return offlineFallbackActive(_that.reason);case MasterHealthEvent_SeverelyDegraded():
return severelyDegraded(_that.reason);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function()?  online,TResult? Function( String reason)?  offlineFallbackActive,TResult? Function( String reason)?  severelyDegraded,}) {final _that = this;
switch (_that) {
case MasterHealthEvent_Online() when online != null:
return online();case MasterHealthEvent_OfflineFallbackActive() when offlineFallbackActive != null:
return offlineFallbackActive(_that.reason);case MasterHealthEvent_SeverelyDegraded() when severelyDegraded != null:
return severelyDegraded(_that.reason);case _:
  return null;

}
}

}

/// @nodoc


class MasterHealthEvent_Online extends MasterHealthEvent {
  const MasterHealthEvent_Online(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MasterHealthEvent_Online);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'MasterHealthEvent.online()';
}


}




/// @nodoc


class MasterHealthEvent_OfflineFallbackActive extends MasterHealthEvent {
  const MasterHealthEvent_OfflineFallbackActive({required this.reason}): super._();
  

 final  String reason;

/// Create a copy of MasterHealthEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$MasterHealthEvent_OfflineFallbackActiveCopyWith<MasterHealthEvent_OfflineFallbackActive> get copyWith => _$MasterHealthEvent_OfflineFallbackActiveCopyWithImpl<MasterHealthEvent_OfflineFallbackActive>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MasterHealthEvent_OfflineFallbackActive&&(identical(other.reason, reason) || other.reason == reason));
}


@override
int get hashCode => Object.hash(runtimeType,reason);

@override
String toString() {
  return 'MasterHealthEvent.offlineFallbackActive(reason: $reason)';
}


}

/// @nodoc
abstract mixin class $MasterHealthEvent_OfflineFallbackActiveCopyWith<$Res> implements $MasterHealthEventCopyWith<$Res> {
  factory $MasterHealthEvent_OfflineFallbackActiveCopyWith(MasterHealthEvent_OfflineFallbackActive value, $Res Function(MasterHealthEvent_OfflineFallbackActive) _then) = _$MasterHealthEvent_OfflineFallbackActiveCopyWithImpl;
@useResult
$Res call({
 String reason
});




}
/// @nodoc
class _$MasterHealthEvent_OfflineFallbackActiveCopyWithImpl<$Res>
    implements $MasterHealthEvent_OfflineFallbackActiveCopyWith<$Res> {
  _$MasterHealthEvent_OfflineFallbackActiveCopyWithImpl(this._self, this._then);

  final MasterHealthEvent_OfflineFallbackActive _self;
  final $Res Function(MasterHealthEvent_OfflineFallbackActive) _then;

/// Create a copy of MasterHealthEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? reason = null,}) {
  return _then(MasterHealthEvent_OfflineFallbackActive(
reason: null == reason ? _self.reason : reason // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class MasterHealthEvent_SeverelyDegraded extends MasterHealthEvent {
  const MasterHealthEvent_SeverelyDegraded({required this.reason}): super._();
  

 final  String reason;

/// Create a copy of MasterHealthEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$MasterHealthEvent_SeverelyDegradedCopyWith<MasterHealthEvent_SeverelyDegraded> get copyWith => _$MasterHealthEvent_SeverelyDegradedCopyWithImpl<MasterHealthEvent_SeverelyDegraded>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MasterHealthEvent_SeverelyDegraded&&(identical(other.reason, reason) || other.reason == reason));
}


@override
int get hashCode => Object.hash(runtimeType,reason);

@override
String toString() {
  return 'MasterHealthEvent.severelyDegraded(reason: $reason)';
}


}

/// @nodoc
abstract mixin class $MasterHealthEvent_SeverelyDegradedCopyWith<$Res> implements $MasterHealthEventCopyWith<$Res> {
  factory $MasterHealthEvent_SeverelyDegradedCopyWith(MasterHealthEvent_SeverelyDegraded value, $Res Function(MasterHealthEvent_SeverelyDegraded) _then) = _$MasterHealthEvent_SeverelyDegradedCopyWithImpl;
@useResult
$Res call({
 String reason
});




}
/// @nodoc
class _$MasterHealthEvent_SeverelyDegradedCopyWithImpl<$Res>
    implements $MasterHealthEvent_SeverelyDegradedCopyWith<$Res> {
  _$MasterHealthEvent_SeverelyDegradedCopyWithImpl(this._self, this._then);

  final MasterHealthEvent_SeverelyDegraded _self;
  final $Res Function(MasterHealthEvent_SeverelyDegraded) _then;

/// Create a copy of MasterHealthEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? reason = null,}) {
  return _then(MasterHealthEvent_SeverelyDegraded(
reason: null == reason ? _self.reason : reason // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

// dart format on
