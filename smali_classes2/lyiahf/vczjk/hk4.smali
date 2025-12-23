.class public abstract Llyiahf/vczjk/hk4;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0o0:Llyiahf/vczjk/qt5;


# instance fields
.field public OooO00o:Llyiahf/vczjk/dm5;

.field public final OooO0O0:Llyiahf/vczjk/o45;

.field public final OooO0OO:Llyiahf/vczjk/l45;

.field public final OooO0Oo:Llyiahf/vczjk/q45;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "<built-ins module>"

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/hk4;->OooO0o0:Llyiahf/vczjk/qt5;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/q45;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/hk4;->OooO0Oo:Llyiahf/vczjk/q45;

    new-instance v0, Llyiahf/vczjk/fk4;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/fk4;-><init>(Llyiahf/vczjk/hk4;I)V

    invoke-virtual {p1, v0}, Llyiahf/vczjk/q45;->OooO00o(Llyiahf/vczjk/le3;)Llyiahf/vczjk/o45;

    new-instance v0, Llyiahf/vczjk/fk4;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/fk4;-><init>(Llyiahf/vczjk/hk4;I)V

    new-instance v1, Llyiahf/vczjk/o45;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v1, p0, Llyiahf/vczjk/hk4;->OooO0O0:Llyiahf/vczjk/o45;

    new-instance v0, Llyiahf/vczjk/go;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/go;-><init>(Llyiahf/vczjk/hk4;I)V

    invoke-virtual {p1, v0}, Llyiahf/vczjk/q45;->OooO0O0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/l45;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/hk4;->OooO0OO:Llyiahf/vczjk/l45;

    return-void
.end method

.method public static synthetic OooO00o(I)V
    .locals 23

    move/from16 v0, p0

    const/16 v1, 0x57

    const/16 v2, 0x56

    const/16 v3, 0x54

    const/16 v4, 0x51

    const/16 v5, 0x4a

    const/16 v6, 0x45

    const/16 v7, 0xf

    const/16 v8, 0xd

    const/16 v9, 0xb

    if-eq v0, v9, :cond_0

    if-eq v0, v8, :cond_0

    if-eq v0, v7, :cond_0

    if-eq v0, v6, :cond_0

    if-eq v0, v5, :cond_0

    if-eq v0, v4, :cond_0

    if-eq v0, v3, :cond_0

    if-eq v0, v2, :cond_0

    if-eq v0, v1, :cond_0

    packed-switch v0, :pswitch_data_0

    packed-switch v0, :pswitch_data_1

    packed-switch v0, :pswitch_data_2

    packed-switch v0, :pswitch_data_3

    const-string v10, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    goto :goto_0

    :cond_0
    :pswitch_0
    const-string v10, "@NotNull method %s.%s must not return null"

    :goto_0
    const/4 v11, 0x2

    if-eq v0, v9, :cond_1

    if-eq v0, v8, :cond_1

    if-eq v0, v7, :cond_1

    if-eq v0, v6, :cond_1

    if-eq v0, v5, :cond_1

    if-eq v0, v4, :cond_1

    if-eq v0, v3, :cond_1

    if-eq v0, v2, :cond_1

    if-eq v0, v1, :cond_1

    packed-switch v0, :pswitch_data_4

    packed-switch v0, :pswitch_data_5

    packed-switch v0, :pswitch_data_6

    packed-switch v0, :pswitch_data_7

    const/4 v12, 0x3

    goto :goto_1

    :cond_1
    :pswitch_1
    move v12, v11

    :goto_1
    new-array v12, v12, [Ljava/lang/Object;

    const-string v13, "kotlin/reflect/jvm/internal/impl/builtins/KotlinBuiltIns"

    const/4 v14, 0x0

    packed-switch v0, :pswitch_data_8

    const-string v15, "storageManager"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_2
    const-string v15, "declarationDescriptor"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_3
    const-string v15, "classDescriptor"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_4
    const-string v15, "typeConstructor"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_5
    const-string v15, "annotations"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_6
    const-string v15, "argument"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_7
    const-string v15, "projectionType"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_8
    const-string v15, "kotlinType"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_9
    const-string v15, "primitiveType"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_a
    const-string v15, "notNullArrayType"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_b
    const-string v15, "arrayType"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_c
    const-string v15, "classSimpleName"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_d
    const-string v15, "type"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_e
    const-string v15, "simpleName"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_f
    const-string v15, "fqName"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_10
    const-string v15, "descriptor"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_11
    aput-object v13, v12, v14

    goto :goto_2

    :pswitch_12
    const-string v15, "computation"

    aput-object v15, v12, v14

    goto :goto_2

    :pswitch_13
    const-string v15, "module"

    aput-object v15, v12, v14

    :goto_2
    const-string v14, "getBuiltInClassByFqName"

    const-string v15, "getBuiltInClassByName"

    const-string v16, "getBuiltInTypeByClassName"

    const-string v17, "getPrimitiveKotlinType"

    const-string v18, "getArrayElementType"

    const-string v19, "getPrimitiveArrayKotlinType"

    const-string v20, "getArrayType"

    const-string v21, "getEnumType"

    const/16 v22, 0x1

    if-eq v0, v9, :cond_9

    if-eq v0, v8, :cond_8

    if-eq v0, v7, :cond_7

    if-eq v0, v6, :cond_6

    if-eq v0, v5, :cond_5

    if-eq v0, v4, :cond_4

    if-eq v0, v3, :cond_4

    if-eq v0, v2, :cond_3

    if-eq v0, v1, :cond_2

    packed-switch v0, :pswitch_data_9

    packed-switch v0, :pswitch_data_a

    packed-switch v0, :pswitch_data_b

    packed-switch v0, :pswitch_data_c

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_14
    const-string v13, "getIterableType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_15
    const-string v13, "getStringType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_16
    const-string v13, "getUnitType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_17
    const-string v13, "getBooleanType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_18
    const-string v13, "getCharType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_19
    const-string v13, "getDoubleType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_1a
    const-string v13, "getFloatType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_1b
    const-string v13, "getLongType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_1c
    const-string v13, "getIntType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_1d
    const-string v13, "getShortType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_1e
    const-string v13, "getByteType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_1f
    const-string v13, "getNumberType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_20
    aput-object v17, v12, v22

    goto/16 :goto_3

    :pswitch_21
    const-string v13, "getDefaultBound"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_22
    const-string v13, "getNullableAnyType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_23
    const-string v13, "getAnyType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_24
    const-string v13, "getNullableNothingType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_25
    const-string v13, "getNothingType"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_26
    aput-object v16, v12, v22

    goto/16 :goto_3

    :pswitch_27
    const-string v13, "getMutableListIterator"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_28
    const-string v13, "getListIterator"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_29
    const-string v13, "getMutableMapEntry"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_2a
    const-string v13, "getMapEntry"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_2b
    const-string v13, "getMutableMap"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_2c
    const-string v13, "getMap"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_2d
    const-string v13, "getMutableSet"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_2e
    const-string v13, "getSet"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_2f
    const-string v13, "getMutableList"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_30
    const-string v13, "getList"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_31
    const-string v13, "getMutableCollection"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_32
    const-string v13, "getCollection"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_33
    const-string v13, "getMutableIterator"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_34
    const-string v13, "getMutableIterable"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_35
    const-string v13, "getIterable"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_36
    const-string v13, "getIterator"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_37
    const-string v13, "getKMutableProperty2"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_38
    const-string v13, "getKMutableProperty1"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_39
    const-string v13, "getKMutableProperty0"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_3a
    const-string v13, "getKProperty2"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_3b
    const-string v13, "getKProperty1"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_3c
    const-string v13, "getKProperty0"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_3d
    const-string v13, "getKProperty"

    aput-object v13, v12, v22

    goto/16 :goto_3

    :pswitch_3e
    const-string v13, "getKCallable"

    aput-object v13, v12, v22

    goto :goto_3

    :pswitch_3f
    const-string v13, "getKType"

    aput-object v13, v12, v22

    goto :goto_3

    :pswitch_40
    const-string v13, "getKClass"

    aput-object v13, v12, v22

    goto :goto_3

    :pswitch_41
    const-string v13, "getKSuspendFunction"

    aput-object v13, v12, v22

    goto :goto_3

    :pswitch_42
    const-string v13, "getKFunction"

    aput-object v13, v12, v22

    goto :goto_3

    :pswitch_43
    const-string v13, "getSuspendFunction"

    aput-object v13, v12, v22

    goto :goto_3

    :pswitch_44
    const-string v13, "getBuiltInPackagesImportedByDefault"

    aput-object v13, v12, v22

    goto :goto_3

    :pswitch_45
    const-string v13, "getBuiltInsModule"

    aput-object v13, v12, v22

    goto :goto_3

    :pswitch_46
    const-string v13, "getStorageManager"

    aput-object v13, v12, v22

    goto :goto_3

    :pswitch_47
    const-string v13, "getClassDescriptorFactories"

    aput-object v13, v12, v22

    goto :goto_3

    :pswitch_48
    const-string v13, "getPlatformDependentDeclarationFilter"

    aput-object v13, v12, v22

    goto :goto_3

    :pswitch_49
    const-string v13, "getAdditionalClassPartsProvider"

    aput-object v13, v12, v22

    goto :goto_3

    :cond_2
    const-string v13, "getAnnotationType"

    aput-object v13, v12, v22

    goto :goto_3

    :cond_3
    aput-object v21, v12, v22

    goto :goto_3

    :cond_4
    aput-object v20, v12, v22

    goto :goto_3

    :cond_5
    aput-object v19, v12, v22

    goto :goto_3

    :cond_6
    aput-object v18, v12, v22

    goto :goto_3

    :cond_7
    aput-object v15, v12, v22

    goto :goto_3

    :cond_8
    aput-object v14, v12, v22

    goto :goto_3

    :cond_9
    const-string v13, "getBuiltInsPackageScope"

    aput-object v13, v12, v22

    :goto_3
    packed-switch v0, :pswitch_data_d

    const-string v13, "<init>"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_4a
    const-string v13, "isNotNullOrNullableFunctionSupertype"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_4b
    const-string v13, "isDeprecated"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_4c
    const-string v13, "isNonPrimitiveArray"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_4d
    const-string v13, "isKClass"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_4e
    const-string v13, "isThrowable"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_4f
    const-string v13, "isThrowableOrNullableThrowable"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_50
    const-string v13, "isIterableOrNullableIterable"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_51
    const-string v13, "isMapOrNullableMap"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_52
    const-string v13, "isSetOrNullableSet"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_53
    const-string v13, "isListOrNullableList"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_54
    const-string v13, "isCollectionOrNullableCollection"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_55
    const-string v13, "isComparable"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_56
    const-string v13, "isEnum"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_57
    const-string v13, "isMemberOfAny"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_58
    const-string v13, "isBooleanOrSubtype"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_59
    const-string v13, "isUnitOrNullableUnit"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_5a
    const-string v13, "mayReturnNonUnitValue"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_5b
    const-string v13, "isUnit"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_5c
    const-string v13, "isDefaultBound"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_5d
    const-string v13, "isNullableAny"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_5e
    const-string v13, "isAnyOrNullableAny"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_5f
    const-string v13, "isNothingOrNullableNothing"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_60
    const-string v13, "isNullableNothing"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_61
    const-string v13, "isNothing"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_62
    const-string v13, "isConstructedFromGivenClassAndNotNullable"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_63
    const-string v13, "isDoubleOrNullableDouble"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_64
    const-string v13, "isUnsignedArrayType"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_65
    const-string v13, "isULongArray"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_66
    const-string v13, "isUIntArray"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_67
    const-string v13, "isUShortArray"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_68
    const-string v13, "isUByteArray"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_69
    const-string v13, "isULong"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_6a
    const-string v13, "isUInt"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_6b
    const-string v13, "isUShort"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_6c
    const-string v13, "isUByte"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_6d
    const-string v13, "isDouble"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_6e
    const-string v13, "isFloatOrNullableFloat"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_6f
    const-string v13, "isFloat"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_70
    const-string v13, "isShort"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_71
    const-string v13, "isLongOrNullableLong"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_72
    const-string v13, "isLong"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_73
    const-string v13, "isByte"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_74
    const-string v13, "isInt"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_75
    const-string v13, "isCharOrNullableChar"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_76
    const-string v13, "isChar"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_77
    const-string v13, "isNumber"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_78
    const-string v13, "isBooleanOrNullableBoolean"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_79
    const-string v13, "isBoolean"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_7a
    const-string v13, "isAny"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_7b
    const-string v13, "isSpecialClassWithNoSupertypes"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_7c
    const-string v13, "isNotNullConstructedFromGivenClass"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_7d
    const-string v13, "classFqNameEquals"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_7e
    const-string v13, "isTypeConstructorForGivenClass"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_7f
    const-string v13, "isConstructedFromGivenClass"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_80
    const-string v13, "isPrimitiveClass"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_81
    const-string v13, "isPrimitiveTypeOrNullablePrimitiveType"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_82
    const-string v13, "isPrimitiveType"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_83
    const-string v13, "getPrimitiveArrayElementType"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_84
    const-string v13, "isPrimitiveArray"

    aput-object v13, v12, v11

    goto/16 :goto_4

    :pswitch_85
    const-string v13, "isArrayOrPrimitiveArray"

    aput-object v13, v12, v11

    goto :goto_4

    :pswitch_86
    const-string v13, "isArray"

    aput-object v13, v12, v11

    goto :goto_4

    :pswitch_87
    aput-object v21, v12, v11

    goto :goto_4

    :pswitch_88
    aput-object v20, v12, v11

    goto :goto_4

    :pswitch_89
    const-string v13, "getPrimitiveArrayType"

    aput-object v13, v12, v11

    goto :goto_4

    :pswitch_8a
    const-string v13, "getPrimitiveType"

    aput-object v13, v12, v11

    goto :goto_4

    :pswitch_8b
    const-string v13, "getPrimitiveArrayKotlinTypeByPrimitiveKotlinType"

    aput-object v13, v12, v11

    goto :goto_4

    :pswitch_8c
    aput-object v19, v12, v11

    goto :goto_4

    :pswitch_8d
    const-string v13, "getElementTypeForUnsignedArray"

    aput-object v13, v12, v11

    goto :goto_4

    :pswitch_8e
    const-string v13, "getArrayElementTypeOrNull"

    aput-object v13, v12, v11

    goto :goto_4

    :pswitch_8f
    aput-object v18, v12, v11

    goto :goto_4

    :pswitch_90
    aput-object v17, v12, v11

    goto :goto_4

    :pswitch_91
    aput-object v16, v12, v11

    goto :goto_4

    :pswitch_92
    const-string v13, "getPrimitiveArrayClassDescriptor"

    aput-object v13, v12, v11

    goto :goto_4

    :pswitch_93
    const-string v13, "getPrimitiveClassDescriptor"

    aput-object v13, v12, v11

    goto :goto_4

    :pswitch_94
    aput-object v15, v12, v11

    goto :goto_4

    :pswitch_95
    aput-object v14, v12, v11

    goto :goto_4

    :pswitch_96
    const-string v13, "isUnderKotlinPackage"

    aput-object v13, v12, v11

    goto :goto_4

    :pswitch_97
    const-string v13, "isBuiltIn"

    aput-object v13, v12, v11

    goto :goto_4

    :pswitch_98
    const-string v13, "setPostponedBuiltinsModuleComputation"

    aput-object v13, v12, v11

    goto :goto_4

    :pswitch_99
    const-string v13, "setBuiltInsModule"

    aput-object v13, v12, v11

    :goto_4
    :pswitch_9a
    invoke-static {v10, v12}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v10

    if-eq v0, v9, :cond_a

    if-eq v0, v8, :cond_a

    if-eq v0, v7, :cond_a

    if-eq v0, v6, :cond_a

    if-eq v0, v5, :cond_a

    if-eq v0, v4, :cond_a

    if-eq v0, v3, :cond_a

    if-eq v0, v2, :cond_a

    if-eq v0, v1, :cond_a

    packed-switch v0, :pswitch_data_e

    packed-switch v0, :pswitch_data_f

    packed-switch v0, :pswitch_data_10

    packed-switch v0, :pswitch_data_11

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, v10}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    goto :goto_5

    :cond_a
    :pswitch_9b
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    :goto_5
    throw v0

    nop

    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch

    :pswitch_data_1
    .packed-switch 0x12
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch

    :pswitch_data_2
    .packed-switch 0x30
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch

    :pswitch_data_3
    .packed-switch 0x37
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch

    :pswitch_data_4
    .packed-switch 0x3
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
    .end packed-switch

    :pswitch_data_5
    .packed-switch 0x12
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
    .end packed-switch

    :pswitch_data_6
    .packed-switch 0x30
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
    .end packed-switch

    :pswitch_data_7
    .packed-switch 0x37
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
    .end packed-switch

    :pswitch_data_8
    .packed-switch 0x1
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_10
        :pswitch_10
        :pswitch_11
        :pswitch_f
        :pswitch_11
        :pswitch_e
        :pswitch_11
        :pswitch_d
        :pswitch_d
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_c
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_d
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_b
        :pswitch_11
        :pswitch_b
        :pswitch_a
        :pswitch_13
        :pswitch_9
        :pswitch_11
        :pswitch_8
        :pswitch_10
        :pswitch_10
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_11
        :pswitch_7
        :pswitch_6
        :pswitch_11
        :pswitch_6
        :pswitch_11
        :pswitch_11
        :pswitch_d
        :pswitch_10
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_10
        :pswitch_d
        :pswitch_f
        :pswitch_d
        :pswitch_f
        :pswitch_4
        :pswitch_f
        :pswitch_10
        :pswitch_f
        :pswitch_d
        :pswitch_f
        :pswitch_10
        :pswitch_10
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_3
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_f
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_10
        :pswitch_d
        :pswitch_d
        :pswitch_10
        :pswitch_10
        :pswitch_d
        :pswitch_10
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_10
        :pswitch_10
        :pswitch_10
        :pswitch_2
        :pswitch_d
    .end packed-switch

    :pswitch_data_9
    .packed-switch 0x3
        :pswitch_49
        :pswitch_48
        :pswitch_47
        :pswitch_46
        :pswitch_45
        :pswitch_44
    .end packed-switch

    :pswitch_data_a
    .packed-switch 0x12
        :pswitch_43
        :pswitch_42
        :pswitch_41
        :pswitch_40
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
    .end packed-switch

    :pswitch_data_b
    .packed-switch 0x30
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
    .end packed-switch

    :pswitch_data_c
    .packed-switch 0x37
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
    .end packed-switch

    :pswitch_data_d
    .packed-switch 0x1
        :pswitch_99
        :pswitch_98
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_97
        :pswitch_96
        :pswitch_9a
        :pswitch_95
        :pswitch_9a
        :pswitch_94
        :pswitch_9a
        :pswitch_93
        :pswitch_92
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_91
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_90
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_8f
        :pswitch_9a
        :pswitch_8e
        :pswitch_8d
        :pswitch_8d
        :pswitch_8c
        :pswitch_9a
        :pswitch_8b
        :pswitch_8a
        :pswitch_89
        :pswitch_88
        :pswitch_88
        :pswitch_88
        :pswitch_9a
        :pswitch_88
        :pswitch_88
        :pswitch_9a
        :pswitch_87
        :pswitch_9a
        :pswitch_9a
        :pswitch_86
        :pswitch_85
        :pswitch_85
        :pswitch_84
        :pswitch_83
        :pswitch_8a
        :pswitch_82
        :pswitch_81
        :pswitch_80
        :pswitch_7f
        :pswitch_7f
        :pswitch_7f
        :pswitch_7f
        :pswitch_7e
        :pswitch_7e
        :pswitch_7d
        :pswitch_7d
        :pswitch_7c
        :pswitch_7c
        :pswitch_7b
        :pswitch_7a
        :pswitch_7a
        :pswitch_79
        :pswitch_78
        :pswitch_79
        :pswitch_77
        :pswitch_76
        :pswitch_75
        :pswitch_74
        :pswitch_73
        :pswitch_72
        :pswitch_71
        :pswitch_70
        :pswitch_6f
        :pswitch_6e
        :pswitch_6d
        :pswitch_6c
        :pswitch_6b
        :pswitch_6a
        :pswitch_69
        :pswitch_68
        :pswitch_67
        :pswitch_66
        :pswitch_65
        :pswitch_64
        :pswitch_63
        :pswitch_62
        :pswitch_62
        :pswitch_61
        :pswitch_60
        :pswitch_5f
        :pswitch_5e
        :pswitch_5d
        :pswitch_5c
        :pswitch_5b
        :pswitch_5a
        :pswitch_59
        :pswitch_58
        :pswitch_57
        :pswitch_56
        :pswitch_56
        :pswitch_55
        :pswitch_55
        :pswitch_54
        :pswitch_53
        :pswitch_52
        :pswitch_51
        :pswitch_50
        :pswitch_4f
        :pswitch_4e
        :pswitch_4d
        :pswitch_4c
        :pswitch_4b
        :pswitch_4a
    .end packed-switch

    :pswitch_data_e
    .packed-switch 0x3
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
    .end packed-switch

    :pswitch_data_f
    .packed-switch 0x12
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
    .end packed-switch

    :pswitch_data_10
    .packed-switch 0x30
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
    .end packed-switch

    :pswitch_data_11
    .packed-switch 0x37
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
        :pswitch_9b
    .end packed-switch
.end method

.method public static OooO0O0(Llyiahf/vczjk/by0;Llyiahf/vczjk/ic3;)Z
    .locals 2

    const/4 v0, 0x0

    if-eqz p0, :cond_2

    if-eqz p1, :cond_1

    invoke-interface {p0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/qt5;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/n72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object p0

    invoke-virtual {p1, p0}, Llyiahf/vczjk/ic3;->equals(Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0

    :cond_1
    const/16 p0, 0x68

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0

    :cond_2
    const/16 p0, 0x67

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0
.end method

.method public static OooOOoo(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/q47;
    .locals 3

    const/4 v0, 0x0

    if-eqz p0, :cond_1

    sget-object v1, Llyiahf/vczjk/w09;->OooooOO:Ljava/util/HashSet;

    invoke-interface {p0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object v0, Llyiahf/vczjk/w09;->Oooooo0:Ljava/util/HashMap;

    invoke-static {p0}, Llyiahf/vczjk/n72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/q47;

    return-object p0

    :cond_0
    return-object v0

    :cond_1
    const/16 p0, 0x4d

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0
.end method

.method public static OooOo0(Llyiahf/vczjk/by0;)Llyiahf/vczjk/q47;
    .locals 3

    const/4 v0, 0x0

    if-eqz p0, :cond_1

    sget-object v1, Llyiahf/vczjk/w09;->OooooO0:Ljava/util/HashSet;

    invoke-interface {p0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object v0, Llyiahf/vczjk/w09;->OooooOo:Ljava/util/HashMap;

    invoke-static {p0}, Llyiahf/vczjk/n72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/q47;

    return-object p0

    :cond_0
    return-object v0

    :cond_1
    const/16 p0, 0x4c

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0
.end method

.method public static OooOoO(Llyiahf/vczjk/uk4;)Z
    .locals 1

    if-eqz p0, :cond_0

    sget-object v0, Llyiahf/vczjk/w09;->OooO0oO:Llyiahf/vczjk/ic3;

    invoke-static {p0, v0}, Llyiahf/vczjk/hk4;->OooOoo0(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z

    move-result p0

    return p0

    :cond_0
    const/16 p0, 0x58

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 p0, 0x0

    throw p0
.end method

.method public static OooOoO0(Llyiahf/vczjk/uk4;)Z
    .locals 1

    if-eqz p0, :cond_0

    sget-object v0, Llyiahf/vczjk/w09;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-static {p0, v0}, Llyiahf/vczjk/hk4;->OooOoo0(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z

    move-result p0

    return p0

    :cond_0
    const/16 p0, 0x8b

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 p0, 0x0

    throw p0
.end method

.method public static OooOoOO(Llyiahf/vczjk/v02;)Z
    .locals 2

    if-eqz p0, :cond_1

    const-class v0, Llyiahf/vczjk/hk0;

    const/4 v1, 0x0

    invoke-static {p0, v0, v1}, Llyiahf/vczjk/n72;->OooO(Llyiahf/vczjk/v02;Ljava/lang/Class;Z)Llyiahf/vczjk/v02;

    move-result-object p0

    if-eqz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    return v1

    :cond_1
    const/16 p0, 0x9

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 p0, 0x0

    throw p0
.end method

.method public static OooOoo(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z
    .locals 0

    if-eqz p1, :cond_1

    invoke-static {p0, p1}, Llyiahf/vczjk/hk4;->OooOoo0(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z

    move-result p1

    if-eqz p1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result p0

    if-nez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0

    :cond_1
    const/16 p0, 0x87

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 p0, 0x0

    throw p0
.end method

.method public static OooOoo0(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z
    .locals 1

    const/4 v0, 0x0

    if-eqz p0, :cond_1

    if-eqz p1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p0

    invoke-static {p0, p1}, Llyiahf/vczjk/hk4;->Oooo0(Llyiahf/vczjk/n3a;Llyiahf/vczjk/ic3;)Z

    move-result p0

    return p0

    :cond_0
    const/16 p0, 0x62

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0

    :cond_1
    const/16 p0, 0x61

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0
.end method

.method public static OooOooO(Llyiahf/vczjk/rf3;)Z
    .locals 2

    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooO00o()Llyiahf/vczjk/v02;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/gm;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/w09;->OooOOO0:Llyiahf/vczjk/hc3;

    invoke-interface {v0, v1}, Llyiahf/vczjk/ko;->OooO0o0(Llyiahf/vczjk/hc3;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    instance-of v0, p0, Llyiahf/vczjk/sa7;

    if-eqz v0, :cond_2

    check-cast p0, Llyiahf/vczjk/sa7;

    invoke-interface {p0}, Llyiahf/vczjk/ada;->OoooooO()Z

    move-result v0

    invoke-interface {p0}, Llyiahf/vczjk/sa7;->OooO0O0()Llyiahf/vczjk/va7;

    move-result-object v1

    invoke-interface {p0}, Llyiahf/vczjk/sa7;->OooO0OO()Llyiahf/vczjk/hb7;

    move-result-object p0

    if-eqz v1, :cond_2

    invoke-static {v1}, Llyiahf/vczjk/hk4;->OooOooO(Llyiahf/vczjk/rf3;)Z

    move-result v1

    if-eqz v1, :cond_2

    if-eqz v0, :cond_1

    if-eqz p0, :cond_2

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooOooO(Llyiahf/vczjk/rf3;)Z

    move-result p0

    if-eqz p0, :cond_2

    :cond_1
    :goto_0
    const/4 p0, 0x1

    return p0

    :cond_2
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOooo(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z
    .locals 1

    const/4 v0, 0x0

    if-eqz p0, :cond_2

    if-eqz p1, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-static {p0, p1}, Llyiahf/vczjk/hk4;->OooOoo0(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z

    move-result p0

    if-eqz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0

    :cond_1
    const/16 p0, 0x6a

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0

    :cond_2
    const/16 p0, 0x69

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0
.end method

.method public static Oooo0(Llyiahf/vczjk/n3a;Llyiahf/vczjk/ic3;)Z
    .locals 1

    const/4 v0, 0x0

    if-eqz p0, :cond_2

    if-eqz p1, :cond_1

    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p0

    instance-of v0, p0, Llyiahf/vczjk/by0;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/by0;

    invoke-static {p0, p1}, Llyiahf/vczjk/hk4;->OooO0O0(Llyiahf/vczjk/by0;Llyiahf/vczjk/ic3;)Z

    move-result p0

    if-eqz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0

    :cond_1
    const/16 p0, 0x66

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0

    :cond_2
    const/16 p0, 0x65

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0
.end method

.method public static Oooo000(Llyiahf/vczjk/uk4;)Z
    .locals 1

    const/4 v0, 0x0

    if-eqz p0, :cond_2

    if-eqz p0, :cond_1

    sget-object v0, Llyiahf/vczjk/w09;->OooO0O0:Llyiahf/vczjk/ic3;

    invoke-static {p0, v0}, Llyiahf/vczjk/hk4;->OooOoo0(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/l5a;->OooO0o0(Llyiahf/vczjk/uk4;)Z

    move-result p0

    if-nez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0

    :cond_1
    const/16 p0, 0x8a

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0

    :cond_2
    const/16 p0, 0x88

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0
.end method

.method public static Oooo00O(Llyiahf/vczjk/uk4;)Z
    .locals 2

    const/4 v0, 0x0

    if-eqz p0, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result v1

    if-nez v1, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p0

    instance-of v1, p0, Llyiahf/vczjk/by0;

    if-eqz v1, :cond_1

    check-cast p0, Llyiahf/vczjk/by0;

    if-eqz p0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooOo0(Llyiahf/vczjk/by0;)Llyiahf/vczjk/q47;

    move-result-object p0

    if-eqz p0, :cond_1

    const/4 p0, 0x1

    return p0

    :cond_0
    const/16 p0, 0x60

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0

    :cond_1
    const/4 p0, 0x0

    return p0

    :cond_2
    const/16 p0, 0x5e

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0
.end method

.method public static Oooo00o(Llyiahf/vczjk/uk4;)Z
    .locals 1

    sget-object v0, Llyiahf/vczjk/w09;->OooO0o:Llyiahf/vczjk/ic3;

    invoke-static {p0, v0}, Llyiahf/vczjk/hk4;->OooOooo(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z

    move-result p0

    if-eqz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static Oooo0O0(Llyiahf/vczjk/gz0;)Z
    .locals 1

    if-eqz p0, :cond_2

    :goto_0
    if-eqz p0, :cond_1

    instance-of v0, p0, Llyiahf/vczjk/hh6;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/hh6;

    check-cast p0, Llyiahf/vczjk/ih6;

    sget-object v0, Llyiahf/vczjk/x09;->OooOO0O:Llyiahf/vczjk/qt5;

    iget-object p0, p0, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hc3;->OooO0OO(Llyiahf/vczjk/qt5;)Z

    move-result p0

    return p0

    :cond_0
    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p0

    goto :goto_0

    :cond_1
    const/4 p0, 0x0

    return p0

    :cond_2
    const/16 p0, 0xa

    invoke-static {p0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 p0, 0x0

    throw p0
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/cda;Llyiahf/vczjk/uk4;Llyiahf/vczjk/ko;)Llyiahf/vczjk/dp8;
    .locals 1

    if-eqz p2, :cond_0

    new-instance v0, Llyiahf/vczjk/f19;

    invoke-direct {v0, p2, p1}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)V

    invoke-static {v0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    invoke-static {p3}, Llyiahf/vczjk/br6;->Oooo00o(Llyiahf/vczjk/ko;)Llyiahf/vczjk/d3a;

    move-result-object p2

    const-string p3, "Array"

    invoke-virtual {p0, p3}, Llyiahf/vczjk/hk4;->OooOO0O(Ljava/lang/String;)Llyiahf/vczjk/by0;

    move-result-object p3

    invoke-static {p2, p3, p1}, Llyiahf/vczjk/so8;->Oooo0o(Llyiahf/vczjk/d3a;Llyiahf/vczjk/by0;Ljava/util/List;)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1

    :cond_0
    const/16 p1, 0x4f

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooO0OO()V
    .locals 22

    move-object/from16 v0, p0

    new-instance v1, Llyiahf/vczjk/dm5;

    sget-object v2, Llyiahf/vczjk/hk4;->OooO0o0:Llyiahf/vczjk/qt5;

    const-string v3, "moduleName"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v5, v0, Llyiahf/vczjk/hk4;->OooO0Oo:Llyiahf/vczjk/q45;

    const/16 v3, 0x30

    invoke-direct {v1, v2, v5, v0, v3}, Llyiahf/vczjk/dm5;-><init>(Llyiahf/vczjk/qt5;Llyiahf/vczjk/q45;Llyiahf/vczjk/hk4;I)V

    iput-object v1, v0, Llyiahf/vczjk/hk4;->OooO00o:Llyiahf/vczjk/dm5;

    sget-object v2, Llyiahf/vczjk/fk0;->OooO00o:Llyiahf/vczjk/ek0;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/ek0;->OooO0O0:Ljava/lang/Object;

    invoke-interface {v2}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/fk0;

    iget-object v6, v0, Llyiahf/vczjk/hk4;->OooO00o:Llyiahf/vczjk/dm5;

    invoke-virtual {v0}, Llyiahf/vczjk/hk4;->OooOOO0()Ljava/lang/Iterable;

    move-result-object v10

    invoke-virtual {v0}, Llyiahf/vczjk/hk4;->OooOOo0()Llyiahf/vczjk/cx6;

    move-result-object v13

    invoke-virtual {v0}, Llyiahf/vczjk/hk4;->OooO0Oo()Llyiahf/vczjk/n1;

    move-result-object v12

    check-cast v2, Llyiahf/vczjk/gk0;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v3, "builtInsModule"

    invoke-static {v6, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "classDescriptorFactories"

    invoke-static {v10, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "platformDependentDeclarationFilter"

    invoke-static {v13, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "additionalClassPartsProvider"

    invoke-static {v12, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/x09;->OooOOo:Ljava/util/Set;

    new-instance v14, Llyiahf/vczjk/o00000;

    iget-object v2, v2, Llyiahf/vczjk/gk0;->OooO0O0:Llyiahf/vczjk/jk0;

    const-string v19, "loadResource(Ljava/lang/String;)Ljava/io/InputStream;"

    const/16 v20, 0x0

    const/4 v15, 0x1

    const-class v17, Llyiahf/vczjk/jk0;

    const-string v18, "loadResource"

    const/16 v21, 0x3

    move-object/from16 v16, v2

    invoke-direct/range {v14 .. v21}, Llyiahf/vczjk/o00000;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    const-string v2, "packageFqNames"

    invoke-static {v3, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v3, Ljava/lang/Iterable;

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_0
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_2

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/hc3;

    sget-object v7, Llyiahf/vczjk/bk0;->OooOOO0:Llyiahf/vczjk/bk0;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/bk0;->OooO00o(Llyiahf/vczjk/hc3;)Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v14, v7}, Llyiahf/vczjk/o00000;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Ljava/io/InputStream;

    if-eqz v7, :cond_1

    invoke-static {v4, v5, v6, v7}, Llyiahf/vczjk/c6a;->Oooo00O(Llyiahf/vczjk/hc3;Llyiahf/vczjk/q45;Llyiahf/vczjk/cm5;Ljava/io/InputStream;)Llyiahf/vczjk/hk0;

    move-result-object v4

    goto :goto_1

    :cond_1
    const/4 v4, 0x0

    :goto_1
    if-eqz v4, :cond_0

    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    new-instance v9, Llyiahf/vczjk/jh6;

    invoke-direct {v9, v2}, Llyiahf/vczjk/jh6;-><init>(Ljava/util/ArrayList;)V

    new-instance v11, Llyiahf/vczjk/ld9;

    invoke-direct {v11, v5, v6}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/cm5;)V

    new-instance v4, Llyiahf/vczjk/s72;

    new-instance v7, Llyiahf/vczjk/vz5;

    const/16 v3, 0x10

    invoke-direct {v7, v9, v3}, Llyiahf/vczjk/vz5;-><init>(Ljava/lang/Object;I)V

    new-instance v8, Llyiahf/vczjk/era;

    sget-object v3, Llyiahf/vczjk/bk0;->OooOOO0:Llyiahf/vczjk/bk0;

    invoke-direct {v8, v6, v11, v3}, Llyiahf/vczjk/era;-><init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/ld9;Llyiahf/vczjk/bk0;)V

    new-instance v14, Llyiahf/vczjk/ws7;

    invoke-direct {v14, v5}, Llyiahf/vczjk/ws7;-><init>(Llyiahf/vczjk/q45;)V

    iget-object v3, v3, Llyiahf/vczjk/qg8;->OooO00o:Llyiahf/vczjk/iu2;

    const/4 v15, 0x0

    const/high16 v17, 0xd0000

    move-object/from16 v16, v14

    move-object v14, v3

    invoke-direct/range {v4 .. v17}, Llyiahf/vczjk/s72;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/cm5;Llyiahf/vczjk/vz5;Llyiahf/vczjk/era;Llyiahf/vczjk/lh6;Ljava/lang/Iterable;Llyiahf/vczjk/ld9;Llyiahf/vczjk/n1;Llyiahf/vczjk/cx6;Llyiahf/vczjk/iu2;Llyiahf/vczjk/v06;Llyiahf/vczjk/ws7;I)V

    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/hk0;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/hk0;->o0000O0O(Llyiahf/vczjk/s72;)V

    goto :goto_2

    :cond_3
    iput-object v9, v1, Llyiahf/vczjk/dm5;->OooOo0o:Llyiahf/vczjk/lh6;

    iget-object v1, v0, Llyiahf/vczjk/hk4;->OooO00o:Llyiahf/vczjk/dm5;

    filled-new-array {v1}, [Llyiahf/vczjk/dm5;

    move-result-object v2

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v2}, Llyiahf/vczjk/sy;->o0000oO([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/tg7;

    const/16 v4, 0x16

    invoke-direct {v3, v2, v4}, Llyiahf/vczjk/tg7;-><init>(Ljava/lang/Object;I)V

    iput-object v3, v1, Llyiahf/vczjk/dm5;->OooOo0O:Llyiahf/vczjk/tg7;

    return-void
.end method

.method public OooO0Oo()Llyiahf/vczjk/n1;
    .locals 1

    sget-object v0, Llyiahf/vczjk/uk2;->OooOOO:Llyiahf/vczjk/uk2;

    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/uk4;
    .locals 3

    if-eqz p1, :cond_1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/hk4;->OooO0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/uk4;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "not array: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    const/16 p1, 0x44

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooO0o0()Llyiahf/vczjk/dp8;
    .locals 1

    const-string v0, "Any"

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hk4;->OooOO0O(Ljava/lang/String;)Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x33

    invoke-static {v0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooO0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/uk4;
    .locals 4

    const/4 v0, 0x0

    if-eqz p1, :cond_a

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooOoO(Llyiahf/vczjk/uk4;)Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    const/4 v3, 0x1

    if-eq v1, v3, :cond_0

    goto/16 :goto_3

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object p1

    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/z4a;

    invoke-virtual {p1}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object p1

    return-object p1

    :cond_1
    invoke-static {p1, v2}, Llyiahf/vczjk/l5a;->OooO0oO(Llyiahf/vczjk/uk4;Z)Llyiahf/vczjk/iaa;

    move-result-object p1

    iget-object v1, p0, Llyiahf/vczjk/hk4;->OooO0O0:Llyiahf/vczjk/o45;

    invoke-virtual {v1}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/gk4;

    iget-object v1, v1, Llyiahf/vczjk/gk4;->OooO0O0:Ljava/util/HashMap;

    invoke-virtual {v1, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/uk4;

    if-eqz v1, :cond_2

    return-object v1

    :cond_2
    sget v1, Llyiahf/vczjk/n72;->OooO00o:I

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v1

    if-nez v1, :cond_3

    move-object v1, v0

    goto :goto_0

    :cond_3
    invoke-static {v1}, Llyiahf/vczjk/n72;->OooO0o0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/cm5;

    move-result-object v1

    :goto_0
    if-eqz v1, :cond_9

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p1

    if-nez p1, :cond_4

    :goto_1
    move-object p1, v0

    goto :goto_2

    :cond_4
    sget-object v2, Llyiahf/vczjk/aaa;->OooO00o:Ljava/util/Set;

    invoke-interface {p1}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v2

    const-string v3, "name"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/aaa;->OooO0Oo:Ljava/util/LinkedHashSet;

    invoke-interface {v3, v2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_5

    goto :goto_1

    :cond_5
    invoke-static {p1}, Llyiahf/vczjk/p72;->OooO0o(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/hy0;

    move-result-object p1

    if-nez p1, :cond_6

    goto :goto_1

    :cond_6
    sget-object v2, Llyiahf/vczjk/aaa;->OooO0O0:Ljava/util/HashMap;

    invoke-virtual {v2, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/hy0;

    if-nez p1, :cond_7

    goto :goto_1

    :cond_7
    invoke-static {v1, p1}, Llyiahf/vczjk/r02;->OooOOo0(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hy0;)Llyiahf/vczjk/by0;

    move-result-object p1

    if-nez p1, :cond_8

    goto :goto_1

    :cond_8
    invoke-interface {p1}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object p1

    :goto_2
    if-eqz p1, :cond_9

    return-object p1

    :cond_9
    :goto_3
    return-object v0

    :cond_a
    const/16 p1, 0x46

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/iaa;)Llyiahf/vczjk/dp8;
    .locals 2

    sget-object v0, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    if-eqz p1, :cond_0

    sget-object v1, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    invoke-virtual {p0, v0, p1, v1}, Llyiahf/vczjk/hk4;->OooO(Llyiahf/vczjk/cda;Llyiahf/vczjk/uk4;Llyiahf/vczjk/ko;)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1

    :cond_0
    const/16 p1, 0x53

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooOO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/by0;
    .locals 3

    const/4 v0, 0x0

    if-eqz p1, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/hk4;->OooOO0o()Llyiahf/vczjk/dm5;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/h16;->OooOOO0:Llyiahf/vczjk/h16;

    invoke-static {v1, p1}, Llyiahf/vczjk/l4a;->Oooo00o(Llyiahf/vczjk/dm5;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/by0;

    move-result-object p1

    if-eqz p1, :cond_0

    return-object p1

    :cond_0
    const/16 p1, 0xd

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0

    :cond_1
    const/16 p1, 0xc

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0
.end method

.method public final OooOO0O(Ljava/lang/String;)Llyiahf/vczjk/by0;
    .locals 1

    if-eqz p1, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/hk4;->OooO0OO:Llyiahf/vczjk/l45;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/l45;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/by0;

    return-object p1

    :cond_0
    const/16 p1, 0xe

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooOO0o()Llyiahf/vczjk/dm5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hk4;->OooO00o:Llyiahf/vczjk/dm5;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p0, Llyiahf/vczjk/hk4;->OooO00o:Llyiahf/vczjk/dm5;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/4 v0, 0x7

    invoke-static {v0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOOO()Llyiahf/vczjk/dp8;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/hk4;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x35

    invoke-static {v0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public OooOOO0()Ljava/lang/Iterable;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ak0;

    iget-object v1, p0, Llyiahf/vczjk/hk4;->OooO0Oo:Llyiahf/vczjk/q45;

    invoke-virtual {p0}, Llyiahf/vczjk/hk4;->OooOO0o()Llyiahf/vczjk/dm5;

    move-result-object v2

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/ak0;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/dm5;)V

    invoke-static {v0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/4 v0, 0x5

    invoke-static {v0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOOOO()Llyiahf/vczjk/dp8;
    .locals 1

    const-string v0, "Nothing"

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hk4;->OooOO0O(Ljava/lang/String;)Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x31

    invoke-static {v0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOOOo()Llyiahf/vczjk/dp8;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/hk4;->OooO0o0()Llyiahf/vczjk/dp8;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x34

    invoke-static {v0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOOo(Llyiahf/vczjk/q47;)Llyiahf/vczjk/dp8;
    .locals 2

    const/4 v0, 0x0

    if-eqz p1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/hk4;->OooO0O0:Llyiahf/vczjk/o45;

    invoke-virtual {v1}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/gk4;

    iget-object v1, v1, Llyiahf/vczjk/gk4;->OooO00o:Ljava/util/EnumMap;

    invoke-virtual {v1, p1}, Ljava/util/EnumMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dp8;

    if-eqz p1, :cond_0

    return-object p1

    :cond_0
    const/16 p1, 0x4a

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0

    :cond_1
    const/16 p1, 0x49

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0
.end method

.method public OooOOo0()Llyiahf/vczjk/cx6;
    .locals 1

    sget-object v0, Llyiahf/vczjk/up3;->OooOOoo:Llyiahf/vczjk/up3;

    return-object v0
.end method

.method public final OooOo()Llyiahf/vczjk/dp8;
    .locals 1

    const-string v0, "Unit"

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hk4;->OooOO0O(Ljava/lang/String;)Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x41

    invoke-static {v0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOo00(Llyiahf/vczjk/q47;)Llyiahf/vczjk/dp8;
    .locals 1

    const/4 v0, 0x0

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/q47;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/hk4;->OooOO0O(Ljava/lang/String;)Llyiahf/vczjk/by0;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object p1

    if-eqz p1, :cond_0

    return-object p1

    :cond_0
    const/16 p1, 0x37

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0

    :cond_1
    const/16 p1, 0x36

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0
.end method

.method public final OooOo0O()Llyiahf/vczjk/dp8;
    .locals 1

    const-string v0, "String"

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hk4;->OooOO0O(Ljava/lang/String;)Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x42

    invoke-static {v0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOo0o(I)Llyiahf/vczjk/by0;
    .locals 3

    sget-object v0, Llyiahf/vczjk/x09;->OooO0o:Llyiahf/vczjk/hc3;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v2, Llyiahf/vczjk/ag3;->OooO0OO:Llyiahf/vczjk/ag3;

    iget-object v2, v2, Llyiahf/vczjk/bg3;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/hc3;->OooO00o(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hc3;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/hk4;->OooOO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/by0;

    move-result-object p1

    return-object p1
.end method
