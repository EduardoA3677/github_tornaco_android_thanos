.class public abstract Llyiahf/vczjk/rl7;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/util/List;

.field public static final OooO0O0:Ljava/util/Map;

.field public static final OooO0OO:Ljava/util/Map;

.field public static final OooO0Oo:Ljava/util/Map;


# direct methods
.method static constructor <clinit>()V
    .locals 28

    const/4 v0, 0x1

    const/4 v1, 0x0

    sget-object v2, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    sget-object v3, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v3

    sget-object v4, Ljava/lang/Byte;->TYPE:Ljava/lang/Class;

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v4

    sget-object v5, Ljava/lang/Character;->TYPE:Ljava/lang/Class;

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v5

    sget-object v6, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v6

    sget-object v7, Ljava/lang/Float;->TYPE:Ljava/lang/Class;

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v7

    sget-object v8, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v8

    sget-object v9, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v9

    sget-object v10, Ljava/lang/Short;->TYPE:Ljava/lang/Class;

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v2

    const/16 v10, 0x8

    new-array v10, v10, [Llyiahf/vczjk/gf4;

    aput-object v3, v10, v1

    aput-object v4, v10, v0

    const/4 v3, 0x2

    aput-object v5, v10, v3

    const/4 v3, 0x3

    aput-object v6, v10, v3

    const/4 v3, 0x4

    aput-object v7, v10, v3

    const/4 v3, 0x5

    aput-object v8, v10, v3

    const/4 v3, 0x6

    aput-object v9, v10, v3

    const/4 v3, 0x7

    aput-object v2, v10, v3

    invoke-static {v10}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    sput-object v2, Llyiahf/vczjk/rl7;->OooO00o:Ljava/util/List;

    new-instance v3, Ljava/util/ArrayList;

    const/16 v4, 0xa

    invoke-static {v2, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v5

    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_0

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/gf4;

    invoke-static {v5}, Llyiahf/vczjk/rs;->Oooo00o(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v6

    invoke-static {v5}, Llyiahf/vczjk/rs;->Oooo0(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v5

    new-instance v7, Llyiahf/vczjk/xn6;

    invoke-direct {v7, v6, v5}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    invoke-static {v3}, Llyiahf/vczjk/lc5;->o0OOO0o(Ljava/util/List;)Ljava/util/Map;

    move-result-object v2

    sput-object v2, Llyiahf/vczjk/rl7;->OooO0O0:Ljava/util/Map;

    sget-object v2, Llyiahf/vczjk/rl7;->OooO00o:Ljava/util/List;

    new-instance v3, Ljava/util/ArrayList;

    invoke-static {v2, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v5

    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_1

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/gf4;

    invoke-static {v5}, Llyiahf/vczjk/rs;->Oooo0(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v6

    invoke-static {v5}, Llyiahf/vczjk/rs;->Oooo00o(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v5

    new-instance v7, Llyiahf/vczjk/xn6;

    invoke-direct {v7, v6, v5}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_1
    invoke-static {v3}, Llyiahf/vczjk/lc5;->o0OOO0o(Ljava/util/List;)Ljava/util/Map;

    move-result-object v2

    sput-object v2, Llyiahf/vczjk/rl7;->OooO0OO:Ljava/util/Map;

    const-class v24, Llyiahf/vczjk/ve3;

    const-class v25, Llyiahf/vczjk/xe3;

    const-class v5, Llyiahf/vczjk/le3;

    const-class v6, Llyiahf/vczjk/oe3;

    const-class v7, Llyiahf/vczjk/ze3;

    const-class v8, Llyiahf/vczjk/bf3;

    const-class v9, Llyiahf/vczjk/df3;

    const-class v10, Llyiahf/vczjk/ef3;

    const-class v11, Llyiahf/vczjk/ff3;

    const-class v12, Llyiahf/vczjk/gf3;

    const-class v13, Llyiahf/vczjk/hf3;

    const-class v14, Llyiahf/vczjk/if3;

    const-class v15, Llyiahf/vczjk/me3;

    const-class v16, Llyiahf/vczjk/ne3;

    const-class v17, Llyiahf/vczjk/eg3;

    const-class v18, Llyiahf/vczjk/pe3;

    const-class v19, Llyiahf/vczjk/qe3;

    const-class v20, Llyiahf/vczjk/re3;

    const-class v21, Llyiahf/vczjk/se3;

    const-class v22, Llyiahf/vczjk/te3;

    const-class v23, Llyiahf/vczjk/ue3;

    const-class v26, Llyiahf/vczjk/ye3;

    const-class v27, Llyiahf/vczjk/eg3;

    filled-new-array/range {v5 .. v27}, [Ljava/lang/Class;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    new-instance v3, Ljava/util/ArrayList;

    invoke-static {v2, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_3

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    add-int/lit8 v5, v1, 0x1

    if-ltz v1, :cond_2

    check-cast v4, Ljava/lang/Class;

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/xn6;

    invoke-direct {v6, v4, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v1, v5

    goto :goto_2

    :cond_2
    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    const/4 v0, 0x0

    throw v0

    :cond_3
    invoke-static {v3}, Llyiahf/vczjk/lc5;->o0OOO0o(Ljava/util/List;)Ljava/util/Map;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/rl7;->OooO0Oo:Ljava/util/Map;

    return-void
.end method

.method public static final OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;
    .locals 3

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/Class;->isPrimitive()Z

    move-result v0

    if-nez v0, :cond_4

    invoke-virtual {p0}, Ljava/lang/Class;->isArray()Z

    move-result v0

    if-nez v0, :cond_3

    invoke-virtual {p0}, Ljava/lang/Class;->getEnclosingMethod()Ljava/lang/reflect/Method;

    move-result-object v0

    if-nez v0, :cond_2

    invoke-virtual {p0}, Ljava/lang/Class;->getEnclosingConstructor()Ljava/lang/reflect/Constructor;

    move-result-object v0

    if-nez v0, :cond_2

    invoke-virtual {p0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Class;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v0

    invoke-virtual {p0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p0

    invoke-virtual {v0, p0}, Llyiahf/vczjk/hy0;->OooO0Oo(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hy0;

    move-result-object p0

    return-object p0

    :cond_1
    new-instance v0, Llyiahf/vczjk/hc3;

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance p0, Llyiahf/vczjk/hy0;

    invoke-virtual {v0}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-direct {p0, v1, v0}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    return-object p0

    :cond_2
    :goto_0
    new-instance v0, Llyiahf/vczjk/hc3;

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance p0, Llyiahf/vczjk/hy0;

    invoke-virtual {v0}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/r02;->Oooo00O(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hc3;

    move-result-object v0

    const/4 v2, 0x1

    invoke-direct {p0, v1, v0, v2}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;Z)V

    return-object p0

    :cond_3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Can\'t compute ClassId for array type: "

    invoke-static {p0, v1}, Llyiahf/vczjk/ii5;->OooO0oO(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_4
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Can\'t compute ClassId for primitive type: "

    invoke-static {p0, v1}, Llyiahf/vczjk/ii5;->OooO0oO(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static final OooO0O0(Ljava/lang/Class;)Ljava/lang/String;
    .locals 4

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/Class;->isPrimitive()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    move-result v1

    sparse-switch v1, :sswitch_data_0

    goto :goto_0

    :sswitch_0
    const-string v1, "short"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const-string p0, "S"

    return-object p0

    :sswitch_1
    const-string v1, "float"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const-string p0, "F"

    return-object p0

    :sswitch_2
    const-string v1, "boolean"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const-string p0, "Z"

    return-object p0

    :sswitch_3
    const-string v1, "void"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const-string p0, "V"

    return-object p0

    :sswitch_4
    const-string v1, "long"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const-string p0, "J"

    return-object p0

    :sswitch_5
    const-string v1, "char"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const-string p0, "C"

    return-object p0

    :sswitch_6
    const-string v1, "byte"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const-string p0, "B"

    return-object p0

    :sswitch_7
    const-string v1, "int"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const-string p0, "I"

    return-object p0

    :sswitch_8
    const-string v1, "double"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const-string p0, "D"

    return-object p0

    :cond_0
    :goto_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Unsupported primitive type: "

    invoke-static {p0, v1}, Llyiahf/vczjk/ii5;->OooO0oO(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    invoke-virtual {p0}, Ljava/lang/Class;->isArray()Z

    move-result v0

    const/16 v1, 0x2f

    const/16 v2, 0x2e

    if-eqz v0, :cond_2

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, v2, v1}, Llyiahf/vczjk/g79;->OooOooo(Ljava/lang/String;CC)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_2
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v3, "L"

    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, v2, v1}, Llyiahf/vczjk/g79;->OooOooo(Ljava/lang/String;CC)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 p0, 0x3b

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0

    nop

    :sswitch_data_0
    .sparse-switch
        -0x4f08842f -> :sswitch_8
        0x197ef -> :sswitch_7
        0x2e6108 -> :sswitch_6
        0x2e9356 -> :sswitch_5
        0x32c67c -> :sswitch_4
        0x375194 -> :sswitch_3
        0x3db6c28 -> :sswitch_2
        0x5d0225c -> :sswitch_1
        0x685847c -> :sswitch_0
    .end sparse-switch
.end method

.method public static final OooO0OO(Ljava/lang/reflect/Type;)Ljava/util/List;
    .locals 3

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p0, Ljava/lang/reflect/ParameterizedType;

    if-nez v0, :cond_0

    sget-object p0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p0

    :cond_0
    move-object v0, p0

    check-cast v0, Ljava/lang/reflect/ParameterizedType;

    invoke-interface {v0}, Ljava/lang/reflect/ParameterizedType;->getOwnerType()Ljava/lang/reflect/Type;

    move-result-object v1

    if-nez v1, :cond_1

    invoke-interface {v0}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    move-result-object p0

    const-string v0, "getActualTypeArguments(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/sy;->o0000oO([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p0

    return-object p0

    :cond_1
    sget-object v0, Llyiahf/vczjk/iu6;->OooOOo0:Llyiahf/vczjk/iu6;

    invoke-static {p0, v0}, Llyiahf/vczjk/ag8;->Oooo0OO(Ljava/lang/Object;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/wf8;

    move-result-object p0

    sget-object v0, Llyiahf/vczjk/iu6;->OooOOo:Llyiahf/vczjk/iu6;

    new-instance v1, Llyiahf/vczjk/oz2;

    sget-object v2, Llyiahf/vczjk/dg8;->OooOOO:Llyiahf/vczjk/dg8;

    invoke-direct {v1, p0, v0, v2}, Llyiahf/vczjk/oz2;-><init>(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    invoke-static {v1}, Llyiahf/vczjk/ag8;->OoooO00(Llyiahf/vczjk/wf8;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0Oo(Ljava/lang/Class;)Ljava/lang/ClassLoader;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object p0

    if-nez p0, :cond_0

    invoke-static {}, Ljava/lang/ClassLoader;->getSystemClassLoader()Ljava/lang/ClassLoader;

    move-result-object p0

    const-string v0, "getSystemClassLoader(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_0
    return-object p0
.end method
