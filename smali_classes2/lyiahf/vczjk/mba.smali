.class public abstract Llyiahf/vczjk/mba;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/hc3;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/hc3;

    const-string v1, "kotlin.jvm.JvmStatic"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/mba;->OooO00o:Llyiahf/vczjk/hc3;

    return-void
.end method

.method public static final OooO(Ljava/lang/ClassLoader;Llyiahf/vczjk/hy0;I)Ljava/lang/Class;
    .locals 4

    sget-object v0, Llyiahf/vczjk/w64;->OooO00o:Ljava/lang/String;

    invoke-virtual {p1}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-static {v0}, Llyiahf/vczjk/w64;->OooO0o(Llyiahf/vczjk/ic3;)Llyiahf/vczjk/hy0;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    move-object p1, v0

    :goto_0
    iget-object v0, p1, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v0, v0, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    iget-object p1, p1, Llyiahf/vczjk/hy0;->OooO0O0:Llyiahf/vczjk/hc3;

    iget-object p1, p1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object p1, p1, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    const-string v1, "kotlin"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_a

    invoke-virtual {p1}, Ljava/lang/String;->hashCode()I

    move-result v1

    sparse-switch v1, :sswitch_data_0

    goto/16 :goto_1

    :sswitch_0
    const-string v1, "LongArray"

    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1

    goto :goto_1

    :cond_1
    const-class p0, [J

    return-object p0

    :sswitch_1
    const-string v1, "FloatArray"

    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2

    goto :goto_1

    :cond_2
    const-class p0, [F

    return-object p0

    :sswitch_2
    const-string v1, "IntArray"

    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3

    goto :goto_1

    :cond_3
    const-class p0, [I

    return-object p0

    :sswitch_3
    const-string v1, "Array"

    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4

    goto :goto_1

    :cond_4
    const-class p0, [Ljava/lang/Object;

    return-object p0

    :sswitch_4
    const-string v1, "DoubleArray"

    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_5

    goto :goto_1

    :cond_5
    const-class p0, [D

    return-object p0

    :sswitch_5
    const-string v1, "ByteArray"

    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_6

    goto :goto_1

    :cond_6
    const-class p0, [B

    return-object p0

    :sswitch_6
    const-string v1, "CharArray"

    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_7

    goto :goto_1

    :cond_7
    const-class p0, [C

    return-object p0

    :sswitch_7
    const-string v1, "ShortArray"

    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_8

    goto :goto_1

    :cond_8
    const-class p0, [S

    return-object p0

    :sswitch_8
    const-string v1, "BooleanArray"

    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_9

    goto :goto_1

    :cond_9
    const-class p0, [Z

    return-object p0

    :cond_a
    :goto_1
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    if-lez p2, :cond_c

    const/4 v2, 0x0

    :goto_2
    if-ge v2, p2, :cond_b

    const-string v3, "["

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    add-int/lit8 v2, v2, 0x1

    goto :goto_2

    :cond_b
    const-string v2, "L"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_c
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v2

    if-lez v2, :cond_d

    const-string v2, "."

    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_d
    const/16 v0, 0x24

    const/16 v2, 0x2e

    invoke-static {p1, v2, v0}, Llyiahf/vczjk/g79;->OooOooo(Ljava/lang/String;CC)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    if-lez p2, :cond_e

    const-string p1, ";"

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_e
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p0, p1}, Llyiahf/vczjk/tn6;->OooOo0O(Ljava/lang/ClassLoader;Ljava/lang/String;)Ljava/lang/Class;

    move-result-object p0

    return-object p0

    :sswitch_data_0
    .sparse-switch
        -0x35c13ccf -> :sswitch_8
        -0x2d7eb8a3 -> :sswitch_7
        -0x2d0e4b7d -> :sswitch_6
        -0x47759ef -> :sswitch_5
        0x15568e8 -> :sswitch_4
        0x3c98239 -> :sswitch_3
        0x23deebca -> :sswitch_2
        0x388e557d -> :sswitch_1
        0x7d6d891d -> :sswitch_0
    .end sparse-switch
.end method

.method public static final OooO00o(Llyiahf/vczjk/bf4;)Llyiahf/vczjk/ff4;
    .locals 1

    instance-of v0, p0, Llyiahf/vczjk/ff4;

    if-eqz v0, :cond_0

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/ff4;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-nez v0, :cond_2

    invoke-static {p0}, Llyiahf/vczjk/mba;->OooO0O0(Ljava/lang/Object;)Llyiahf/vczjk/bg4;

    move-result-object v0

    if-eqz v0, :cond_1

    return-object v0

    :cond_1
    invoke-static {p0}, Llyiahf/vczjk/mba;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/ai4;

    move-result-object p0

    return-object p0

    :cond_2
    return-object v0
.end method

.method public static final OooO0O0(Ljava/lang/Object;)Llyiahf/vczjk/bg4;
    .locals 2

    instance-of v0, p0, Llyiahf/vczjk/bg4;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/bg4;

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    if-nez v0, :cond_5

    instance-of v0, p0, Llyiahf/vczjk/vf3;

    if-eqz v0, :cond_1

    check-cast p0, Llyiahf/vczjk/vf3;

    goto :goto_1

    :cond_1
    move-object p0, v1

    :goto_1
    if-eqz p0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/go0;->OooOOO0:Llyiahf/vczjk/bf4;

    if-nez v0, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/vf3;->OooO0oO()Llyiahf/vczjk/bf4;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/go0;->OooOOO0:Llyiahf/vczjk/bf4;

    goto :goto_2

    :cond_2
    move-object v0, v1

    :cond_3
    :goto_2
    instance-of p0, v0, Llyiahf/vczjk/bg4;

    if-eqz p0, :cond_4

    check-cast v0, Llyiahf/vczjk/bg4;

    return-object v0

    :cond_4
    return-object v1

    :cond_5
    return-object v0
.end method

.method public static final OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/ai4;
    .locals 2

    instance-of v0, p0, Llyiahf/vczjk/ai4;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/ai4;

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    if-nez v0, :cond_4

    instance-of v0, p0, Llyiahf/vczjk/ab7;

    if-eqz v0, :cond_1

    check-cast p0, Llyiahf/vczjk/ab7;

    goto :goto_1

    :cond_1
    move-object p0, v1

    :goto_1
    if-eqz p0, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/ab7;->OooOOO0()Llyiahf/vczjk/bf4;

    move-result-object p0

    goto :goto_2

    :cond_2
    move-object p0, v1

    :goto_2
    instance-of v0, p0, Llyiahf/vczjk/ai4;

    if-eqz v0, :cond_3

    check-cast p0, Llyiahf/vczjk/ai4;

    return-object p0

    :cond_3
    return-object v1

    :cond_4
    return-object v0
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/gm;)Ljava/util/ArrayList;
    .locals 6

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Llyiahf/vczjk/gm;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object p0

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_5

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/un;

    invoke-interface {v1}, Llyiahf/vczjk/un;->OooO0oO()Llyiahf/vczjk/sx8;

    move-result-object v3

    instance-of v4, v3, Llyiahf/vczjk/ql7;

    if-eqz v4, :cond_1

    check-cast v3, Llyiahf/vczjk/ql7;

    iget-object v2, v3, Llyiahf/vczjk/ql7;->OooOOO0:Ljava/lang/annotation/Annotation;

    goto :goto_2

    :cond_1
    instance-of v4, v3, Llyiahf/vczjk/hz7;

    if-eqz v4, :cond_3

    check-cast v3, Llyiahf/vczjk/hz7;

    iget-object v1, v3, Llyiahf/vczjk/hz7;->OooOOO0:Llyiahf/vczjk/gm7;

    instance-of v3, v1, Llyiahf/vczjk/sl7;

    if-eqz v3, :cond_2

    check-cast v1, Llyiahf/vczjk/sl7;

    goto :goto_1

    :cond_2
    move-object v1, v2

    :goto_1
    if-eqz v1, :cond_4

    iget-object v2, v1, Llyiahf/vczjk/sl7;->OooO00o:Ljava/lang/annotation/Annotation;

    goto :goto_2

    :cond_3
    invoke-static {v1}, Llyiahf/vczjk/mba;->OooOO0(Llyiahf/vczjk/un;)Ljava/lang/annotation/Annotation;

    move-result-object v2

    :cond_4
    :goto_2
    if-eqz v2, :cond_0

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_5
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p0

    if-eqz p0, :cond_6

    goto :goto_5

    :cond_6
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_7
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_a

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/annotation/Annotation;

    invoke-static {v1}, Llyiahf/vczjk/rs;->OooOooo(Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/gf4;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    const-string v3, "Container"

    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_7

    new-instance p0, Ljava/util/ArrayList;

    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_9

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/annotation/Annotation;

    invoke-static {v1}, Llyiahf/vczjk/rs;->OooOooo(Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/gf4;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v5, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_8

    const-class v5, Llyiahf/vczjk/mq7;

    invoke-virtual {v4, v5}, Ljava/lang/Class;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v5

    if-eqz v5, :cond_8

    const-string v5, "value"

    invoke-virtual {v4, v5, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v4

    invoke-virtual {v4, v1, v2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    const-string v4, "null cannot be cast to non-null type kotlin.Array<out kotlin.Annotation>"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, [Ljava/lang/annotation/Annotation;

    invoke-static {v1}, Llyiahf/vczjk/sy;->Oooooo0([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    goto :goto_4

    :cond_8
    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    :goto_4
    invoke-static {v1, p0}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_3

    :cond_9
    return-object p0

    :cond_a
    :goto_5
    return-object v0
.end method

.method public static final OooO0o(Ljava/lang/Class;Llyiahf/vczjk/sg3;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/zb0;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/co0;
    .locals 11

    const-string v0, "moduleAnchor"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "proto"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "nameResolver"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "metadataVersion"

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/zl5;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/gz7;

    move-result-object p0

    instance-of v0, p1, Llyiahf/vczjk/pc7;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/pc7;

    invoke-virtual {v0}, Llyiahf/vczjk/pc7;->OoooO()Ljava/util/List;

    move-result-object v0

    :goto_0
    move-object v10, v0

    goto :goto_1

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/xc7;

    if-eqz v0, :cond_1

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/xc7;

    invoke-virtual {v0}, Llyiahf/vczjk/xc7;->OoooOO0()Ljava/util/List;

    move-result-object v0

    goto :goto_0

    :goto_1
    new-instance v1, Llyiahf/vczjk/u72;

    iget-object v2, p0, Llyiahf/vczjk/gz7;->OooO00o:Llyiahf/vczjk/s72;

    sget-object v6, Llyiahf/vczjk/xea;->OooO0O0:Llyiahf/vczjk/xea;

    invoke-static {v10}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const/4 v8, 0x0

    const/4 v9, 0x0

    iget-object v4, v2, Llyiahf/vczjk/s72;->OooO0O0:Llyiahf/vczjk/cm5;

    move-object v3, p2

    move-object v5, p3

    move-object v7, p4

    invoke-direct/range {v1 .. v10}, Llyiahf/vczjk/u72;-><init>(Llyiahf/vczjk/s72;Llyiahf/vczjk/rt5;Llyiahf/vczjk/v02;Llyiahf/vczjk/h87;Llyiahf/vczjk/xea;Llyiahf/vczjk/zb0;Llyiahf/vczjk/ce4;Llyiahf/vczjk/t3a;Ljava/util/List;)V

    new-instance p0, Llyiahf/vczjk/cg5;

    invoke-direct {p0, v1}, Llyiahf/vczjk/cg5;-><init>(Llyiahf/vczjk/u72;)V

    move-object/from16 p2, p5

    invoke-interface {p2, p0, p1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/co0;

    return-object p0

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    new-instance p2, Ljava/lang/StringBuilder;

    const-string p3, "Unsupported message: "

    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooO0o0(Ljava/lang/reflect/Type;)Ljava/lang/Object;
    .locals 3

    const-string v0, "type"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p0, Ljava/lang/Class;

    if-eqz v0, :cond_9

    move-object v0, p0

    check-cast v0, Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->isPrimitive()Z

    move-result v1

    if-eqz v1, :cond_9

    sget-object v1, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p0

    :cond_0
    sget-object v1, Ljava/lang/Character;->TYPE:Ljava/lang/Class;

    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    invoke-static {v2}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    move-result-object p0

    return-object p0

    :cond_1
    sget-object v1, Ljava/lang/Byte;->TYPE:Ljava/lang/Class;

    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-static {v2}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object p0

    return-object p0

    :cond_2
    sget-object v1, Ljava/lang/Short;->TYPE:Ljava/lang/Class;

    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-static {v2}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

    move-result-object p0

    return-object p0

    :cond_3
    sget-object v1, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    return-object p0

    :cond_4
    sget-object v1, Ljava/lang/Float;->TYPE:Ljava/lang/Class;

    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_5

    const/4 p0, 0x0

    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p0

    return-object p0

    :cond_5
    sget-object v1, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_6

    const-wide/16 v0, 0x0

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p0

    return-object p0

    :cond_6
    sget-object v1, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_7

    const-wide/16 v0, 0x0

    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p0

    return-object p0

    :cond_7
    sget-object v1, Ljava/lang/Void;->TYPE:Ljava/lang/Class;

    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_8

    new-instance p0, Ljava/lang/IllegalStateException;

    const-string v0, "Parameter with void type is illegal"

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_8
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Unknown primitive: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_9
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final OooO0oO(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/mp4;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Llyiahf/vczjk/co0;->Oooooo0()Llyiahf/vczjk/mp4;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p0

    const-string v0, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.ClassDescriptor"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Llyiahf/vczjk/by0;

    invoke-interface {p0}, Llyiahf/vczjk/by0;->o00000()Llyiahf/vczjk/mp4;

    move-result-object p0

    return-object p0

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final OooO0oo(Llyiahf/vczjk/di4;)Z
    .locals 1

    iget-object p0, p0, Llyiahf/vczjk/di4;->OooO00o:Llyiahf/vczjk/uk4;

    if-eqz p0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/uz3;->OooO0oo(Llyiahf/vczjk/uk4;)Z

    move-result p0

    const/4 v0, 0x1

    if-ne p0, v0, :cond_0

    return v0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static final OooOO0(Llyiahf/vczjk/un;)Ljava/lang/annotation/Annotation;
    .locals 7

    invoke-static {p0}, Llyiahf/vczjk/p72;->OooO0Oo(Llyiahf/vczjk/un;)Llyiahf/vczjk/by0;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/mba;->OooOO0O(Llyiahf/vczjk/by0;)Ljava/lang/Class;

    move-result-object v0

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    if-eqz v0, :cond_1

    goto :goto_1

    :cond_1
    move-object v0, v1

    :goto_1
    if-nez v0, :cond_2

    return-object v1

    :cond_2
    invoke-interface {p0}, Llyiahf/vczjk/un;->OooO()Ljava/util/Map;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object p0

    check-cast p0, Ljava/lang/Iterable;

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_3
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_5

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Map$Entry;

    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/qt5;

    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ij1;

    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v5

    const-string v6, "getClassLoader(...)"

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v3, v5}, Llyiahf/vczjk/mba;->OooOO0o(Llyiahf/vczjk/ij1;Ljava/lang/ClassLoader;)Ljava/lang/Object;

    move-result-object v3

    if-eqz v3, :cond_4

    invoke-virtual {v4}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v4

    new-instance v5, Llyiahf/vczjk/xn6;

    invoke-direct {v5, v4, v3}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_3

    :cond_4
    move-object v5, v1

    :goto_3
    if-eqz v5, :cond_3

    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_5
    invoke-static {v2}, Llyiahf/vczjk/lc5;->o0OOO0o(Ljava/util/List;)Ljava/util/Map;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    move-result-object v2

    check-cast v2, Ljava/lang/Iterable;

    new-instance v3, Ljava/util/ArrayList;

    const/16 v4, 0xa

    invoke-static {v2, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_4
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_6

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    invoke-virtual {v0, v4, v1}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_4

    :cond_6
    invoke-static {v0, p0, v3}, Llyiahf/vczjk/v34;->Oooo00o(Ljava/lang/Class;Ljava/util/Map;Ljava/util/List;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/annotation/Annotation;

    return-object p0
.end method

.method public static final OooOO0O(Llyiahf/vczjk/by0;)Ljava/lang/Class;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Llyiahf/vczjk/x02;->OooO0oO()Llyiahf/vczjk/sx8;

    move-result-object v0

    const-string v1, "getSource(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v1, v0, Llyiahf/vczjk/pk4;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/pk4;

    iget-object p0, v0, Llyiahf/vczjk/pk4;->OooOOO0:Llyiahf/vczjk/tm7;

    iget-object p0, p0, Llyiahf/vczjk/tm7;->OooO00o:Ljava/lang/Class;

    return-object p0

    :cond_0
    instance-of v1, v0, Llyiahf/vczjk/hz7;

    if-eqz v1, :cond_1

    check-cast v0, Llyiahf/vczjk/hz7;

    iget-object p0, v0, Llyiahf/vczjk/hz7;->OooOOO0:Llyiahf/vczjk/gm7;

    const-string v0, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.runtime.structure.ReflectJavaClass"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Llyiahf/vczjk/cm7;

    iget-object p0, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    return-object p0

    :cond_1
    invoke-static {p0}, Llyiahf/vczjk/p72;->OooO0o(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/hy0;

    move-result-object v0

    if-nez v0, :cond_2

    const/4 p0, 0x0

    return-object p0

    :cond_2
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/rl7;->OooO0Oo(Ljava/lang/Class;)Ljava/lang/ClassLoader;

    move-result-object p0

    const/4 v1, 0x0

    invoke-static {p0, v0, v1}, Llyiahf/vczjk/mba;->OooO(Ljava/lang/ClassLoader;Llyiahf/vczjk/hy0;I)Ljava/lang/Class;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOO0o(Llyiahf/vczjk/ij1;Ljava/lang/ClassLoader;)Ljava/lang/Object;
    .locals 6

    instance-of v0, p0, Llyiahf/vczjk/io;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/io;

    iget-object p0, p0, Llyiahf/vczjk/ij1;->OooO00o:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/un;

    invoke-static {p0}, Llyiahf/vczjk/mba;->OooOO0(Llyiahf/vczjk/un;)Ljava/lang/annotation/Annotation;

    move-result-object p0

    return-object p0

    :cond_0
    instance-of v0, p0, Llyiahf/vczjk/ry;

    const/4 v1, 0x0

    const/4 v2, 0x0

    if-eqz v0, :cond_17

    check-cast p0, Llyiahf/vczjk/ry;

    instance-of v0, p0, Llyiahf/vczjk/s5a;

    if-eqz v0, :cond_1

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/s5a;

    goto :goto_0

    :cond_1
    move-object v0, v2

    :goto_0
    if-eqz v0, :cond_1b

    iget-object v0, v0, Llyiahf/vczjk/s5a;->OooO0OO:Llyiahf/vczjk/uk4;

    if-nez v0, :cond_2

    goto/16 :goto_11

    :cond_2
    iget-object v3, p0, Llyiahf/vczjk/ij1;->OooO00o:Ljava/lang/Object;

    check-cast v3, Ljava/lang/Iterable;

    new-instance v4, Ljava/util/ArrayList;

    const/16 v5, 0xa

    invoke-static {v3, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v5

    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_3

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ij1;

    invoke-static {v5, p1}, Llyiahf/vczjk/mba;->OooOO0o(Llyiahf/vczjk/ij1;Ljava/lang/ClassLoader;)Ljava/lang/Object;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_3
    sget-object v3, Llyiahf/vczjk/hk4;->OooO0o0:Llyiahf/vczjk/qt5;

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v3

    invoke-interface {v3}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v3

    if-nez v3, :cond_4

    move-object v3, v2

    goto :goto_2

    :cond_4
    invoke-static {v3}, Llyiahf/vczjk/hk4;->OooOOoo(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/q47;

    move-result-object v3

    :goto_2
    if-nez v3, :cond_5

    const/4 v3, -0x1

    goto :goto_3

    :cond_5
    sget-object v5, Llyiahf/vczjk/lba;->OooO00o:[I

    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    move-result v3

    aget v3, v5, v3

    :goto_3
    iget-object p0, p0, Llyiahf/vczjk/ij1;->OooO00o:Ljava/lang/Object;

    packed-switch v3, :pswitch_data_0

    :pswitch_0
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :pswitch_1
    check-cast p0, Ljava/util/List;

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result p0

    new-array p1, p0, [D

    :goto_4
    if-ge v1, p0, :cond_6

    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    const-string v2, "null cannot be cast to non-null type kotlin.Double"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Double;

    invoke-virtual {v0}, Ljava/lang/Double;->doubleValue()D

    move-result-wide v2

    aput-wide v2, p1, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_4

    :cond_6
    return-object p1

    :pswitch_2
    check-cast p0, Ljava/util/List;

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result p0

    new-array p1, p0, [J

    :goto_5
    if-ge v1, p0, :cond_7

    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    const-string v2, "null cannot be cast to non-null type kotlin.Long"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Long;

    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    move-result-wide v2

    aput-wide v2, p1, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_5

    :cond_7
    return-object p1

    :pswitch_3
    check-cast p0, Ljava/util/List;

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result p0

    new-array p1, p0, [F

    :goto_6
    if-ge v1, p0, :cond_8

    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    const-string v2, "null cannot be cast to non-null type kotlin.Float"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Float;

    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    move-result v0

    aput v0, p1, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_6

    :cond_8
    return-object p1

    :pswitch_4
    check-cast p0, Ljava/util/List;

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result p0

    new-array p1, p0, [I

    :goto_7
    if-ge v1, p0, :cond_9

    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    const-string v2, "null cannot be cast to non-null type kotlin.Int"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Integer;

    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    move-result v0

    aput v0, p1, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_7

    :cond_9
    return-object p1

    :pswitch_5
    check-cast p0, Ljava/util/List;

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result p0

    new-array p1, p0, [S

    :goto_8
    if-ge v1, p0, :cond_a

    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    const-string v2, "null cannot be cast to non-null type kotlin.Short"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Short;

    invoke-virtual {v0}, Ljava/lang/Short;->shortValue()S

    move-result v0

    aput-short v0, p1, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_8

    :cond_a
    return-object p1

    :pswitch_6
    check-cast p0, Ljava/util/List;

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result p0

    new-array p1, p0, [B

    :goto_9
    if-ge v1, p0, :cond_b

    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    const-string v2, "null cannot be cast to non-null type kotlin.Byte"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Byte;

    invoke-virtual {v0}, Ljava/lang/Byte;->byteValue()B

    move-result v0

    aput-byte v0, p1, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_9

    :cond_b
    return-object p1

    :pswitch_7
    check-cast p0, Ljava/util/List;

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result p0

    new-array p1, p0, [C

    :goto_a
    if-ge v1, p0, :cond_c

    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    const-string v2, "null cannot be cast to non-null type kotlin.Char"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Character;

    invoke-virtual {v0}, Ljava/lang/Character;->charValue()C

    move-result v0

    aput-char v0, p1, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_a

    :cond_c
    return-object p1

    :pswitch_8
    check-cast p0, Ljava/util/List;

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result p0

    new-array p1, p0, [Z

    :goto_b
    if-ge v1, p0, :cond_d

    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    const-string v2, "null cannot be cast to non-null type kotlin.Boolean"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    aput-boolean v0, p1, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_b

    :cond_d
    return-object p1

    :pswitch_9
    invoke-static {v0}, Llyiahf/vczjk/hk4;->OooOoO(Llyiahf/vczjk/uk4;)Z

    move-result v3

    if-eqz v3, :cond_16

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/d21;->o00000o0(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/z4a;

    invoke-virtual {v0}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v0

    const-string v3, "getType(...)"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v3

    invoke-interface {v3}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v3

    instance-of v5, v3, Llyiahf/vczjk/by0;

    if-eqz v5, :cond_e

    check-cast v3, Llyiahf/vczjk/by0;

    goto :goto_c

    :cond_e
    move-object v3, v2

    :goto_c
    if-eqz v3, :cond_15

    invoke-static {v0}, Llyiahf/vczjk/hk4;->Oooo00o(Llyiahf/vczjk/uk4;)Z

    move-result v0

    if-eqz v0, :cond_10

    check-cast p0, Ljava/util/List;

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result p0

    new-array p1, p0, [Ljava/lang/String;

    :goto_d
    if-ge v1, p0, :cond_f

    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    const-string v2, "null cannot be cast to non-null type kotlin.String"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    aput-object v0, p1, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_d

    :cond_f
    return-object p1

    :cond_10
    sget-object v0, Llyiahf/vczjk/w09;->OoooO00:Llyiahf/vczjk/ic3;

    invoke-static {v3, v0}, Llyiahf/vczjk/hk4;->OooO0O0(Llyiahf/vczjk/by0;Llyiahf/vczjk/ic3;)Z

    move-result v0

    if-eqz v0, :cond_12

    check-cast p0, Ljava/util/List;

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result p0

    new-array p1, p0, [Ljava/lang/Class;

    :goto_e
    if-ge v1, p0, :cond_11

    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    const-string v2, "null cannot be cast to non-null type java.lang.Class<*>"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    aput-object v0, p1, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_e

    :cond_11
    return-object p1

    :cond_12
    invoke-static {v3}, Llyiahf/vczjk/p72;->OooO0o(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/hy0;

    move-result-object v0

    if-eqz v0, :cond_1b

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/mba;->OooO(Ljava/lang/ClassLoader;Llyiahf/vczjk/hy0;I)Ljava/lang/Class;

    move-result-object p1

    if-nez p1, :cond_13

    goto/16 :goto_11

    :cond_13
    check-cast p0, Ljava/util/List;

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result p0

    invoke-static {p1, p0}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;I)Ljava/lang/Object;

    move-result-object p0

    const-string p1, "null cannot be cast to non-null type kotlin.Array<in kotlin.Any?>"

    invoke-static {p0, p1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, [Ljava/lang/Object;

    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    move-result p1

    :goto_f
    if-ge v1, p1, :cond_14

    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    aput-object v0, p0, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_f

    :cond_14
    return-object p0

    :cond_15
    new-instance p0, Ljava/lang/IllegalStateException;

    new-instance p1, Ljava/lang/StringBuilder;

    const-string v1, "Not a class type: "

    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_16
    new-instance p0, Ljava/lang/StringBuilder;

    const-string p1, "Not an array type: "

    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_17
    instance-of v0, p0, Llyiahf/vczjk/zp2;

    if-eqz v0, :cond_18

    check-cast p0, Llyiahf/vczjk/zp2;

    iget-object p0, p0, Llyiahf/vczjk/ij1;->OooO00o:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/xn6;

    invoke-virtual {p0}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/hy0;

    invoke-virtual {p0}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/qt5;

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/mba;->OooO(Ljava/lang/ClassLoader;Llyiahf/vczjk/hy0;I)Ljava/lang/Class;

    move-result-object p1

    if-eqz p1, :cond_1b

    invoke-virtual {p0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object p0

    invoke-static {p1, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    return-object p0

    :cond_18
    instance-of v0, p0, Llyiahf/vczjk/sf4;

    if-eqz v0, :cond_1d

    check-cast p0, Llyiahf/vczjk/sf4;

    iget-object p0, p0, Llyiahf/vczjk/ij1;->OooO00o:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/rf4;

    instance-of v0, p0, Llyiahf/vczjk/qf4;

    if-eqz v0, :cond_19

    check-cast p0, Llyiahf/vczjk/qf4;

    iget-object p0, p0, Llyiahf/vczjk/qf4;->OooO00o:Llyiahf/vczjk/my0;

    iget-object v0, p0, Llyiahf/vczjk/my0;->OooO00o:Llyiahf/vczjk/hy0;

    iget p0, p0, Llyiahf/vczjk/my0;->OooO0O0:I

    invoke-static {p1, v0, p0}, Llyiahf/vczjk/mba;->OooO(Ljava/lang/ClassLoader;Llyiahf/vczjk/hy0;I)Ljava/lang/Class;

    move-result-object p0

    return-object p0

    :cond_19
    instance-of p1, p0, Llyiahf/vczjk/pf4;

    if-eqz p1, :cond_1c

    check-cast p0, Llyiahf/vczjk/pf4;

    iget-object p0, p0, Llyiahf/vczjk/pf4;->OooO00o:Llyiahf/vczjk/uk4;

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p0

    instance-of p1, p0, Llyiahf/vczjk/by0;

    if-eqz p1, :cond_1a

    check-cast p0, Llyiahf/vczjk/by0;

    goto :goto_10

    :cond_1a
    move-object p0, v2

    :goto_10
    if-eqz p0, :cond_1b

    invoke-static {p0}, Llyiahf/vczjk/mba;->OooOO0O(Llyiahf/vczjk/by0;)Ljava/lang/Class;

    move-result-object p0

    return-object p0

    :cond_1b
    :goto_11
    return-object v2

    :cond_1c
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_1d
    instance-of p1, p0, Llyiahf/vczjk/vq2;

    if-nez p1, :cond_1f

    instance-of p1, p0, Llyiahf/vczjk/t46;

    if-eqz p1, :cond_1e

    return-object v2

    :cond_1e
    invoke-virtual {p0}, Llyiahf/vczjk/ij1;->OooO0O0()Ljava/lang/Object;

    move-result-object p0

    return-object p0

    :cond_1f
    return-object v2

    nop

    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_9
        :pswitch_0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method
