.class public final Llyiahf/vczjk/vw4;
.super Llyiahf/vczjk/yl5;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/i5a;

.field public final OooOOO0:Llyiahf/vczjk/yl5;

.field public OooOOOO:Llyiahf/vczjk/i5a;

.field public OooOOOo:Ljava/util/ArrayList;

.field public OooOOo:Llyiahf/vczjk/sy0;

.field public OooOOo0:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yl5;Llyiahf/vczjk/i5a;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    iput-object p2, p0, Llyiahf/vczjk/vw4;->OooOOO:Llyiahf/vczjk/i5a;

    return-void
.end method

.method public static synthetic o000oOoO(I)V
    .locals 15

    const/16 v0, 0x17

    const/16 v1, 0xd

    const/16 v2, 0xa

    const/16 v3, 0x8

    const/4 v4, 0x6

    const/4 v5, 0x5

    const/4 v6, 0x3

    const/4 v7, 0x2

    if-eq p0, v7, :cond_0

    if-eq p0, v6, :cond_0

    if-eq p0, v5, :cond_0

    if-eq p0, v4, :cond_0

    if-eq p0, v3, :cond_0

    if-eq p0, v2, :cond_0

    if-eq p0, v1, :cond_0

    if-eq p0, v0, :cond_0

    const-string v8, "@NotNull method %s.%s must not return null"

    goto :goto_0

    :cond_0
    const-string v8, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    :goto_0
    if-eq p0, v7, :cond_1

    if-eq p0, v6, :cond_1

    if-eq p0, v5, :cond_1

    if-eq p0, v4, :cond_1

    if-eq p0, v3, :cond_1

    if-eq p0, v2, :cond_1

    if-eq p0, v1, :cond_1

    if-eq p0, v0, :cond_1

    move v9, v7

    goto :goto_1

    :cond_1
    move v9, v6

    :goto_1
    new-array v9, v9, [Ljava/lang/Object;

    const-string v10, "kotlin/reflect/jvm/internal/impl/descriptors/impl/LazySubstitutingClassDescriptor"

    const/4 v11, 0x0

    if-eq p0, v7, :cond_5

    if-eq p0, v6, :cond_4

    if-eq p0, v5, :cond_3

    if-eq p0, v4, :cond_4

    if-eq p0, v3, :cond_5

    if-eq p0, v2, :cond_3

    if-eq p0, v1, :cond_4

    if-eq p0, v0, :cond_2

    aput-object v10, v9, v11

    goto :goto_2

    :cond_2
    const-string v12, "substitutor"

    aput-object v12, v9, v11

    goto :goto_2

    :cond_3
    const-string v12, "typeSubstitution"

    aput-object v12, v9, v11

    goto :goto_2

    :cond_4
    const-string v12, "kotlinTypeRefiner"

    aput-object v12, v9, v11

    goto :goto_2

    :cond_5
    const-string v12, "typeArguments"

    aput-object v12, v9, v11

    :goto_2
    const-string v11, "getMemberScope"

    const-string v12, "getUnsubstitutedMemberScope"

    const-string v13, "substitute"

    const/4 v14, 0x1

    packed-switch p0, :pswitch_data_0

    const-string v10, "getTypeConstructor"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_0
    const-string v10, "getSealedSubclasses"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_1
    const-string v10, "getDeclaredTypeParameters"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_2
    const-string v10, "getSource"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_3
    const-string v10, "getUnsubstitutedInnerClassesScope"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_4
    const-string v10, "getVisibility"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_5
    const-string v10, "getModality"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_6
    const-string v10, "getKind"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_7
    aput-object v13, v9, v14

    goto :goto_3

    :pswitch_8
    const-string v10, "getContainingDeclaration"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_9
    const-string v10, "getOriginal"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_a
    const-string v10, "getName"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_b
    const-string v10, "getAnnotations"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_c
    const-string v10, "getConstructors"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_d
    const-string v10, "getContextReceivers"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_e
    const-string v10, "getDefaultType"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_f
    const-string v10, "getStaticScope"

    aput-object v10, v9, v14

    goto :goto_3

    :pswitch_10
    aput-object v12, v9, v14

    goto :goto_3

    :pswitch_11
    aput-object v11, v9, v14

    goto :goto_3

    :pswitch_12
    aput-object v10, v9, v14

    :goto_3
    if-eq p0, v7, :cond_8

    if-eq p0, v6, :cond_8

    if-eq p0, v5, :cond_8

    if-eq p0, v4, :cond_8

    if-eq p0, v3, :cond_8

    if-eq p0, v2, :cond_8

    if-eq p0, v1, :cond_7

    if-eq p0, v0, :cond_6

    goto :goto_4

    :cond_6
    aput-object v13, v9, v7

    goto :goto_4

    :cond_7
    aput-object v12, v9, v7

    goto :goto_4

    :cond_8
    aput-object v11, v9, v7

    :goto_4
    invoke-static {v8, v9}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v8

    if-eq p0, v7, :cond_9

    if-eq p0, v6, :cond_9

    if-eq p0, v5, :cond_9

    if-eq p0, v4, :cond_9

    if-eq p0, v3, :cond_9

    if-eq p0, v2, :cond_9

    if-eq p0, v1, :cond_9

    if-eq p0, v0, :cond_9

    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    goto :goto_5

    :cond_9
    new-instance p0, Ljava/lang/IllegalArgumentException;

    invoke-direct {p0, v8}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    :goto_5
    throw p0

    nop

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_12
        :pswitch_12
        :pswitch_11
        :pswitch_12
        :pswitch_12
        :pswitch_11
        :pswitch_12
        :pswitch_11
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_12
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_12
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/yk5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooO()Llyiahf/vczjk/yk5;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x1a

    invoke-static {v0}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooO00o()Llyiahf/vczjk/by0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooO00o()Llyiahf/vczjk/by0;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x15

    invoke-static {v0}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooO0Oo()Llyiahf/vczjk/q72;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x1b

    invoke-static {v0}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooO0o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooO0o()Z

    move-result v0

    return v0
.end method

.method public final OooO0o0(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/x02;
    .locals 2

    if-eqz p1, :cond_1

    iget-object v0, p1, Llyiahf/vczjk/i5a;->OooO00o:Llyiahf/vczjk/g5a;

    invoke-virtual {v0}, Llyiahf/vczjk/g5a;->OooO0o0()Z

    move-result v0

    if-eqz v0, :cond_0

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/vw4;

    invoke-virtual {p1}, Llyiahf/vczjk/i5a;->OooO0o()Llyiahf/vczjk/g5a;

    move-result-object p1

    invoke-virtual {p0}, Llyiahf/vczjk/vw4;->OoooOOo()Llyiahf/vczjk/i5a;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/i5a;->OooO0o()Llyiahf/vczjk/g5a;

    move-result-object v1

    invoke-static {p1, v1}, Llyiahf/vczjk/i5a;->OooO0o0(Llyiahf/vczjk/g5a;Llyiahf/vczjk/g5a;)Llyiahf/vczjk/i5a;

    move-result-object p1

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/vw4;-><init>(Llyiahf/vczjk/yl5;Llyiahf/vczjk/i5a;)V

    return-object v0

    :cond_1
    const/16 p1, 0x17

    invoke-static {p1}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooO0oO()Llyiahf/vczjk/sx8;
    .locals 1

    sget-object v0, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    return-object v0
.end method

.method public final OooOO0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOO0()Z

    move-result v0

    return v0
.end method

.method public final OooOO0o()Llyiahf/vczjk/v02;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x16

    invoke-static {v0}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOOOO(Llyiahf/vczjk/g5a;Llyiahf/vczjk/al4;)Llyiahf/vczjk/jg5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/yl5;->OooOOOO(Llyiahf/vczjk/g5a;Llyiahf/vczjk/al4;)Llyiahf/vczjk/jg5;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/vw4;->OooOOO:Llyiahf/vczjk/i5a;

    iget-object p2, p2, Llyiahf/vczjk/i5a;->OooO00o:Llyiahf/vczjk/g5a;

    invoke-virtual {p2}, Llyiahf/vczjk/g5a;->OooO0o0()Z

    move-result p2

    if-eqz p2, :cond_1

    if-eqz p1, :cond_0

    return-object p1

    :cond_0
    const/4 p1, 0x7

    invoke-static {p1}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 p1, 0x0

    throw p1

    :cond_1
    new-instance p2, Llyiahf/vczjk/i99;

    invoke-virtual {p0}, Llyiahf/vczjk/vw4;->OoooOOo()Llyiahf/vczjk/i5a;

    move-result-object v0

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/i99;-><init>(Llyiahf/vczjk/jg5;Llyiahf/vczjk/i5a;)V

    return-object p2
.end method

.method public final OooOOOo()Llyiahf/vczjk/dp8;
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/vw4;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/l5a;->OooO0Oo(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/vw4;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/ko;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_0

    sget-object v1, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/d3a;->OooOOOO:Llyiahf/vczjk/d3a;

    goto :goto_0

    :cond_0
    sget-object v2, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    new-instance v3, Llyiahf/vczjk/qo;

    invoke-direct {v3, v1}, Llyiahf/vczjk/qo;-><init>(Llyiahf/vczjk/ko;)V

    invoke-static {v3}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/xo8;->OooO0o(Ljava/util/List;)Llyiahf/vczjk/d3a;

    move-result-object v1

    :goto_0
    invoke-virtual {p0}, Llyiahf/vczjk/vw4;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v2

    invoke-virtual {p0}, Llyiahf/vczjk/vw4;->o0OO00O()Llyiahf/vczjk/jg5;

    move-result-object v3

    const/4 v4, 0x0

    invoke-static {v0, v3, v1, v2, v4}, Llyiahf/vczjk/so8;->Oooo0oo(Ljava/util/List;Llyiahf/vczjk/jg5;Llyiahf/vczjk/d3a;Llyiahf/vczjk/n3a;Z)Llyiahf/vczjk/dp8;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOo0()Llyiahf/vczjk/ko;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/gm;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x13

    invoke-static {v0}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOo()Z

    move-result v0

    return v0
.end method

.method public final OooOo00()Ljava/util/List;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/vw4;->OoooOOo()Llyiahf/vczjk/i5a;

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOo0:Ljava/util/ArrayList;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x1e

    invoke-static {v0}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOo0O()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/yf5;->OooOo0O()Z

    move-result v0

    return v0
.end method

.method public final OooOo0o()Llyiahf/vczjk/n3a;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/vw4;->OooOOO:Llyiahf/vczjk/i5a;

    iget-object v1, v1, Llyiahf/vczjk/i5a;->OooO00o:Llyiahf/vczjk/g5a;

    invoke-virtual {v1}, Llyiahf/vczjk/g5a;->OooO0o0()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/4 v0, 0x0

    invoke-static {v0}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    throw v2

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/vw4;->OooOOo:Llyiahf/vczjk/sy0;

    if-nez v1, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/vw4;->OoooOOo()Llyiahf/vczjk/i5a;

    move-result-object v1

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO0O0()Ljava/util/Collection;

    move-result-object v0

    new-instance v3, Ljava/util/ArrayList;

    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v4

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/uk4;

    sget-object v5, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    invoke-virtual {v1, v4, v5}, Llyiahf/vczjk/i5a;->OooO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    new-instance v0, Llyiahf/vczjk/sy0;

    iget-object v1, p0, Llyiahf/vczjk/vw4;->OooOOOo:Ljava/util/ArrayList;

    sget-object v4, Llyiahf/vczjk/q45;->OooO0o0:Llyiahf/vczjk/i45;

    invoke-direct {v0, p0, v1, v3, v4}, Llyiahf/vczjk/sy0;-><init>(Llyiahf/vczjk/yl5;Ljava/util/List;Ljava/util/Collection;Llyiahf/vczjk/q45;)V

    iput-object v0, p0, Llyiahf/vczjk/vw4;->OooOOo:Llyiahf/vczjk/sy0;

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOo:Llyiahf/vczjk/sy0;

    if-eqz v0, :cond_4

    return-object v0

    :cond_4
    const/4 v0, 0x1

    invoke-static {v0}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    throw v2
.end method

.method public final OooOoO()Ljava/util/Collection;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOoO()Ljava/util/Collection;

    move-result-object v0

    new-instance v1, Ljava/util/ArrayList;

    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ux0;

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/tf3;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/i5a;->OooO0O0:Llyiahf/vczjk/i5a;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/tf3;->o0000OOO(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/sf3;

    move-result-object v4

    invoke-virtual {v2}, Llyiahf/vczjk/ux0;->o0000o0o()Llyiahf/vczjk/ux0;

    move-result-object v2

    iput-object v2, v4, Llyiahf/vczjk/sf3;->OooOOo0:Llyiahf/vczjk/rf3;

    invoke-virtual {v3}, Llyiahf/vczjk/tf3;->OooO()Llyiahf/vczjk/yk5;

    move-result-object v2

    invoke-virtual {v4, v2}, Llyiahf/vczjk/sf3;->OooOooO(Llyiahf/vczjk/yk5;)Llyiahf/vczjk/qf3;

    invoke-virtual {v3}, Llyiahf/vczjk/tf3;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v2

    invoke-virtual {v4, v2}, Llyiahf/vczjk/sf3;->o000oOoO(Llyiahf/vczjk/q72;)Llyiahf/vczjk/qf3;

    invoke-virtual {v3}, Llyiahf/vczjk/tf3;->getKind()I

    move-result v2

    invoke-virtual {v4, v2}, Llyiahf/vczjk/sf3;->OooOOO0(I)Llyiahf/vczjk/qf3;

    const/4 v2, 0x0

    iput-boolean v2, v4, Llyiahf/vczjk/sf3;->OooOoO0:Z

    iget-object v2, v4, Llyiahf/vczjk/sf3;->Oooo0O0:Llyiahf/vczjk/tf3;

    invoke-virtual {v2, v4}, Llyiahf/vczjk/tf3;->o0000O(Llyiahf/vczjk/sf3;)Llyiahf/vczjk/tf3;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ux0;

    invoke-virtual {p0}, Llyiahf/vczjk/vw4;->OoooOOo()Llyiahf/vczjk/i5a;

    move-result-object v3

    invoke-virtual {v2, v3}, Llyiahf/vczjk/ux0;->o0000oOO(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/ux0;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    return-object v1
.end method

.method public final OooOoo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOoo()Z

    move-result v0

    return v0
.end method

.method public final OooOooO(Llyiahf/vczjk/g5a;)Llyiahf/vczjk/jg5;
    .locals 1

    invoke-static {p0}, Llyiahf/vczjk/n72;->OooO0Oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/cm5;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/p72;->OooO(Llyiahf/vczjk/cm5;)V

    sget-object v0, Llyiahf/vczjk/al4;->OooO00o:Llyiahf/vczjk/al4;

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/vw4;->OooOOOO(Llyiahf/vczjk/g5a;Llyiahf/vczjk/al4;)Llyiahf/vczjk/jg5;

    move-result-object p1

    return-object p1
.end method

.method public final Oooo0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/yf5;->Oooo0()Z

    move-result v0

    return v0
.end method

.method public final Oooo00o()Ljava/util/Collection;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->Oooo00o()Ljava/util/Collection;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x1f

    invoke-static {v0}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final Oooo0O0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/hz0;->Oooo0O0()Z

    move-result v0

    return v0
.end method

.method public final Oooo0oO(Llyiahf/vczjk/al4;)Llyiahf/vczjk/jg5;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yl5;->Oooo0oO(Llyiahf/vczjk/al4;)Llyiahf/vczjk/jg5;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO:Llyiahf/vczjk/i5a;

    iget-object v0, v0, Llyiahf/vczjk/i5a;->OooO00o:Llyiahf/vczjk/g5a;

    invoke-virtual {v0}, Llyiahf/vczjk/g5a;->OooO0o0()Z

    move-result v0

    if-eqz v0, :cond_1

    if-eqz p1, :cond_0

    return-object p1

    :cond_0
    const/16 p1, 0xe

    invoke-static {p1}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 p1, 0x0

    throw p1

    :cond_1
    new-instance v0, Llyiahf/vczjk/i99;

    invoke-virtual {p0}, Llyiahf/vczjk/vw4;->OoooOOo()Llyiahf/vczjk/i5a;

    move-result-object v1

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/i99;-><init>(Llyiahf/vczjk/jg5;Llyiahf/vczjk/i5a;)V

    return-object v0
.end method

.method public final OoooO0()Llyiahf/vczjk/jg5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OoooO0()Llyiahf/vczjk/jg5;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0xf

    invoke-static {v0}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OoooO00()Llyiahf/vczjk/ux0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OoooO00()Llyiahf/vczjk/ux0;

    move-result-object v0

    return-object v0
.end method

.method public final OoooOOo()Llyiahf/vczjk/i5a;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOOO:Llyiahf/vczjk/i5a;

    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO:Llyiahf/vczjk/i5a;

    iget-object v1, v0, Llyiahf/vczjk/i5a;->OooO00o:Llyiahf/vczjk/g5a;

    invoke-virtual {v1}, Llyiahf/vczjk/g5a;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_0

    iput-object v0, p0, Llyiahf/vczjk/vw4;->OooOOOO:Llyiahf/vczjk/i5a;

    goto :goto_1

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v1}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v1

    new-instance v2, Ljava/util/ArrayList;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v3

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v2, p0, Llyiahf/vczjk/vw4;->OooOOOo:Ljava/util/ArrayList;

    invoke-virtual {v0}, Llyiahf/vczjk/i5a;->OooO0o()Llyiahf/vczjk/g5a;

    move-result-object v0

    iget-object v2, p0, Llyiahf/vczjk/vw4;->OooOOOo:Ljava/util/ArrayList;

    invoke-static {v1, v0, p0, v2}, Llyiahf/vczjk/os9;->o000oOoO(Ljava/util/List;Llyiahf/vczjk/g5a;Llyiahf/vczjk/v02;Ljava/util/ArrayList;)Llyiahf/vczjk/i5a;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/vw4;->OooOOOO:Llyiahf/vczjk/i5a;

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOOo:Ljava/util/ArrayList;

    const-string v1, "<this>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_1
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/t4a;

    invoke-interface {v3}, Llyiahf/vczjk/t4a;->ooOO()Z

    move-result v3

    if-nez v3, :cond_1

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    iput-object v1, p0, Llyiahf/vczjk/vw4;->OooOOo0:Ljava/util/ArrayList;

    :cond_3
    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOOO:Llyiahf/vczjk/i5a;

    return-object v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/z02;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p1, p0, p2}, Llyiahf/vczjk/z02;->OooO0oo(Llyiahf/vczjk/yl5;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final getKind()Llyiahf/vczjk/ly0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->getKind()Llyiahf/vczjk/ly0;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x19

    invoke-static {v0}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final getName()Llyiahf/vczjk/qt5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x14

    invoke-static {v0}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final o00000()Llyiahf/vczjk/mp4;
    .locals 1

    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw v0
.end method

.method public final o000000O()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->o000000O()Z

    move-result v0

    return v0
.end method

.method public final o0O0O00()Ljava/util/List;
    .locals 1

    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x11

    invoke-static {v0}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final o0OO00O()Llyiahf/vczjk/jg5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-static {v0}, Llyiahf/vczjk/n72;->OooO0Oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/cm5;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/p72;->OooO(Llyiahf/vczjk/cm5;)V

    sget-object v0, Llyiahf/vczjk/al4;->OooO00o:Llyiahf/vczjk/al4;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/vw4;->Oooo0oO(Llyiahf/vczjk/al4;)Llyiahf/vczjk/jg5;

    move-result-object v0

    return-object v0
.end method

.method public final o0ooOO0()Llyiahf/vczjk/jg5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->o0ooOO0()Llyiahf/vczjk/jg5;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x1c

    invoke-static {v0}, Llyiahf/vczjk/vw4;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final o0ooOOo()Llyiahf/vczjk/fca;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->o0ooOOo()Llyiahf/vczjk/fca;

    move-result-object v0

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    instance-of v1, v0, Llyiahf/vczjk/tz3;

    iget-object v2, p0, Llyiahf/vczjk/vw4;->OooOOO:Llyiahf/vczjk/i5a;

    if-eqz v1, :cond_3

    new-instance v1, Llyiahf/vczjk/tz3;

    check-cast v0, Llyiahf/vczjk/tz3;

    iget-object v3, v0, Llyiahf/vczjk/tz3;->OooO0O0:Llyiahf/vczjk/pt7;

    check-cast v3, Llyiahf/vczjk/dp8;

    if-eqz v3, :cond_2

    iget-object v2, v2, Llyiahf/vczjk/i5a;->OooO00o:Llyiahf/vczjk/g5a;

    invoke-virtual {v2}, Llyiahf/vczjk/g5a;->OooO0o0()Z

    move-result v2

    if-eqz v2, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/vw4;->OoooOOo()Llyiahf/vczjk/i5a;

    move-result-object v2

    sget-object v4, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/i5a;->OooO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/dp8;

    :cond_2
    :goto_0
    iget-object v0, v0, Llyiahf/vczjk/tz3;->OooO00o:Llyiahf/vczjk/qt5;

    invoke-direct {v1, v0, v3}, Llyiahf/vczjk/tz3;-><init>(Llyiahf/vczjk/qt5;Llyiahf/vczjk/pt7;)V

    return-object v1

    :cond_3
    instance-of v1, v0, Llyiahf/vczjk/bq5;

    if-eqz v1, :cond_7

    check-cast v0, Llyiahf/vczjk/bq5;

    new-instance v1, Ljava/util/ArrayList;

    iget-object v0, v0, Llyiahf/vczjk/bq5;->OooO00o:Ljava/util/ArrayList;

    const/16 v3, 0xa

    invoke-static {v0, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_6

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/xn6;

    invoke-virtual {v3}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/qt5;

    invoke-virtual {v3}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pt7;

    check-cast v3, Llyiahf/vczjk/dp8;

    if-eqz v3, :cond_5

    iget-object v5, v2, Llyiahf/vczjk/i5a;->OooO00o:Llyiahf/vczjk/g5a;

    invoke-virtual {v5}, Llyiahf/vczjk/g5a;->OooO0o0()Z

    move-result v5

    if-eqz v5, :cond_4

    goto :goto_2

    :cond_4
    invoke-virtual {p0}, Llyiahf/vczjk/vw4;->OoooOOo()Llyiahf/vczjk/i5a;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    invoke-virtual {v5, v3, v6}, Llyiahf/vczjk/i5a;->OooO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/dp8;

    :cond_5
    :goto_2
    new-instance v5, Llyiahf/vczjk/xn6;

    invoke-direct {v5, v4, v3}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_6
    new-instance v0, Llyiahf/vczjk/bq5;

    invoke-direct {v0, v1}, Llyiahf/vczjk/bq5;-><init>(Ljava/util/ArrayList;)V

    return-object v0

    :cond_7
    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0
.end method

.method public final oo0o0Oo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw4;->OooOOO0:Llyiahf/vczjk/yl5;

    invoke-interface {v0}, Llyiahf/vczjk/yf5;->oo0o0Oo()Z

    move-result v0

    return v0
.end method
