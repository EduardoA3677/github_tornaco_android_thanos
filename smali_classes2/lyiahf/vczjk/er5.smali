.class public final Llyiahf/vczjk/er5;
.super Llyiahf/vczjk/cy0;
.source "SourceFile"


# instance fields
.field public final OooOOoo:Llyiahf/vczjk/ly0;

.field public final OooOo:Ljava/util/ArrayList;

.field public OooOo0:Llyiahf/vczjk/q72;

.field public OooOo00:Llyiahf/vczjk/yk5;

.field public OooOo0O:Llyiahf/vczjk/sy0;

.field public OooOo0o:Ljava/util/ArrayList;

.field public final OooOoO0:Llyiahf/vczjk/i45;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dn2;Llyiahf/vczjk/qt5;Llyiahf/vczjk/i45;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/ly0;->OooOOO:Llyiahf/vczjk/ly0;

    sget-object v1, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    if-eqz p3, :cond_0

    invoke-direct {p0, p3, p1, p2, v1}, Llyiahf/vczjk/cy0;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/v02;Llyiahf/vczjk/qt5;Llyiahf/vczjk/sx8;)V

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/er5;->OooOo:Ljava/util/ArrayList;

    iput-object p3, p0, Llyiahf/vczjk/er5;->OooOoO0:Llyiahf/vczjk/i45;

    iput-object v0, p0, Llyiahf/vczjk/er5;->OooOOoo:Llyiahf/vczjk/ly0;

    return-void

    :cond_0
    const/4 p1, 0x4

    invoke-static {p1}, Llyiahf/vczjk/er5;->o000oOoO(I)V

    const/4 p1, 0x0

    throw p1
.end method

.method public static synthetic o000oOoO(I)V
    .locals 6

    packed-switch p0, :pswitch_data_0

    :pswitch_0
    const-string v0, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    goto :goto_0

    :pswitch_1
    const-string v0, "@NotNull method %s.%s must not return null"

    :goto_0
    const/4 v1, 0x2

    packed-switch p0, :pswitch_data_1

    :pswitch_2
    const/4 v2, 0x3

    goto :goto_1

    :pswitch_3
    move v2, v1

    :goto_1
    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "kotlin/reflect/jvm/internal/impl/descriptors/impl/MutableClassDescriptor"

    const/4 v4, 0x0

    packed-switch p0, :pswitch_data_2

    const-string v5, "containingDeclaration"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_4
    const-string v5, "kotlinTypeRefiner"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_5
    const-string v5, "typeParameters"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_6
    const-string v5, "supertype"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_7
    const-string v5, "visibility"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_8
    const-string v5, "modality"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_9
    aput-object v3, v2, v4

    goto :goto_2

    :pswitch_a
    const-string v5, "storageManager"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_b
    const-string v5, "source"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_c
    const-string v5, "name"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_d
    const-string v5, "kind"

    aput-object v5, v2, v4

    :goto_2
    const-string v4, "getUnsubstitutedMemberScope"

    const/4 v5, 0x1

    packed-switch p0, :pswitch_data_3

    :pswitch_e
    aput-object v3, v2, v5

    goto :goto_3

    :pswitch_f
    const-string v3, "getSealedSubclasses"

    aput-object v3, v2, v5

    goto :goto_3

    :pswitch_10
    const-string v3, "getStaticScope"

    aput-object v3, v2, v5

    goto :goto_3

    :pswitch_11
    aput-object v4, v2, v5

    goto :goto_3

    :pswitch_12
    const-string v3, "getDeclaredTypeParameters"

    aput-object v3, v2, v5

    goto :goto_3

    :pswitch_13
    const-string v3, "getConstructors"

    aput-object v3, v2, v5

    goto :goto_3

    :pswitch_14
    const-string v3, "getTypeConstructor"

    aput-object v3, v2, v5

    goto :goto_3

    :pswitch_15
    const-string v3, "getVisibility"

    aput-object v3, v2, v5

    goto :goto_3

    :pswitch_16
    const-string v3, "getKind"

    aput-object v3, v2, v5

    goto :goto_3

    :pswitch_17
    const-string v3, "getModality"

    aput-object v3, v2, v5

    goto :goto_3

    :pswitch_18
    const-string v3, "getAnnotations"

    aput-object v3, v2, v5

    :goto_3
    packed-switch p0, :pswitch_data_4

    const-string v3, "<init>"

    aput-object v3, v2, v1

    goto :goto_4

    :pswitch_19
    aput-object v4, v2, v1

    goto :goto_4

    :pswitch_1a
    const-string v3, "setTypeParameterDescriptors"

    aput-object v3, v2, v1

    goto :goto_4

    :pswitch_1b
    const-string v3, "addSupertype"

    aput-object v3, v2, v1

    goto :goto_4

    :pswitch_1c
    const-string v3, "setVisibility"

    aput-object v3, v2, v1

    goto :goto_4

    :pswitch_1d
    const-string v3, "setModality"

    aput-object v3, v2, v1

    :goto_4
    :pswitch_1e
    invoke-static {v0, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    packed-switch p0, :pswitch_data_5

    :pswitch_1f
    new-instance p0, Ljava/lang/IllegalArgumentException;

    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    goto :goto_5

    :pswitch_20
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    :goto_5
    throw p0

    :pswitch_data_0
    .packed-switch 0x5
        :pswitch_1
        :pswitch_0
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_1
        :pswitch_0
        :pswitch_1
        :pswitch_0
        :pswitch_1
        :pswitch_1
        :pswitch_1
    .end packed-switch

    :pswitch_data_1
    .packed-switch 0x5
        :pswitch_3
        :pswitch_2
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_3
        :pswitch_2
        :pswitch_3
        :pswitch_2
        :pswitch_3
        :pswitch_3
        :pswitch_3
    .end packed-switch

    :pswitch_data_2
    .packed-switch 0x1
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_9
        :pswitch_9
        :pswitch_7
        :pswitch_9
        :pswitch_9
        :pswitch_6
        :pswitch_9
        :pswitch_5
        :pswitch_9
        :pswitch_4
        :pswitch_9
        :pswitch_9
        :pswitch_9
    .end packed-switch

    :pswitch_data_3
    .packed-switch 0x5
        :pswitch_18
        :pswitch_e
        :pswitch_17
        :pswitch_16
        :pswitch_e
        :pswitch_15
        :pswitch_14
        :pswitch_e
        :pswitch_13
        :pswitch_e
        :pswitch_12
        :pswitch_e
        :pswitch_11
        :pswitch_10
        :pswitch_f
    .end packed-switch

    :pswitch_data_4
    .packed-switch 0x5
        :pswitch_1e
        :pswitch_1d
        :pswitch_1e
        :pswitch_1e
        :pswitch_1c
        :pswitch_1e
        :pswitch_1e
        :pswitch_1b
        :pswitch_1e
        :pswitch_1a
        :pswitch_1e
        :pswitch_19
        :pswitch_1e
        :pswitch_1e
        :pswitch_1e
    .end packed-switch

    :pswitch_data_5
    .packed-switch 0x5
        :pswitch_20
        :pswitch_1f
        :pswitch_20
        :pswitch_20
        :pswitch_1f
        :pswitch_20
        :pswitch_20
        :pswitch_1f
        :pswitch_20
        :pswitch_1f
        :pswitch_20
        :pswitch_1f
        :pswitch_20
        :pswitch_20
        :pswitch_20
    .end packed-switch
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/yk5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er5;->OooOo00:Llyiahf/vczjk/yk5;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/4 v0, 0x7

    invoke-static {v0}, Llyiahf/vczjk/er5;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooO0Oo()Llyiahf/vczjk/q72;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er5;->OooOo0:Llyiahf/vczjk/q72;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0xa

    invoke-static {v0}, Llyiahf/vczjk/er5;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooO0o()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOO0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOo0()Llyiahf/vczjk/ko;
    .locals 1

    sget-object v0, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    return-object v0
.end method

.method public final OooOo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo00()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er5;->OooOo0o:Ljava/util/ArrayList;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0xf

    invoke-static {v0}, Llyiahf/vczjk/er5;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOo0o()Llyiahf/vczjk/n3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er5;->OooOo0O:Llyiahf/vczjk/sy0;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0xb

    invoke-static {v0}, Llyiahf/vczjk/er5;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOoO()Ljava/util/Collection;
    .locals 1

    sget-object v0, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0xd

    invoke-static {v0}, Llyiahf/vczjk/er5;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOoo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo00o()Ljava/util/Collection;
    .locals 1

    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x13

    invoke-static {v0}, Llyiahf/vczjk/er5;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final Oooo0O0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo0oO(Llyiahf/vczjk/al4;)Llyiahf/vczjk/jg5;
    .locals 0

    sget-object p1, Llyiahf/vczjk/ig5;->OooO0O0:Llyiahf/vczjk/ig5;

    return-object p1
.end method

.method public final OoooO0()Llyiahf/vczjk/jg5;
    .locals 1

    sget-object v0, Llyiahf/vczjk/ig5;->OooO0O0:Llyiahf/vczjk/ig5;

    return-object v0
.end method

.method public final OoooO00()Llyiahf/vczjk/ux0;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final getKind()Llyiahf/vczjk/ly0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er5;->OooOOoo:Llyiahf/vczjk/ly0;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0x8

    invoke-static {v0}, Llyiahf/vczjk/er5;->o000oOoO(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final o000000O()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final o0ooOOo()Llyiahf/vczjk/fca;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final oo0o0Oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    invoke-static {p0}, Llyiahf/vczjk/w02;->o0000oo(Llyiahf/vczjk/v02;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
