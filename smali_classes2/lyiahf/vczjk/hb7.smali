.class public final Llyiahf/vczjk/hb7;
.super Llyiahf/vczjk/la7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ka7;


# instance fields
.field public final OooOoo:Llyiahf/vczjk/hb7;

.field public OooOoo0:Llyiahf/vczjk/tca;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;ZZZILlyiahf/vczjk/hb7;Llyiahf/vczjk/sx8;)V
    .locals 12

    const/4 v0, 0x0

    if-eqz p2, :cond_5

    if-eqz p3, :cond_4

    if-eqz p4, :cond_3

    if-eqz p8, :cond_2

    if-eqz p10, :cond_1

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "<set-"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-interface {p1}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ">"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v6

    move-object v1, p0

    move-object v4, p1

    move-object v5, p2

    move-object v2, p3

    move-object/from16 v3, p4

    move/from16 v7, p5

    move/from16 v8, p6

    move/from16 v9, p7

    move/from16 v10, p8

    move-object/from16 v11, p10

    invoke-direct/range {v1 .. v11}, Llyiahf/vczjk/la7;-><init>(Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;ZZZILlyiahf/vczjk/sx8;)V

    if-eqz p9, :cond_0

    move-object/from16 p1, p9

    goto :goto_0

    :cond_0
    move-object p1, p0

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/hb7;->OooOoo:Llyiahf/vczjk/hb7;

    return-void

    :cond_1
    const/4 p1, 0x5

    invoke-static {p1}, Llyiahf/vczjk/hb7;->o00000O0(I)V

    throw v0

    :cond_2
    const/4 p1, 0x4

    invoke-static {p1}, Llyiahf/vczjk/hb7;->o00000O0(I)V

    throw v0

    :cond_3
    const/4 p1, 0x3

    invoke-static {p1}, Llyiahf/vczjk/hb7;->o00000O0(I)V

    throw v0

    :cond_4
    const/4 p1, 0x2

    invoke-static {p1}, Llyiahf/vczjk/hb7;->o00000O0(I)V

    throw v0

    :cond_5
    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/hb7;->o00000O0(I)V

    throw v0
.end method

.method public static synthetic o00000O0(I)V
    .locals 6

    packed-switch p0, :pswitch_data_0

    const-string v0, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    goto :goto_0

    :pswitch_0
    const-string v0, "@NotNull method %s.%s must not return null"

    :goto_0
    const/4 v1, 0x2

    packed-switch p0, :pswitch_data_1

    const/4 v2, 0x3

    goto :goto_1

    :pswitch_1
    move v2, v1

    :goto_1
    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "kotlin/reflect/jvm/internal/impl/descriptors/impl/PropertySetterDescriptorImpl"

    const/4 v4, 0x0

    packed-switch p0, :pswitch_data_2

    const-string v5, "correspondingProperty"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_2
    aput-object v3, v2, v4

    goto :goto_2

    :pswitch_3
    const-string v5, "type"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_4
    const-string v5, "setterDescriptor"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_5
    const-string v5, "parameter"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_6
    const-string v5, "source"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_7
    const-string v5, "kind"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_8
    const-string v5, "visibility"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_9
    const-string v5, "modality"

    aput-object v5, v2, v4

    goto :goto_2

    :pswitch_a
    const-string v5, "annotations"

    aput-object v5, v2, v4

    :goto_2
    const/4 v4, 0x1

    packed-switch p0, :pswitch_data_3

    aput-object v3, v2, v4

    goto :goto_3

    :pswitch_b
    const-string v3, "getOriginal"

    aput-object v3, v2, v4

    goto :goto_3

    :pswitch_c
    const-string v3, "getReturnType"

    aput-object v3, v2, v4

    goto :goto_3

    :pswitch_d
    const-string v3, "getValueParameters"

    aput-object v3, v2, v4

    goto :goto_3

    :pswitch_e
    const-string v3, "getOverriddenDescriptors"

    aput-object v3, v2, v4

    :goto_3
    packed-switch p0, :pswitch_data_4

    const-string v3, "<init>"

    aput-object v3, v2, v1

    goto :goto_4

    :pswitch_f
    const-string v3, "createSetterParameter"

    aput-object v3, v2, v1

    goto :goto_4

    :pswitch_10
    const-string v3, "initialize"

    aput-object v3, v2, v1

    :goto_4
    :pswitch_11
    invoke-static {v0, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    packed-switch p0, :pswitch_data_5

    new-instance p0, Ljava/lang/IllegalArgumentException;

    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    goto :goto_5

    :pswitch_12
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    :goto_5
    throw p0

    :pswitch_data_0
    .packed-switch 0xa
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch

    :pswitch_data_1
    .packed-switch 0xa
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
    .end packed-switch

    :pswitch_data_2
    .packed-switch 0x1
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_a
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
    .end packed-switch

    :pswitch_data_3
    .packed-switch 0xa
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
    .end packed-switch

    :pswitch_data_4
    .packed-switch 0x6
        :pswitch_10
        :pswitch_f
        :pswitch_f
        :pswitch_f
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
    .end packed-switch

    :pswitch_data_5
    .packed-switch 0xa
        :pswitch_12
        :pswitch_12
        :pswitch_12
        :pswitch_12
    .end packed-switch
.end method

.method public static o000OO(Llyiahf/vczjk/hb7;Llyiahf/vczjk/uk4;Llyiahf/vczjk/ko;)Llyiahf/vczjk/tca;
    .locals 13

    const/4 v0, 0x0

    if-eqz p1, :cond_1

    if-eqz p2, :cond_0

    new-instance v1, Llyiahf/vczjk/tca;

    sget-object v6, Llyiahf/vczjk/vy8;->OooO0oO:Llyiahf/vczjk/qt5;

    sget-object v12, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    move-object v2, p0

    move-object v7, p1

    move-object v5, p2

    invoke-direct/range {v1 .. v12}, Llyiahf/vczjk/tca;-><init>(Llyiahf/vczjk/co0;Llyiahf/vczjk/tca;ILlyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/uk4;ZZZLlyiahf/vczjk/uk4;Llyiahf/vczjk/sx8;)V

    return-object v1

    :cond_0
    const/16 p0, 0x9

    invoke-static {p0}, Llyiahf/vczjk/hb7;->o00000O0(I)V

    throw v0

    :cond_1
    const/16 p0, 0x8

    invoke-static {p0}, Llyiahf/vczjk/hb7;->o00000O0(I)V

    throw v0
.end method


# virtual methods
.method public final bridge synthetic OooO00o()Llyiahf/vczjk/co0;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/hb7;->o0000O()Llyiahf/vczjk/hb7;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic OooO00o()Llyiahf/vczjk/eo0;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/hb7;->o0000O()Llyiahf/vczjk/hb7;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic OooO00o()Llyiahf/vczjk/rf3;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/hb7;->o0000O()Llyiahf/vczjk/hb7;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic OooO00o()Llyiahf/vczjk/v02;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/hb7;->o0000O()Llyiahf/vczjk/hb7;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOO0()Ljava/util/Collection;
    .locals 1

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/la7;->o0000O0O(Z)Ljava/util/ArrayList;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOoo()Llyiahf/vczjk/uk4;
    .locals 1

    invoke-static {p0}, Llyiahf/vczjk/p72;->OooO0o0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hk4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/hk4;->OooOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    return-object v0
.end method

.method public final OoooOOO()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hb7;->OooOoo0:Llyiahf/vczjk/tca;

    if-eqz v0, :cond_1

    invoke-static {v0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0xb

    invoke-static {v0}, Llyiahf/vczjk/hb7;->o00000O0(I)V

    const/4 v0, 0x0

    throw v0

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    throw v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/z02;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p1, p0, p2}, Llyiahf/vczjk/z02;->OooOoO0(Llyiahf/vczjk/hb7;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final o0000O()Llyiahf/vczjk/hb7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hb7;->OooOoo:Llyiahf/vczjk/hb7;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/16 v0, 0xd

    invoke-static {v0}, Llyiahf/vczjk/hb7;->o00000O0(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final bridge synthetic o0000oO()Llyiahf/vczjk/x02;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/hb7;->o0000O()Llyiahf/vczjk/hb7;

    move-result-object v0

    return-object v0
.end method
