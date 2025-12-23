.class public final Llyiahf/vczjk/o0O000;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/o0O000;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/o0O000;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/o0O000;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Z)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/o0O000;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/o0O000;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/o0O000;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ds4;Llyiahf/vczjk/im7;Llyiahf/vczjk/hl7;)V
    .locals 0

    const/16 p2, 0x18

    iput p2, p0, Llyiahf/vczjk/o0O000;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/o0O000;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/o0O000;->OooOOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 36

    move-object/from16 v1, p0

    const-string v0, "additionalAnnotations"

    const-string v2, "<this>"

    const-string v3, "getContainingDeclaration(...)"

    const/4 v4, 0x2

    sget-object v5, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    const/16 v6, 0xa

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x1

    sget-object v10, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v11, v1, Llyiahf/vczjk/o0O000;->OooOOO:Ljava/lang/Object;

    iget-object v12, v1, Llyiahf/vczjk/o0O000;->OooOOOO:Ljava/lang/Object;

    iget v13, v1, Llyiahf/vczjk/o0O000;->OooOOO0:I

    packed-switch v13, :pswitch_data_0

    new-instance v14, Llyiahf/vczjk/z2a;

    check-cast v11, Llyiahf/vczjk/z2a;

    iget-object v15, v11, Llyiahf/vczjk/z2a;->OoooO0O:Llyiahf/vczjk/w59;

    move-object/from16 v17, v12

    check-cast v17, Llyiahf/vczjk/ux0;

    move-object/from16 v0, v17

    check-cast v0, Llyiahf/vczjk/l21;

    invoke-virtual {v0}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v19

    move-object/from16 v0, v17

    check-cast v0, Llyiahf/vczjk/tf3;

    invoke-virtual {v0}, Llyiahf/vczjk/tf3;->getKind()I

    move-result v2

    const-string v3, "getKind(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/u81;->OooOoO0(ILjava/lang/String;)V

    iget-object v3, v11, Llyiahf/vczjk/z2a;->OoooO:Llyiahf/vczjk/a3a;

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/y02;

    invoke-virtual {v4}, Llyiahf/vczjk/y02;->OooO0oO()Llyiahf/vczjk/sx8;

    move-result-object v4

    const-string v5, "getSource(...)"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v5, v11, Llyiahf/vczjk/z2a;->OoooO:Llyiahf/vczjk/a3a;

    move/from16 v20, v2

    move-object/from16 v21, v4

    move-object/from16 v16, v5

    move-object/from16 v18, v11

    invoke-direct/range {v14 .. v21}, Llyiahf/vczjk/z2a;-><init>(Llyiahf/vczjk/w59;Llyiahf/vczjk/a3a;Llyiahf/vczjk/ux0;Llyiahf/vczjk/y2a;Llyiahf/vczjk/ko;ILlyiahf/vczjk/sx8;)V

    sget-object v2, Llyiahf/vczjk/z2a;->o000oOoO:Llyiahf/vczjk/sp3;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-object v2, v3

    check-cast v2, Llyiahf/vczjk/v82;

    invoke-virtual {v2}, Llyiahf/vczjk/v82;->o0000O0()Llyiahf/vczjk/by0;

    move-result-object v4

    if-nez v4, :cond_0

    move-object v2, v8

    goto :goto_0

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/v82;->o0000O0O()Llyiahf/vczjk/dp8;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/i5a;->OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/i5a;

    move-result-object v2

    :goto_0
    if-nez v2, :cond_1

    goto :goto_2

    :cond_1
    iget-object v4, v0, Llyiahf/vczjk/tf3;->OooOoO0:Llyiahf/vczjk/mp4;

    if-eqz v4, :cond_2

    invoke-virtual {v4, v2}, Llyiahf/vczjk/mp4;->o0000O0O(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/mp4;

    move-result-object v8

    :cond_2
    move-object/from16 v16, v8

    invoke-virtual {v0}, Llyiahf/vczjk/tf3;->o00Oo0()Ljava/util/List;

    move-result-object v0

    const-string v4, "getContextReceiverParameters(...)"

    invoke-static {v0, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v4, Ljava/util/ArrayList;

    invoke-static {v0, v6}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v5

    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/mp4;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/mp4;->o0000O0O(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/mp4;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_3
    check-cast v3, Llyiahf/vczjk/v82;

    invoke-virtual {v3}, Llyiahf/vczjk/v82;->OooOo00()Ljava/util/List;

    move-result-object v18

    invoke-virtual {v11}, Llyiahf/vczjk/tf3;->OoooOOO()Ljava/util/List;

    move-result-object v19

    iget-object v0, v11, Llyiahf/vczjk/tf3;->OooOo0O:Llyiahf/vczjk/uk4;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v21, Llyiahf/vczjk/yk5;->OooOOO:Llyiahf/vczjk/yk5;

    const/4 v15, 0x0

    iget-object v2, v3, Llyiahf/vczjk/v82;->OooOo0:Llyiahf/vczjk/q72;

    move-object/from16 v20, v0

    move-object/from16 v22, v2

    move-object/from16 v17, v4

    invoke-virtual/range {v14 .. v22}, Llyiahf/vczjk/tf3;->o0000OO(Llyiahf/vczjk/mp4;Llyiahf/vczjk/mp4;Ljava/util/List;Ljava/util/List;Ljava/util/List;Llyiahf/vczjk/uk4;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;)V

    move-object v8, v14

    :goto_2
    return-object v8

    :pswitch_0
    check-cast v11, Llyiahf/vczjk/n06;

    iget-object v0, v11, Llyiahf/vczjk/n06;->OooO0o0:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/List;

    if-nez v0, :cond_4

    goto :goto_3

    :cond_4
    move-object v5, v0

    :goto_3
    new-instance v0, Ljava/util/ArrayList;

    invoke-static {v5, v6}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_4
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_5

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/iaa;

    move-object v4, v12

    check-cast v4, Llyiahf/vczjk/al4;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/iaa;->o00000Oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/iaa;

    move-result-object v3

    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_4

    :cond_5
    return-object v0

    :pswitch_1
    check-cast v11, Landroid/app/Activity;

    invoke-static {v11}, Llyiahf/vczjk/n27;->OooO00o(Landroid/content/Context;)Landroid/content/SharedPreferences;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    const-string v2, "PREF_PRIVACY_STATEMENT_ACCEPTED2_V_3354368"

    invoke-interface {v0, v2, v9}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    check-cast v12, Llyiahf/vczjk/qs5;

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-interface {v12, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    return-object v10

    :pswitch_2
    check-cast v12, Llyiahf/vczjk/zw4;

    iget-object v0, v12, Llyiahf/vczjk/zw4;->OooOOOO:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/yk4;

    check-cast v11, Llyiahf/vczjk/al4;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v2, "type"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/uk4;

    return-object v0

    :pswitch_3
    check-cast v11, Llyiahf/vczjk/ds4;

    iget-object v0, v11, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v0, v0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    check-cast v12, Llyiahf/vczjk/hl7;

    iget-object v2, v12, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/sa7;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooO0oo:Llyiahf/vczjk/up3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "descriptor"

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v8

    :pswitch_4
    check-cast v11, Llyiahf/vczjk/ld9;

    iget-object v0, v11, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooO0O0:Llyiahf/vczjk/bh6;

    check-cast v12, Llyiahf/vczjk/zr4;

    iget-object v2, v12, Llyiahf/vczjk/zr4;->OooOOOO:Llyiahf/vczjk/tr4;

    iget-object v2, v2, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "packageFqName"

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v8

    :pswitch_5
    new-instance v0, Llyiahf/vczjk/tr4;

    check-cast v11, Llyiahf/vczjk/ur4;

    iget-object v2, v11, Llyiahf/vczjk/ur4;->OooO00o:Llyiahf/vczjk/ld9;

    check-cast v12, Llyiahf/vczjk/mm7;

    invoke-direct {v0, v2, v12}, Llyiahf/vczjk/tr4;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/mm7;)V

    return-object v0

    :pswitch_6
    check-cast v12, Llyiahf/vczjk/ex7;

    iget-object v0, v12, Llyiahf/vczjk/ex7;->OooO00o:Ljava/lang/String;

    check-cast v11, Llyiahf/vczjk/on4;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v11, Llyiahf/vczjk/on4;->OooO0o:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    invoke-virtual {v2, v0}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->deleteLaunchOtherAppRule(Ljava/lang/String;)V

    invoke-virtual {v11}, Llyiahf/vczjk/on4;->OooO0o0()V

    return-object v10

    :pswitch_7
    check-cast v11, Llyiahf/vczjk/di4;

    iget-object v0, v11, Llyiahf/vczjk/di4;->OooO00o:Llyiahf/vczjk/uk4;

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_6

    goto/16 :goto_8

    :cond_6
    sget-object v2, Llyiahf/vczjk/ww4;->OooOOO0:Llyiahf/vczjk/ww4;

    new-instance v3, Llyiahf/vczjk/ci4;

    invoke-direct {v3, v11, v9}, Llyiahf/vczjk/ci4;-><init>(Llyiahf/vczjk/di4;I)V

    invoke-static {v2, v3}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object v2

    new-instance v5, Ljava/util/ArrayList;

    invoke-static {v0, v6}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v5, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_5
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_d

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    add-int/lit8 v6, v7, 0x1

    if-ltz v7, :cond_c

    check-cast v3, Llyiahf/vczjk/z4a;

    invoke-virtual {v3}, Llyiahf/vczjk/z4a;->OooO0OO()Z

    move-result v10

    if-eqz v10, :cond_7

    sget-object v3, Llyiahf/vczjk/ii4;->OooO0OO:Llyiahf/vczjk/ii4;

    goto :goto_7

    :cond_7
    new-instance v10, Llyiahf/vczjk/di4;

    invoke-virtual {v3}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v13

    const-string v14, "getType(...)"

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v14, v12

    check-cast v14, Llyiahf/vczjk/le3;

    if-nez v14, :cond_8

    move-object v14, v8

    goto :goto_6

    :cond_8
    new-instance v14, Llyiahf/vczjk/ag5;

    invoke-direct {v14, v11, v7, v2}, Llyiahf/vczjk/ag5;-><init>(Llyiahf/vczjk/di4;ILlyiahf/vczjk/kp4;)V

    :goto_6
    invoke-direct {v10, v13, v14}, Llyiahf/vczjk/di4;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/le3;)V

    invoke-virtual {v3}, Llyiahf/vczjk/z4a;->OooO00o()Llyiahf/vczjk/cda;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    move-result v3

    if-eqz v3, :cond_b

    if-eq v3, v9, :cond_a

    if-ne v3, v4, :cond_9

    new-instance v3, Llyiahf/vczjk/ii4;

    sget-object v7, Llyiahf/vczjk/ji4;->OooOOOO:Llyiahf/vczjk/ji4;

    invoke-direct {v3, v7, v10}, Llyiahf/vczjk/ii4;-><init>(Llyiahf/vczjk/ji4;Llyiahf/vczjk/di4;)V

    goto :goto_7

    :cond_9
    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_a
    new-instance v3, Llyiahf/vczjk/ii4;

    sget-object v7, Llyiahf/vczjk/ji4;->OooOOO:Llyiahf/vczjk/ji4;

    invoke-direct {v3, v7, v10}, Llyiahf/vczjk/ii4;-><init>(Llyiahf/vczjk/ji4;Llyiahf/vczjk/di4;)V

    goto :goto_7

    :cond_b
    new-instance v3, Llyiahf/vczjk/ii4;

    sget-object v7, Llyiahf/vczjk/ji4;->OooOOO0:Llyiahf/vczjk/ji4;

    invoke-direct {v3, v7, v10}, Llyiahf/vczjk/ii4;-><init>(Llyiahf/vczjk/ji4;Llyiahf/vczjk/di4;)V

    :goto_7
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v7, v6

    goto :goto_5

    :cond_c
    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    throw v8

    :cond_d
    :goto_8
    return-object v5

    :pswitch_8
    check-cast v11, Llyiahf/vczjk/bg4;

    iget-object v0, v11, Llyiahf/vczjk/bg4;->OooOOOO:Llyiahf/vczjk/yf4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    check-cast v12, Ljava/lang/String;

    iget-object v2, v11, Llyiahf/vczjk/bg4;->OooOOOo:Ljava/lang/String;

    const-string v4, "signature"

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "<init>"

    invoke-virtual {v12, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_11

    invoke-virtual {v0}, Llyiahf/vczjk/yf4;->OooO0oo()Ljava/util/Collection;

    move-result-object v4

    check-cast v4, Ljava/lang/Iterable;

    invoke-static {v4}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v4

    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :cond_e
    :goto_9
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_13

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    move-object v10, v8

    check-cast v10, Llyiahf/vczjk/il1;

    invoke-interface {v10}, Llyiahf/vczjk/il1;->OooOoOO()Z

    move-result v11

    if-eqz v11, :cond_10

    invoke-interface {v10}, Llyiahf/vczjk/il1;->OooOO0o()Llyiahf/vczjk/hz0;

    move-result-object v11

    invoke-static {v11, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v11}, Llyiahf/vczjk/uz3;->OooO0Oo(Llyiahf/vczjk/v02;)Z

    move-result v11

    if-eqz v11, :cond_10

    invoke-static {v10}, Llyiahf/vczjk/iz7;->OooO0OO(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/ng0;

    move-result-object v11

    invoke-virtual {v11}, Llyiahf/vczjk/ng0;->OooOO0()Ljava/lang/String;

    move-result-object v11

    const-string v13, "constructor-impl"

    invoke-static {v11, v13, v7}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v13

    if-eqz v13, :cond_f

    const-string v13, ")V"

    invoke-static {v11, v13, v7}, Llyiahf/vczjk/g79;->OooOoOO(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v13

    if-eqz v13, :cond_f

    new-instance v13, Ljava/lang/StringBuilder;

    invoke-direct {v13}, Ljava/lang/StringBuilder;-><init>()V

    const-string v14, "V"

    invoke-static {v11, v14}, Llyiahf/vczjk/z69;->Ooooo00(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v11

    invoke-virtual {v13, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {v10}, Llyiahf/vczjk/il1;->OooOO0o()Llyiahf/vczjk/hz0;

    move-result-object v10

    invoke-static {v10, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v10}, Llyiahf/vczjk/p72;->OooO0o(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/hy0;

    move-result-object v10

    invoke-static {v10}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v10}, Llyiahf/vczjk/hy0;->OooO0O0()Ljava/lang/String;

    move-result-object v10

    invoke-static {v10}, Llyiahf/vczjk/ny0;->OooO0O0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v10

    invoke-virtual {v13, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v10

    goto :goto_a

    :cond_f
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "Invalid signature of "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, ": "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v2, Ljava/lang/IllegalArgumentException;

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v2, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    :cond_10
    invoke-static {v10}, Llyiahf/vczjk/iz7;->OooO0OO(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/ng0;

    move-result-object v10

    invoke-virtual {v10}, Llyiahf/vczjk/ng0;->OooOO0()Ljava/lang/String;

    move-result-object v10

    :goto_a
    invoke-static {v10, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_e

    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto/16 :goto_9

    :cond_11
    invoke-static {v12}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v3

    invoke-virtual {v0, v3}, Llyiahf/vczjk/yf4;->OooO(Llyiahf/vczjk/qt5;)Ljava/util/Collection;

    move-result-object v4

    move-object v3, v4

    check-cast v3, Ljava/lang/Iterable;

    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_12
    :goto_b
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_13

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    move-object v7, v6

    check-cast v7, Llyiahf/vczjk/rf3;

    invoke-static {v7}, Llyiahf/vczjk/iz7;->OooO0OO(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/ng0;

    move-result-object v7

    invoke-virtual {v7}, Llyiahf/vczjk/ng0;->OooOO0()Ljava/lang/String;

    move-result-object v7

    invoke-static {v7, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_12

    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_b

    :cond_13
    invoke-interface {v5}, Ljava/util/List;->size()I

    move-result v3

    if-eq v3, v9, :cond_15

    move-object v13, v4

    check-cast v13, Ljava/lang/Iterable;

    sget-object v17, Llyiahf/vczjk/g13;->OooOo0o:Llyiahf/vczjk/g13;

    const/16 v16, 0x0

    const/16 v18, 0x1e

    const-string v14, "\n"

    const/4 v15, 0x0

    invoke-static/range {v13 .. v18}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object v3

    new-instance v4, Llyiahf/vczjk/es1;

    const-string v5, "Function \'"

    const-string v6, "\' (JVM signature: "

    const-string v7, ") not resolved in "

    invoke-static {v5, v12, v6, v2, v7}, Llyiahf/vczjk/q99;->OooO0oo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v0, 0x3a

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v0

    if-nez v0, :cond_14

    const-string v0, " no members found"

    goto :goto_c

    :cond_14
    const-string v0, "\n"

    invoke-virtual {v0, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    :goto_c
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v4, v0}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw v4

    :cond_15
    invoke-static {v5}, Llyiahf/vczjk/d21;->o00000o0(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/rf3;

    return-object v0

    :pswitch_9
    check-cast v11, Llyiahf/vczjk/nr4;

    new-instance v0, Llyiahf/vczjk/nr4;

    iget-object v2, v11, Llyiahf/vczjk/nr4;->OooOo0O:Llyiahf/vczjk/ld9;

    iget-object v4, v2, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/s64;

    new-instance v13, Llyiahf/vczjk/s64;

    iget-object v14, v4, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooOo0O:Llyiahf/vczjk/c74;

    iget-object v6, v4, Llyiahf/vczjk/s64;->OooOo0o:Llyiahf/vczjk/e86;

    iget-object v15, v4, Llyiahf/vczjk/s64;->OooO0O0:Llyiahf/vczjk/bh6;

    iget-object v7, v4, Llyiahf/vczjk/s64;->OooO0OO:Llyiahf/vczjk/tg7;

    iget-object v8, v4, Llyiahf/vczjk/s64;->OooO0Oo:Llyiahf/vczjk/l82;

    iget-object v9, v4, Llyiahf/vczjk/s64;->OooO0o0:Llyiahf/vczjk/xj0;

    iget-object v10, v4, Llyiahf/vczjk/s64;->OooO0o:Llyiahf/vczjk/qp3;

    move-object/from16 v34, v5

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooO0oo:Llyiahf/vczjk/up3;

    move-object/from16 v20, v5

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooO:Llyiahf/vczjk/ws7;

    move-object/from16 v21, v5

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    move-object/from16 v22, v5

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooOO0O:Llyiahf/vczjk/as7;

    move-object/from16 v23, v5

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooOO0o:Llyiahf/vczjk/pp3;

    move-object/from16 v24, v5

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooOOO0:Llyiahf/vczjk/sp3;

    move-object/from16 v25, v5

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooOOO:Llyiahf/vczjk/sp3;

    move-object/from16 v26, v5

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooOOOO:Llyiahf/vczjk/dm5;

    move-object/from16 v27, v5

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooOOOo:Llyiahf/vczjk/fn7;

    move-object/from16 v28, v5

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooOOo0:Llyiahf/vczjk/eo;

    move-object/from16 v29, v5

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooOOo:Llyiahf/vczjk/tp3;

    move-object/from16 v30, v5

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooOOoo:Llyiahf/vczjk/sp3;

    move-object/from16 v31, v5

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooOo00:Llyiahf/vczjk/wp3;

    iget-object v4, v4, Llyiahf/vczjk/s64;->OooOo0:Llyiahf/vczjk/v06;

    move-object/from16 v33, v4

    move-object/from16 v32, v5

    move-object/from16 v35, v6

    move-object/from16 v16, v7

    move-object/from16 v17, v8

    move-object/from16 v18, v9

    move-object/from16 v19, v10

    invoke-direct/range {v13 .. v35}, Llyiahf/vczjk/s64;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/bh6;Llyiahf/vczjk/tg7;Llyiahf/vczjk/l82;Llyiahf/vczjk/xj0;Llyiahf/vczjk/qp3;Llyiahf/vczjk/up3;Llyiahf/vczjk/ws7;Llyiahf/vczjk/rp3;Llyiahf/vczjk/as7;Llyiahf/vczjk/pp3;Llyiahf/vczjk/sp3;Llyiahf/vczjk/sp3;Llyiahf/vczjk/dm5;Llyiahf/vczjk/fn7;Llyiahf/vczjk/eo;Llyiahf/vczjk/tp3;Llyiahf/vczjk/sp3;Llyiahf/vczjk/wp3;Llyiahf/vczjk/v06;Llyiahf/vczjk/c74;Llyiahf/vczjk/e86;)V

    new-instance v4, Llyiahf/vczjk/ld9;

    iget-object v5, v2, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    iget-object v2, v2, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/v4a;

    invoke-direct {v4, v13, v2, v5}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/s64;Llyiahf/vczjk/v4a;Llyiahf/vczjk/kp4;)V

    invoke-virtual {v11}, Llyiahf/vczjk/cy0;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v2

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v12, Llyiahf/vczjk/by0;

    iget-object v3, v11, Llyiahf/vczjk/nr4;->OooOo00:Llyiahf/vczjk/cm7;

    invoke-direct {v0, v4, v2, v3, v12}, Llyiahf/vczjk/nr4;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/v02;Llyiahf/vczjk/cm7;Llyiahf/vczjk/by0;)V

    return-object v0

    :pswitch_a
    check-cast v11, Llyiahf/vczjk/nd4;

    invoke-virtual {v11}, Llyiahf/vczjk/nd4;->OooO0O0()Llyiahf/vczjk/id4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/id4;->OooO00o:Llyiahf/vczjk/dm5;

    sget-object v2, Llyiahf/vczjk/fd4;->OooO0Oo:Llyiahf/vczjk/vp3;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/fd4;->OooO0oo:Llyiahf/vczjk/hy0;

    new-instance v3, Llyiahf/vczjk/ld9;

    invoke-virtual {v11}, Llyiahf/vczjk/nd4;->OooO0O0()Llyiahf/vczjk/id4;

    move-result-object v4

    iget-object v4, v4, Llyiahf/vczjk/id4;->OooO00o:Llyiahf/vczjk/dm5;

    check-cast v12, Llyiahf/vczjk/q45;

    invoke-direct {v3, v12, v4}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/cm5;)V

    invoke-static {v0, v2, v3}, Llyiahf/vczjk/r02;->OooOOoo(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hy0;Llyiahf/vczjk/ld9;)Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    return-object v0

    :pswitch_b
    new-instance v0, Llyiahf/vczjk/nd4;

    check-cast v11, Llyiahf/vczjk/jd4;

    invoke-virtual {v11}, Llyiahf/vczjk/hk4;->OooOO0o()Llyiahf/vczjk/dm5;

    move-result-object v2

    const-string v3, "getBuiltInsModule(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Llyiahf/vczjk/o0oOOo;

    const/16 v4, 0x13

    invoke-direct {v3, v11, v4}, Llyiahf/vczjk/o0oOOo;-><init>(Ljava/lang/Object;I)V

    check-cast v12, Llyiahf/vczjk/q45;

    invoke-direct {v0, v2, v12, v3}, Llyiahf/vczjk/nd4;-><init>(Llyiahf/vczjk/dm5;Llyiahf/vczjk/q45;Llyiahf/vczjk/o0oOOo;)V

    return-object v0

    :pswitch_c
    new-instance v13, Llyiahf/vczjk/ey0;

    check-cast v11, Llyiahf/vczjk/fd4;

    iget-object v0, v11, Llyiahf/vczjk/fd4;->OooO0O0:Llyiahf/vczjk/oe3;

    iget-object v2, v11, Llyiahf/vczjk/fd4;->OooO00o:Llyiahf/vczjk/dm5;

    invoke-interface {v0, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    move-object v14, v0

    check-cast v14, Llyiahf/vczjk/v02;

    sget-object v16, Llyiahf/vczjk/yk5;->OooOOo0:Llyiahf/vczjk/yk5;

    sget-object v17, Llyiahf/vczjk/ly0;->OooOOO:Llyiahf/vczjk/ly0;

    iget-object v0, v2, Llyiahf/vczjk/dm5;->OooOOoo:Llyiahf/vczjk/hk4;

    invoke-virtual {v0}, Llyiahf/vczjk/hk4;->OooO0o0()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v18

    sget-object v15, Llyiahf/vczjk/fd4;->OooO0oO:Llyiahf/vczjk/qt5;

    move-object/from16 v19, v12

    check-cast v19, Llyiahf/vczjk/q45;

    invoke-direct/range {v13 .. v19}, Llyiahf/vczjk/ey0;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/qt5;Llyiahf/vczjk/yk5;Llyiahf/vczjk/ly0;Ljava/util/List;Llyiahf/vczjk/q45;)V

    move-object/from16 v12, v19

    new-instance v0, Llyiahf/vczjk/g01;

    invoke-direct {v0, v12, v13}, Llyiahf/vczjk/kh3;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/oo0o0Oo;)V

    sget-object v2, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    invoke-virtual {v13, v0, v2, v8}, Llyiahf/vczjk/ey0;->o00ooo(Llyiahf/vczjk/jg5;Ljava/util/Set;Llyiahf/vczjk/ux0;)V

    return-object v13

    :pswitch_d
    check-cast v11, Llyiahf/vczjk/ld9;

    iget-object v0, v11, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooOOOO:Llyiahf/vczjk/dm5;

    iget-object v0, v0, Llyiahf/vczjk/dm5;->OooOOoo:Llyiahf/vczjk/hk4;

    check-cast v12, Llyiahf/vczjk/z54;

    iget-object v2, v12, Llyiahf/vczjk/z54;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/hk4;->OooOO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    const-string v2, "getDefaultType(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0

    :pswitch_e
    check-cast v12, Llyiahf/vczjk/qq3;

    check-cast v11, Llyiahf/vczjk/tq3;

    sget-object v2, Llyiahf/vczjk/fq2;->OooOOOO:Llyiahf/vczjk/fq2;

    :try_start_0
    invoke-virtual {v11, v9, v1}, Llyiahf/vczjk/tq3;->OooO0Oo(ZLlyiahf/vczjk/o0O000;)Z

    move-result v0

    if-eqz v0, :cond_17

    :cond_16
    invoke-virtual {v11, v7, v1}, Llyiahf/vczjk/tq3;->OooO0Oo(ZLlyiahf/vczjk/o0O000;)Z

    move-result v0

    if-nez v0, :cond_16

    sget-object v3, Llyiahf/vczjk/fq2;->OooOOO0:Llyiahf/vczjk/fq2;
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    :try_start_1
    sget-object v0, Llyiahf/vczjk/fq2;->OooOOo:Llyiahf/vczjk/fq2;
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    invoke-virtual {v12, v3, v0, v8}, Llyiahf/vczjk/qq3;->OooO0Oo(Llyiahf/vczjk/fq2;Llyiahf/vczjk/fq2;Ljava/io/IOException;)V

    :goto_d
    invoke-static {v11}, Llyiahf/vczjk/kba;->OooO0OO(Ljava/io/Closeable;)V

    goto :goto_f

    :catchall_0
    move-exception v0

    goto :goto_10

    :catch_0
    move-exception v0

    move-object v8, v0

    goto :goto_e

    :catchall_1
    move-exception v0

    move-object v3, v2

    goto :goto_10

    :catch_1
    move-exception v0

    move-object v8, v0

    move-object v3, v2

    goto :goto_e

    :cond_17
    :try_start_2
    new-instance v0, Ljava/io/IOException;

    const-string v3, "Required SETTINGS preface not received"

    invoke-direct {v0, v3}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw v0
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :goto_e
    :try_start_3
    sget-object v0, Llyiahf/vczjk/fq2;->OooOOO:Llyiahf/vczjk/fq2;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    invoke-virtual {v12, v0, v0, v8}, Llyiahf/vczjk/qq3;->OooO0Oo(Llyiahf/vczjk/fq2;Llyiahf/vczjk/fq2;Ljava/io/IOException;)V

    goto :goto_d

    :goto_f
    return-object v10

    :goto_10
    invoke-virtual {v12, v3, v2, v8}, Llyiahf/vczjk/qq3;->OooO0Oo(Llyiahf/vczjk/fq2;Llyiahf/vczjk/fq2;Ljava/io/IOException;)V

    invoke-static {v11}, Llyiahf/vczjk/kba;->OooO0OO(Ljava/io/Closeable;)V

    throw v0

    :pswitch_f
    new-instance v0, Llyiahf/vczjk/ct8;

    invoke-direct {v0}, Llyiahf/vczjk/ct8;-><init>()V

    check-cast v12, Llyiahf/vczjk/tf3;

    invoke-virtual {v12}, Llyiahf/vczjk/tf3;->OooOOO0()Ljava/util/Collection;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_11
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_18

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/rf3;

    move-object v4, v11

    check-cast v4, Llyiahf/vczjk/i5a;

    invoke-interface {v3, v4}, Llyiahf/vczjk/rf3;->OooO0o0(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/rf3;

    move-result-object v3

    invoke-virtual {v0, v3}, Llyiahf/vczjk/ct8;->add(Ljava/lang/Object;)Z

    goto :goto_11

    :cond_18
    return-object v0

    :pswitch_10
    check-cast v11, Llyiahf/vczjk/h82;

    iget-object v0, v11, Llyiahf/vczjk/h82;->OooOo:Llyiahf/vczjk/u72;

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooO0o0:Llyiahf/vczjk/hn;

    check-cast v12, Llyiahf/vczjk/kc7;

    iget-object v2, v11, Llyiahf/vczjk/h82;->Oooo00o:Llyiahf/vczjk/wd7;

    invoke-interface {v0, v2, v12}, Llyiahf/vczjk/zn;->OooOO0O(Llyiahf/vczjk/yd7;Llyiahf/vczjk/kc7;)Ljava/util/List;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :pswitch_11
    check-cast v11, Llyiahf/vczjk/l1a;

    check-cast v12, Llyiahf/vczjk/le3;

    invoke-interface {v12}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    iget-object v2, v11, Llyiahf/vczjk/l1a;->OooOOOo:Llyiahf/vczjk/fx9;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v3, Llyiahf/vczjk/jk2;->OooO0OO:Llyiahf/vczjk/cu1;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/cu1;->OooO00o(F)F

    move-result v0

    iget-wide v3, v2, Llyiahf/vczjk/fx9;->OooO00o:J

    iget-wide v5, v2, Llyiahf/vczjk/fx9;->OooO0O0:J

    invoke-static {v3, v4, v5, v6, v0}, Llyiahf/vczjk/v34;->Ooooo00(JJF)J

    move-result-wide v2

    new-instance v0, Llyiahf/vczjk/n21;

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/n21;-><init>(J)V

    return-object v0

    :pswitch_12
    check-cast v12, Llyiahf/vczjk/cra;

    iget-object v0, v12, Llyiahf/vczjk/cra;->OooO00o:Ljava/util/UUID;

    check-cast v11, Llyiahf/vczjk/oe3;

    invoke-interface {v11, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v10

    :pswitch_13
    check-cast v11, Llyiahf/vczjk/oe3;

    check-cast v12, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;

    invoke-interface {v11, v12}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v10

    :pswitch_14
    check-cast v11, Llyiahf/vczjk/ld9;

    invoke-static {v11, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v12, Llyiahf/vczjk/ko;

    invoke-static {v12, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, v11, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v2, v11, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    invoke-interface {v2}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/g74;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooOOo0:Llyiahf/vczjk/eo;

    invoke-virtual {v0, v2, v12}, Llyiahf/vczjk/eo;->OooO0O0(Llyiahf/vczjk/g74;Llyiahf/vczjk/ko;)Llyiahf/vczjk/g74;

    move-result-object v0

    return-object v0

    :pswitch_15
    check-cast v12, Llyiahf/vczjk/py0;

    invoke-interface {v12}, Llyiahf/vczjk/gm;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v3

    check-cast v11, Llyiahf/vczjk/ld9;

    invoke-static {v11, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, v11, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v2, v11, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    invoke-interface {v2}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/g74;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooOOo0:Llyiahf/vczjk/eo;

    invoke-virtual {v0, v2, v3}, Llyiahf/vczjk/eo;->OooO0O0(Llyiahf/vczjk/g74;Llyiahf/vczjk/ko;)Llyiahf/vczjk/g74;

    move-result-object v0

    return-object v0

    :pswitch_16
    sget v0, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;->OoooO0O:I

    check-cast v12, Llyiahf/vczjk/pc6;

    iget v0, v12, Llyiahf/vczjk/pc6;->OooO00o:I

    const-string v2, "context"

    check-cast v11, Landroid/content/Context;

    invoke-static {v11, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Landroid/content/Intent;

    const-class v3, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;

    invoke-direct {v2, v11, v3}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    const-string v3, "code"

    invoke-virtual {v2, v3, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    invoke-virtual {v11, v2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    return-object v10

    :pswitch_17
    check-cast v11, Llyiahf/vczjk/yg5;

    check-cast v12, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iput-object v12, v11, Llyiahf/vczjk/yg5;->OooO0o:Ljava/lang/Object;

    invoke-virtual {v11, v9}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    return-object v10

    :pswitch_18
    check-cast v12, Llyiahf/vczjk/vt;

    iget-object v0, v12, Llyiahf/vczjk/vt;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    check-cast v11, Llyiahf/vczjk/yg5;

    iput-object v0, v11, Llyiahf/vczjk/yg5;->OooO0o:Ljava/lang/Object;

    invoke-virtual {v11, v9}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    return-object v10

    :pswitch_19
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const/16 v0, 0x40

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    check-cast v11, Ljava/lang/Class;

    invoke-virtual {v11}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    check-cast v12, Ljava/util/Map;

    invoke-interface {v12}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object v0

    move-object v2, v0

    check-cast v2, Ljava/lang/Iterable;

    sget-object v7, Llyiahf/vczjk/tn;->OooOOO:Llyiahf/vczjk/tn;

    const-string v5, "("

    const-string v6, ")"

    const-string v4, ", "

    const/16 v8, 0x30

    invoke-static/range {v2 .. v8}, Llyiahf/vczjk/d21;->o0ooOOo(Ljava/lang/Iterable;Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)V

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :pswitch_1a
    check-cast v11, Llyiahf/vczjk/w6;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "appInfo"

    check-cast v12, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v12, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, v11, Llyiahf/vczjk/w6;->OooO0oo:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object v0

    iget-object v2, v11, Llyiahf/vczjk/w6;->OooO0oO:Llyiahf/vczjk/gh7;

    iget-object v2, v2, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v2, Llyiahf/vczjk/s29;

    invoke-virtual {v2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/t6;

    iget-object v2, v2, Llyiahf/vczjk/t6;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v2}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v2

    invoke-static {v12}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v3

    invoke-virtual {v0, v2, v3}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->removePkgFromLaunchOtherAppAllowList(Lgithub/tornaco/android/thanos/core/pm/Pkg;Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    invoke-virtual {v11}, Llyiahf/vczjk/w6;->OooO0oo()V

    return-object v10

    :pswitch_1b
    sget-object v0, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/d3a;->OooOOOO:Llyiahf/vczjk/d3a;

    check-cast v12, Llyiahf/vczjk/o0OoOoOo;

    invoke-virtual {v12}, Llyiahf/vczjk/o0OoOoOo;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v2

    sget-object v3, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    new-instance v5, Llyiahf/vczjk/pw4;

    new-instance v6, Llyiahf/vczjk/o0oOOo;

    invoke-direct {v6, v1, v4}, Llyiahf/vczjk/o0oOOo;-><init>(Ljava/lang/Object;I)V

    sget-object v4, Llyiahf/vczjk/q45;->OooO0o0:Llyiahf/vczjk/i45;

    invoke-direct {v5, v4, v6}, Llyiahf/vczjk/pw4;-><init>(Llyiahf/vczjk/w59;Llyiahf/vczjk/le3;)V

    invoke-static {v3, v5, v0, v2, v7}, Llyiahf/vczjk/so8;->Oooo0oo(Ljava/util/List;Llyiahf/vczjk/jg5;Llyiahf/vczjk/d3a;Llyiahf/vczjk/n3a;Z)Llyiahf/vczjk/dp8;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
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
