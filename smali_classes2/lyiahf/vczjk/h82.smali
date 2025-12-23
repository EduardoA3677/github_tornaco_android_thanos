.class public final Llyiahf/vczjk/h82;
.super Llyiahf/vczjk/oo0o0Oo;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/v02;


# instance fields
.field public final OooOOo:Llyiahf/vczjk/zb0;

.field public final OooOOo0:Llyiahf/vczjk/zb7;

.field public final OooOOoo:Llyiahf/vczjk/sx8;

.field public final OooOo:Llyiahf/vczjk/u72;

.field public final OooOo0:Llyiahf/vczjk/yk5;

.field public final OooOo00:Llyiahf/vczjk/hy0;

.field public final OooOo0O:Llyiahf/vczjk/q72;

.field public final OooOo0o:Llyiahf/vczjk/ly0;

.field public final OooOoO:Llyiahf/vczjk/f82;

.field public final OooOoO0:Llyiahf/vczjk/kg5;

.field public final OooOoOO:Llyiahf/vczjk/z88;

.field public final OooOoo:Llyiahf/vczjk/v02;

.field public final OooOoo0:Llyiahf/vczjk/ld9;

.field public final OooOooO:Llyiahf/vczjk/n45;

.field public final OooOooo:Llyiahf/vczjk/o45;

.field public final Oooo0:Llyiahf/vczjk/ko;

.field public final Oooo000:Llyiahf/vczjk/o45;

.field public final Oooo00O:Llyiahf/vczjk/n45;

.field public final Oooo00o:Llyiahf/vczjk/wd7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/u72;Llyiahf/vczjk/zb7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/zb0;Llyiahf/vczjk/sx8;)V
    .locals 18

    move-object/from16 v1, p0

    move-object/from16 v0, p1

    move-object/from16 v8, p2

    move-object/from16 v3, p3

    move-object/from16 v6, p4

    move-object/from16 v9, p5

    const-string v2, "outerContext"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "classProto"

    invoke-static {v8, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "nameResolver"

    invoke-static {v3, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "metadataVersion"

    invoke-static {v6, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "sourceElement"

    invoke-static {v9, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s72;

    iget-object v2, v2, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    invoke-virtual {v8}, Llyiahf/vczjk/zb7;->o0OoOo0()I

    move-result v4

    invoke-static {v3, v4}, Llyiahf/vczjk/l4a;->OooOo0O(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/hy0;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/hy0;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v4

    invoke-direct {v1, v2, v4}, Llyiahf/vczjk/oo0o0Oo;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/qt5;)V

    iput-object v8, v1, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    iput-object v6, v1, Llyiahf/vczjk/h82;->OooOOo:Llyiahf/vczjk/zb0;

    iput-object v9, v1, Llyiahf/vczjk/h82;->OooOOoo:Llyiahf/vczjk/sx8;

    invoke-virtual {v8}, Llyiahf/vczjk/zb7;->o0OoOo0()I

    move-result v2

    invoke-static {v3, v2}, Llyiahf/vczjk/l4a;->OooOo0O(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/hy0;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/h82;->OooOo00:Llyiahf/vczjk/hy0;

    sget-object v2, Llyiahf/vczjk/c23;->OooO0o0:Llyiahf/vczjk/a23;

    invoke-virtual {v8}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result v4

    invoke-virtual {v2, v4}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/rc7;

    invoke-static {v2}, Llyiahf/vczjk/ws7;->OooOOo0(Llyiahf/vczjk/rc7;)Llyiahf/vczjk/yk5;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/h82;->OooOo0:Llyiahf/vczjk/yk5;

    sget-object v2, Llyiahf/vczjk/c23;->OooO0Oo:Llyiahf/vczjk/a23;

    invoke-virtual {v8}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result v4

    invoke-virtual {v2, v4}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/vd7;

    invoke-static {v2}, Llyiahf/vczjk/er8;->OooOO0o(Llyiahf/vczjk/vd7;)Llyiahf/vczjk/q72;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/h82;->OooOo0O:Llyiahf/vczjk/q72;

    sget-object v2, Llyiahf/vczjk/c23;->OooO0o:Llyiahf/vczjk/a23;

    invoke-virtual {v8}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result v4

    invoke-virtual {v2, v4}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/yb7;

    if-nez v2, :cond_0

    const/4 v2, -0x1

    goto :goto_0

    :cond_0
    sget-object v4, Llyiahf/vczjk/zd7;->OooO0O0:[I

    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    move-result v2

    aget v2, v4, v2

    :goto_0
    packed-switch v2, :pswitch_data_0

    sget-object v2, Llyiahf/vczjk/ly0;->OooOOO0:Llyiahf/vczjk/ly0;

    :goto_1
    move-object v12, v2

    goto :goto_2

    :pswitch_0
    sget-object v2, Llyiahf/vczjk/ly0;->OooOOo:Llyiahf/vczjk/ly0;

    goto :goto_1

    :pswitch_1
    sget-object v2, Llyiahf/vczjk/ly0;->OooOOo0:Llyiahf/vczjk/ly0;

    goto :goto_1

    :pswitch_2
    sget-object v2, Llyiahf/vczjk/ly0;->OooOOOo:Llyiahf/vczjk/ly0;

    goto :goto_1

    :pswitch_3
    sget-object v2, Llyiahf/vczjk/ly0;->OooOOOO:Llyiahf/vczjk/ly0;

    goto :goto_1

    :pswitch_4
    sget-object v2, Llyiahf/vczjk/ly0;->OooOOO:Llyiahf/vczjk/ly0;

    goto :goto_1

    :pswitch_5
    sget-object v2, Llyiahf/vczjk/ly0;->OooOOO0:Llyiahf/vczjk/ly0;

    goto :goto_1

    :goto_2
    iput-object v12, v1, Llyiahf/vczjk/h82;->OooOo0o:Llyiahf/vczjk/ly0;

    invoke-virtual {v8}, Llyiahf/vczjk/zb7;->o0O0O00()Ljava/util/List;

    move-result-object v2

    const-string v4, "getTypeParameterList(...)"

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v4, Llyiahf/vczjk/h87;

    invoke-virtual {v8}, Llyiahf/vczjk/zb7;->o000OOo()Llyiahf/vczjk/nd7;

    move-result-object v5

    const-string v7, "getTypeTable(...)"

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v4, v5}, Llyiahf/vczjk/h87;-><init>(Llyiahf/vczjk/nd7;)V

    sget-object v5, Llyiahf/vczjk/xea;->OooO0O0:Llyiahf/vczjk/xea;

    invoke-virtual {v8}, Llyiahf/vczjk/zb7;->o000000()Llyiahf/vczjk/ud7;

    move-result-object v5

    const-string v7, "getVersionRequirementTable(...)"

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v5}, Llyiahf/vczjk/dl6;->OooO0O0(Llyiahf/vczjk/ud7;)Llyiahf/vczjk/xea;

    move-result-object v5

    invoke-virtual/range {v0 .. v6}, Llyiahf/vczjk/u72;->OooO00o(Llyiahf/vczjk/v02;Ljava/util/List;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/xea;Llyiahf/vczjk/zb0;)Llyiahf/vczjk/u72;

    move-result-object v13

    move-object v14, v0

    iput-object v13, v1, Llyiahf/vczjk/h82;->OooOo:Llyiahf/vczjk/u72;

    sget-object v0, Llyiahf/vczjk/c23;->OooOOO0:Llyiahf/vczjk/z13;

    invoke-virtual {v8}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    sget-object v15, Llyiahf/vczjk/ly0;->OooOOOO:Llyiahf/vczjk/ly0;

    iget-object v2, v13, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s72;

    if-ne v12, v15, :cond_3

    if-nez v0, :cond_2

    iget-object v0, v2, Llyiahf/vczjk/s72;->OooOOoo:Llyiahf/vczjk/mp2;

    invoke-interface {v0}, Llyiahf/vczjk/mp2;->o0O0O00()Ljava/lang/Boolean;

    move-result-object v0

    sget-object v3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    goto :goto_3

    :cond_1
    const/4 v0, 0x0

    goto :goto_4

    :cond_2
    :goto_3
    const/4 v0, 0x1

    :goto_4
    new-instance v3, Llyiahf/vczjk/n39;

    iget-object v4, v2, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    invoke-direct {v3, v4, v1, v0}, Llyiahf/vczjk/n39;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/h82;Z)V

    goto :goto_5

    :cond_3
    sget-object v3, Llyiahf/vczjk/ig5;->OooO0O0:Llyiahf/vczjk/ig5;

    :goto_5
    iput-object v3, v1, Llyiahf/vczjk/h82;->OooOoO0:Llyiahf/vczjk/kg5;

    new-instance v0, Llyiahf/vczjk/f82;

    invoke-direct {v0, v1}, Llyiahf/vczjk/f82;-><init>(Llyiahf/vczjk/h82;)V

    iput-object v0, v1, Llyiahf/vczjk/h82;->OooOoO:Llyiahf/vczjk/f82;

    sget-object v16, Llyiahf/vczjk/z88;->OooO0Oo:Llyiahf/vczjk/pp3;

    iget-object v0, v2, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    iget-object v3, v2, Llyiahf/vczjk/s72;->OooOOo0:Llyiahf/vczjk/u06;

    check-cast v3, Llyiahf/vczjk/v06;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-object v3, v0

    new-instance v0, Llyiahf/vczjk/o00000;

    move-object v4, v3

    const-class v3, Llyiahf/vczjk/e82;

    move-object v5, v4

    const-string v4, "<init>"

    const/4 v1, 0x1

    move-object v6, v5

    const-string v5, "<init>(Lorg/jetbrains/kotlin/serialization/deserialization/descriptors/DeserializedClassDescriptor;Lorg/jetbrains/kotlin/types/checker/KotlinTypeRefiner;)V"

    move-object v7, v6

    const/4 v6, 0x0

    move-object/from16 v17, v7

    const/4 v7, 0x5

    move-object v10, v2

    move-object/from16 v11, v17

    move-object/from16 v2, p0

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/o00000;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    move-object v6, v2

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v1, "storageManager"

    invoke-static {v11, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/z88;

    invoke-direct {v1, v6, v11, v0}, Llyiahf/vczjk/z88;-><init>(Llyiahf/vczjk/oo0o0Oo;Llyiahf/vczjk/q45;Llyiahf/vczjk/oe3;)V

    iput-object v1, v6, Llyiahf/vczjk/h82;->OooOoOO:Llyiahf/vczjk/z88;

    const/4 v0, 0x0

    if-ne v12, v15, :cond_4

    new-instance v1, Llyiahf/vczjk/ld9;

    invoke-direct {v1, v6}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/h82;)V

    goto :goto_6

    :cond_4
    move-object v1, v0

    :goto_6
    iput-object v1, v6, Llyiahf/vczjk/h82;->OooOoo0:Llyiahf/vczjk/ld9;

    iget-object v1, v14, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v02;

    iput-object v1, v6, Llyiahf/vczjk/h82;->OooOoo:Llyiahf/vczjk/v02;

    iget-object v7, v10, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance v2, Llyiahf/vczjk/a82;

    const/4 v3, 0x0

    invoke-direct {v2, v6, v3}, Llyiahf/vczjk/a82;-><init>(Llyiahf/vczjk/h82;I)V

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v3, Llyiahf/vczjk/n45;

    invoke-direct {v3, v7, v2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v3, v6, Llyiahf/vczjk/h82;->OooOooO:Llyiahf/vczjk/n45;

    new-instance v2, Llyiahf/vczjk/a82;

    const/4 v3, 0x1

    invoke-direct {v2, v6, v3}, Llyiahf/vczjk/a82;-><init>(Llyiahf/vczjk/h82;I)V

    new-instance v3, Llyiahf/vczjk/o45;

    invoke-direct {v3, v7, v2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v3, v6, Llyiahf/vczjk/h82;->OooOooo:Llyiahf/vczjk/o45;

    new-instance v2, Llyiahf/vczjk/a82;

    const/4 v3, 0x2

    invoke-direct {v2, v6, v3}, Llyiahf/vczjk/a82;-><init>(Llyiahf/vczjk/h82;I)V

    new-instance v3, Llyiahf/vczjk/n45;

    invoke-direct {v3, v7, v2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    new-instance v2, Llyiahf/vczjk/a82;

    const/4 v3, 0x3

    invoke-direct {v2, v6, v3}, Llyiahf/vczjk/a82;-><init>(Llyiahf/vczjk/h82;I)V

    new-instance v3, Llyiahf/vczjk/o45;

    invoke-direct {v3, v7, v2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v3, v6, Llyiahf/vczjk/h82;->Oooo000:Llyiahf/vczjk/o45;

    new-instance v2, Llyiahf/vczjk/a82;

    const/4 v3, 0x4

    invoke-direct {v2, v6, v3}, Llyiahf/vczjk/a82;-><init>(Llyiahf/vczjk/h82;I)V

    new-instance v3, Llyiahf/vczjk/n45;

    invoke-direct {v3, v7, v2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v3, v6, Llyiahf/vczjk/h82;->Oooo00O:Llyiahf/vczjk/n45;

    move-object v2, v0

    new-instance v0, Llyiahf/vczjk/wd7;

    instance-of v3, v1, Llyiahf/vczjk/h82;

    if-eqz v3, :cond_5

    check-cast v1, Llyiahf/vczjk/h82;

    goto :goto_7

    :cond_5
    move-object v1, v2

    :goto_7
    if-eqz v1, :cond_6

    iget-object v1, v1, Llyiahf/vczjk/h82;->Oooo00o:Llyiahf/vczjk/wd7;

    move-object v5, v1

    goto :goto_8

    :cond_6
    move-object v5, v2

    :goto_8
    iget-object v1, v13, Llyiahf/vczjk/u72;->OooO0Oo:Ljava/lang/Object;

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/h87;

    iget-object v1, v13, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/rt5;

    move-object v1, v8

    move-object v4, v9

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wd7;-><init>(Llyiahf/vczjk/zb7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/sx8;Llyiahf/vczjk/wd7;)V

    iput-object v0, v6, Llyiahf/vczjk/h82;->Oooo00o:Llyiahf/vczjk/wd7;

    sget-object v0, Llyiahf/vczjk/c23;->OooO0OO:Llyiahf/vczjk/z13;

    invoke-virtual/range {p2 .. p2}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-nez v0, :cond_7

    sget-object v0, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    goto :goto_9

    :cond_7
    new-instance v0, Llyiahf/vczjk/j26;

    new-instance v1, Llyiahf/vczjk/a82;

    const/4 v2, 0x5

    invoke-direct {v1, v6, v2}, Llyiahf/vczjk/a82;-><init>(Llyiahf/vczjk/h82;I)V

    invoke-direct {v0, v7, v1}, Llyiahf/vczjk/j26;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    :goto_9
    iput-object v0, v6, Llyiahf/vczjk/h82;->Oooo0:Llyiahf/vczjk/ko;

    return-void

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/yk5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h82;->OooOo0:Llyiahf/vczjk/yk5;

    return-object v0
.end method

.method public final OooO0Oo()Llyiahf/vczjk/q72;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h82;->OooOo0O:Llyiahf/vczjk/q72;

    return-object v0
.end method

.method public final OooO0o()Z
    .locals 4

    sget-object v0, Llyiahf/vczjk/c23;->OooOO0O:Llyiahf/vczjk/z13;

    iget-object v1, p0, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    invoke-virtual {v1}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/h82;->OooOOo:Llyiahf/vczjk/zb0;

    iget v1, v0, Llyiahf/vczjk/zb0;->OooO0O0:I

    const/4 v2, 0x1

    if-ge v1, v2, :cond_0

    goto :goto_0

    :cond_0
    if-le v1, v2, :cond_1

    goto :goto_1

    :cond_1
    const/4 v1, 0x4

    iget v3, v0, Llyiahf/vczjk/zb0;->OooO0OO:I

    if-ge v3, v1, :cond_2

    goto :goto_0

    :cond_2
    if-le v3, v1, :cond_3

    goto :goto_1

    :cond_3
    iget v0, v0, Llyiahf/vczjk/zb0;->OooO0Oo:I

    if-gt v0, v2, :cond_4

    :goto_0
    return v2

    :cond_4
    :goto_1
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0oO()Llyiahf/vczjk/sx8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h82;->OooOOoo:Llyiahf/vczjk/sx8;

    return-object v0
.end method

.method public final OooOO0()Z
    .locals 4

    sget-object v0, Llyiahf/vczjk/c23;->OooOO0O:Llyiahf/vczjk/z13;

    iget-object v1, p0, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    invoke-virtual {v1}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    const/4 v1, 0x2

    iget-object v2, p0, Llyiahf/vczjk/h82;->OooOOo:Llyiahf/vczjk/zb0;

    const/4 v3, 0x1

    invoke-virtual {v2, v3, v0, v1}, Llyiahf/vczjk/zb0;->OooO00o(III)Z

    move-result v0

    if-eqz v0, :cond_0

    return v3

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOO0o()Llyiahf/vczjk/v02;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h82;->OooOoo:Llyiahf/vczjk/v02;

    return-object v0
.end method

.method public final OooOOo0()Llyiahf/vczjk/ko;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h82;->Oooo0:Llyiahf/vczjk/ko;

    return-object v0
.end method

.method public final OooOo()Z
    .locals 2

    sget-object v0, Llyiahf/vczjk/c23;->OooO0o:Llyiahf/vczjk/a23;

    iget-object v1, p0, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    invoke-virtual {v1}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/yb7;->OooOOo0:Llyiahf/vczjk/yb7;

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo00()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h82;->OooOo:Llyiahf/vczjk/u72;

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO0oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/t3a;

    invoke-virtual {v0}, Llyiahf/vczjk/t3a;->OooO0O0()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final OooOo0O()Z
    .locals 2

    sget-object v0, Llyiahf/vczjk/c23;->OooO:Llyiahf/vczjk/z13;

    iget-object v1, p0, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    invoke-virtual {v1}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

.method public final OooOo0o()Llyiahf/vczjk/n3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h82;->OooOoO:Llyiahf/vczjk/f82;

    return-object v0
.end method

.method public final OooOoO()Ljava/util/Collection;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h82;->OooOooo:Llyiahf/vczjk/o45;

    invoke-virtual {v0}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Collection;

    return-object v0
.end method

.method public final OooOoo()Z
    .locals 2

    sget-object v0, Llyiahf/vczjk/c23;->OooOO0o:Llyiahf/vczjk/z13;

    iget-object v1, p0, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    invoke-virtual {v1}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

.method public final Oooo0()Z
    .locals 2

    sget-object v0, Llyiahf/vczjk/c23;->OooOO0:Llyiahf/vczjk/z13;

    iget-object v1, p0, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    invoke-virtual {v1}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

.method public final Oooo00o()Ljava/util/Collection;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h82;->Oooo000:Llyiahf/vczjk/o45;

    invoke-virtual {v0}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Collection;

    return-object v0
.end method

.method public final Oooo0O0()Z
    .locals 2

    sget-object v0, Llyiahf/vczjk/c23;->OooO0oO:Llyiahf/vczjk/z13;

    iget-object v1, p0, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    invoke-virtual {v1}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

.method public final Oooo0oO(Llyiahf/vczjk/al4;)Llyiahf/vczjk/jg5;
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/h82;->OooOoOO:Llyiahf/vczjk/z88;

    iget-object v0, p1, Llyiahf/vczjk/z88;->OooO00o:Llyiahf/vczjk/oo0o0Oo;

    invoke-static {v0}, Llyiahf/vczjk/p72;->OooOO0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/cm5;

    iget-object p1, p1, Llyiahf/vczjk/z88;->OooO0OO:Llyiahf/vczjk/o45;

    sget-object v0, Llyiahf/vczjk/z88;->OooO0o0:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    invoke-static {p1, v0}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/jg5;

    return-object p1
.end method

.method public final OoooO0()Llyiahf/vczjk/jg5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h82;->OooOoO0:Llyiahf/vczjk/kg5;

    return-object v0
.end method

.method public final OoooO00()Llyiahf/vczjk/ux0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h82;->OooOooO:Llyiahf/vczjk/n45;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ux0;

    return-object v0
.end method

.method public final getKind()Llyiahf/vczjk/ly0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h82;->OooOo0o:Llyiahf/vczjk/ly0;

    return-object v0
.end method

.method public final o000000O()Z
    .locals 2

    sget-object v0, Llyiahf/vczjk/c23;->OooO0oo:Llyiahf/vczjk/z13;

    iget-object v1, p0, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    invoke-virtual {v1}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

.method public final o00ooo()Llyiahf/vczjk/e82;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/h82;->OooOo:Llyiahf/vczjk/u72;

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooOOo0:Llyiahf/vczjk/u06;

    check-cast v0, Llyiahf/vczjk/v06;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p0, Llyiahf/vczjk/h82;->OooOoOO:Llyiahf/vczjk/z88;

    iget-object v1, v0, Llyiahf/vczjk/z88;->OooO00o:Llyiahf/vczjk/oo0o0Oo;

    invoke-static {v1}, Llyiahf/vczjk/p72;->OooOO0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/cm5;

    iget-object v0, v0, Llyiahf/vczjk/z88;->OooO0OO:Llyiahf/vczjk/o45;

    sget-object v1, Llyiahf/vczjk/z88;->OooO0o0:[Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    invoke-static {v0, v1}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/jg5;

    check-cast v0, Llyiahf/vczjk/e82;

    return-object v0
.end method

.method public final o0O0O00()Ljava/util/List;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/h82;->OooOo:Llyiahf/vczjk/u72;

    iget-object v1, v0, Llyiahf/vczjk/u72;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/h87;

    iget-object v2, p0, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    const-string v3, "<this>"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2}, Llyiahf/vczjk/zb7;->OoooooO()Ljava/util/List;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    move-result v4

    const/4 v5, 0x0

    if-nez v4, :cond_0

    goto :goto_0

    :cond_0
    move-object v3, v5

    :goto_0
    const/16 v4, 0xa

    if-nez v3, :cond_1

    invoke-virtual {v2}, Llyiahf/vczjk/zb7;->Oooooo()Ljava/util/List;

    move-result-object v2

    const-string v3, "getContextReceiverTypeIdList(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Ljava/util/ArrayList;

    invoke-static {v2, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v6

    invoke-direct {v3, v6}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_1

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/Integer;

    invoke-static {v6}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    move-result v6

    invoke-virtual {v1, v6}, Llyiahf/vczjk/h87;->OooO0Oo(I)Llyiahf/vczjk/hd7;

    move-result-object v6

    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_1
    new-instance v1, Ljava/util/ArrayList;

    invoke-static {v3, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/hd7;

    iget-object v4, v0, Llyiahf/vczjk/u72;->OooO0oo:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/t3a;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/t3a;->OooO0oO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/uk4;

    move-result-object v3

    new-instance v4, Llyiahf/vczjk/mp4;

    invoke-virtual {p0}, Llyiahf/vczjk/oo0o0Oo;->o00000()Llyiahf/vczjk/mp4;

    move-result-object v6

    new-instance v7, Llyiahf/vczjk/ln1;

    invoke-direct {v7, p0, v3, v5}, Llyiahf/vczjk/ln1;-><init>(Llyiahf/vczjk/by0;Llyiahf/vczjk/uk4;Llyiahf/vczjk/qt5;)V

    sget-object v3, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    invoke-direct {v4, v6, v7, v3}, Llyiahf/vczjk/mp4;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/l21;Llyiahf/vczjk/ko;)V

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_2
    return-object v1
.end method

.method public final o0OOO0o(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/dp8;
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/h82;->o00ooo()Llyiahf/vczjk/e82;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/h16;->OooOOoo:Llyiahf/vczjk/h16;

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/e82;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    const/4 v0, 0x0

    const/4 v1, 0x0

    move-object v2, v0

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/sa7;

    invoke-interface {v4}, Llyiahf/vczjk/co0;->Ooooooo()Llyiahf/vczjk/mp4;

    move-result-object v4

    if-nez v4, :cond_0

    if-eqz v1, :cond_1

    :goto_1
    move-object v2, v0

    goto :goto_2

    :cond_1
    const/4 v1, 0x1

    move-object v2, v3

    goto :goto_0

    :cond_2
    if-nez v1, :cond_3

    goto :goto_1

    :cond_3
    :goto_2
    check-cast v2, Llyiahf/vczjk/sa7;

    if-eqz v2, :cond_4

    invoke-interface {v2}, Llyiahf/vczjk/gca;->getType()Llyiahf/vczjk/uk4;

    move-result-object v0

    :cond_4
    check-cast v0, Llyiahf/vczjk/dp8;

    return-object v0
.end method

.method public final o0ooOOo()Llyiahf/vczjk/fca;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h82;->Oooo00O:Llyiahf/vczjk/n45;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/fca;

    return-object v0
.end method

.method public final oo0o0Oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "deserialized "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/h82;->Oooo0()Z

    move-result v1

    if-eqz v1, :cond_0

    const-string v1, "expect "

    goto :goto_0

    :cond_0
    const-string v1, ""

    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "class "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Llyiahf/vczjk/oo0o0Oo;->getName()Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
