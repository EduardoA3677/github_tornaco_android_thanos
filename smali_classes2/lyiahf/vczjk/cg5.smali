.class public final Llyiahf/vczjk/cg5;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/u72;

.field public final OooO0O0:Llyiahf/vczjk/n62;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/u72;)V
    .locals 2

    const-string v0, "c"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    new-instance v0, Llyiahf/vczjk/n62;

    iget-object p1, p1, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s72;

    iget-object v1, p1, Llyiahf/vczjk/s72;->OooO0O0:Llyiahf/vczjk/cm5;

    iget-object p1, p1, Llyiahf/vczjk/s72;->OooOO0o:Llyiahf/vczjk/ld9;

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/n62;-><init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/ld9;)V

    iput-object v0, p0, Llyiahf/vczjk/cg5;->OooO0O0:Llyiahf/vczjk/n62;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/v02;)Llyiahf/vczjk/yd7;
    .locals 4

    instance-of v0, p1, Llyiahf/vczjk/hh6;

    if-eqz v0, :cond_0

    new-instance v0, Llyiahf/vczjk/xd7;

    check-cast p1, Llyiahf/vczjk/hh6;

    check-cast p1, Llyiahf/vczjk/ih6;

    iget-object p1, p1, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    iget-object v1, p0, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v2, v1, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/rt5;

    iget-object v3, v1, Llyiahf/vczjk/u72;->OooO0Oo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/h87;

    iget-object v1, v1, Llyiahf/vczjk/u72;->OooO0oO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ce4;

    invoke-direct {v0, p1, v2, v3, v1}, Llyiahf/vczjk/xd7;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/ce4;)V

    return-object v0

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/h82;

    if-eqz v0, :cond_1

    check-cast p1, Llyiahf/vczjk/h82;

    iget-object p1, p1, Llyiahf/vczjk/h82;->Oooo00o:Llyiahf/vczjk/wd7;

    return-object p1

    :cond_1
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/sg3;II)Llyiahf/vczjk/ko;
    .locals 3

    sget-object v0, Llyiahf/vczjk/c23;->OooO0OO:Llyiahf/vczjk/z13;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    if-nez p2, :cond_0

    sget-object p1, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    return-object p1

    :cond_0
    new-instance p2, Llyiahf/vczjk/j26;

    iget-object v0, p0, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance v1, Llyiahf/vczjk/ag5;

    const/4 v2, 0x0

    invoke-direct {v1, p0, p1, p3, v2}, Llyiahf/vczjk/ag5;-><init>(Llyiahf/vczjk/cg5;Llyiahf/vczjk/sg3;II)V

    invoke-direct {p2, v0, v1}, Llyiahf/vczjk/j26;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    return-object p2
.end method

.method public final OooO0OO(Llyiahf/vczjk/xc7;Z)Llyiahf/vczjk/ko;
    .locals 4

    sget-object v0, Llyiahf/vczjk/c23;->OooO0OO:Llyiahf/vczjk/z13;

    invoke-virtual {p1}, Llyiahf/vczjk/xc7;->getFlags()I

    move-result v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-nez v0, :cond_0

    sget-object p1, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    return-object p1

    :cond_0
    new-instance v0, Llyiahf/vczjk/j26;

    iget-object v1, p0, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v1, v1, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s72;

    iget-object v1, v1, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance v2, Llyiahf/vczjk/q60;

    const/4 v3, 0x3

    invoke-direct {v2, v3, p0, p1, p2}, Llyiahf/vczjk/q60;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/j26;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    return-object v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/cc7;Z)Llyiahf/vczjk/z72;
    .locals 14

    move-object v6, p1

    iget-object v12, p0, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v0, v12, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v02;

    const-string v1, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.ClassDescriptor"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/by0;

    new-instance v0, Llyiahf/vczjk/z72;

    invoke-virtual {p1}, Llyiahf/vczjk/cc7;->getFlags()I

    move-result v2

    const/4 v13, 0x1

    invoke-virtual {p0, p1, v2, v13}, Llyiahf/vczjk/cg5;->OooO0O0(Llyiahf/vczjk/sg3;II)Llyiahf/vczjk/ko;

    move-result-object v3

    iget-object v2, v12, Llyiahf/vczjk/u72;->OooO0Oo:Ljava/lang/Object;

    move-object v8, v2

    check-cast v8, Llyiahf/vczjk/h87;

    const/4 v2, 0x0

    const/4 v11, 0x0

    const/4 v5, 0x1

    iget-object v4, v12, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    move-object v7, v4

    check-cast v7, Llyiahf/vczjk/rt5;

    iget-object v4, v12, Llyiahf/vczjk/u72;->OooO0o0:Ljava/lang/Object;

    move-object v9, v4

    check-cast v9, Llyiahf/vczjk/xea;

    iget-object v4, v12, Llyiahf/vczjk/u72;->OooO0oO:Ljava/lang/Object;

    move-object v10, v4

    check-cast v10, Llyiahf/vczjk/ce4;

    move/from16 v4, p2

    invoke-direct/range {v0 .. v11}, Llyiahf/vczjk/z72;-><init>(Llyiahf/vczjk/by0;Llyiahf/vczjk/il1;Llyiahf/vczjk/ko;ZILlyiahf/vczjk/cc7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/xea;Llyiahf/vczjk/ce4;Llyiahf/vczjk/sx8;)V

    sget-object v2, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-static {v12, v0, v2}, Llyiahf/vczjk/u72;->OooO0O0(Llyiahf/vczjk/u72;Llyiahf/vczjk/y02;Ljava/util/List;)Llyiahf/vczjk/u72;

    move-result-object v2

    invoke-virtual {p1}, Llyiahf/vczjk/cc7;->OooOo0o()Ljava/util/List;

    move-result-object v3

    const-string v4, "getValueParameterList(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v2, Llyiahf/vczjk/u72;->OooO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/cg5;

    invoke-virtual {v2, v3, p1, v13}, Llyiahf/vczjk/cg5;->OooO0oO(Ljava/util/List;Llyiahf/vczjk/sg3;I)Ljava/util/List;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/c23;->OooO0Oo:Llyiahf/vczjk/a23;

    invoke-virtual {p1}, Llyiahf/vczjk/cc7;->getFlags()I

    move-result v4

    invoke-virtual {v3, v4}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/vd7;

    invoke-static {v3}, Llyiahf/vczjk/er8;->OooOO0o(Llyiahf/vczjk/vd7;)Llyiahf/vczjk/q72;

    move-result-object v3

    invoke-virtual {v0, v2, v3}, Llyiahf/vczjk/ux0;->o0000o(Ljava/util/List;Llyiahf/vczjk/q72;)V

    invoke-interface {v1}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/tf3;->o0000OoO(Llyiahf/vczjk/dp8;)V

    invoke-interface {v1}, Llyiahf/vczjk/yf5;->Oooo0()Z

    move-result v1

    iput-boolean v1, v0, Llyiahf/vczjk/tf3;->Oooo00O:Z

    sget-object v1, Llyiahf/vczjk/c23;->OooOOOO:Llyiahf/vczjk/z13;

    invoke-virtual {p1}, Llyiahf/vczjk/cc7;->getFlags()I

    move-result v2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    xor-int/2addr v1, v13

    iput-boolean v1, v0, Llyiahf/vczjk/tf3;->Oooo0OO:Z

    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/xc7;)Llyiahf/vczjk/t82;
    .locals 26

    move-object/from16 v0, p0

    move-object/from16 v15, p1

    const-string v1, "proto"

    invoke-static {v15, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->o000oOoO()Z

    move-result v1

    const/16 v20, 0x6

    if-eqz v1, :cond_0

    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->getFlags()I

    move-result v1

    goto :goto_0

    :cond_0
    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->Oooo0oO()I

    move-result v1

    and-int/lit8 v2, v1, 0x3f

    shr-int/lit8 v1, v1, 0x8

    shl-int/lit8 v1, v1, 0x6

    add-int/2addr v1, v2

    :goto_0
    new-instance v3, Llyiahf/vczjk/t82;

    iget-object v2, v0, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v4, v2, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/v02;

    const/4 v5, 0x2

    invoke-virtual {v0, v15, v1, v5}, Llyiahf/vczjk/cg5;->OooO0O0(Llyiahf/vczjk/sg3;II)Llyiahf/vczjk/ko;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/c23;->OooO0o0:Llyiahf/vczjk/a23;

    invoke-virtual {v6, v1}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/rc7;

    invoke-static {v6}, Llyiahf/vczjk/ws7;->OooOOo0(Llyiahf/vczjk/rc7;)Llyiahf/vczjk/yk5;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/c23;->OooO0Oo:Llyiahf/vczjk/a23;

    invoke-virtual {v7, v1}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/vd7;

    invoke-static {v7}, Llyiahf/vczjk/er8;->OooOO0o(Llyiahf/vczjk/vd7;)Llyiahf/vczjk/q72;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/c23;->OooOoO0:Llyiahf/vczjk/z13;

    invoke-virtual {v8, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v8

    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v8

    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->Oooo0o()I

    move-result v9

    iget-object v10, v2, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/rt5;

    invoke-static {v10, v9}, Llyiahf/vczjk/l4a;->OooOo(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/qt5;

    move-result-object v9

    sget-object v10, Llyiahf/vczjk/c23;->OooOOOo:Llyiahf/vczjk/a23;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/qc7;

    invoke-static {v10}, Llyiahf/vczjk/er8;->OooOOo0(Llyiahf/vczjk/qc7;)I

    move-result v10

    sget-object v11, Llyiahf/vczjk/c23;->OooOoo:Llyiahf/vczjk/z13;

    invoke-virtual {v11, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v11

    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v11

    sget-object v12, Llyiahf/vczjk/c23;->OooOoo0:Llyiahf/vczjk/z13;

    invoke-virtual {v12, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v12

    invoke-virtual {v12}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v12

    sget-object v13, Llyiahf/vczjk/c23;->OooOooo:Llyiahf/vczjk/z13;

    invoke-virtual {v13, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v13

    invoke-virtual {v13}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v13

    sget-object v14, Llyiahf/vczjk/c23;->Oooo000:Llyiahf/vczjk/z13;

    invoke-virtual {v14, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v14

    invoke-virtual {v14}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v14

    move-object/from16 v16, v3

    sget-object v3, Llyiahf/vczjk/c23;->Oooo00O:Llyiahf/vczjk/z13;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    move/from16 v17, v1

    iget-object v1, v2, Llyiahf/vczjk/u72;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/h87;

    move-object/from16 v18, v4

    move-object v4, v5

    move-object v5, v6

    move-object v6, v7

    move v7, v8

    move-object v8, v9

    move v9, v10

    move v10, v11

    move v11, v12

    move v12, v13

    move v13, v14

    move v14, v3

    iget-object v3, v2, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/rt5;

    move-object/from16 v21, v1

    iget-object v1, v2, Llyiahf/vczjk/u72;->OooO0o0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/xea;

    move-object/from16 v22, v1

    iget-object v1, v2, Llyiahf/vczjk/u72;->OooO0oO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ce4;

    move-object/from16 v0, v21

    move/from16 v21, v17

    move-object/from16 v17, v0

    move-object/from16 v19, v1

    move-object v0, v2

    move-object/from16 v1, v16

    move-object/from16 v2, v18

    move-object/from16 v18, v22

    move-object/from16 v16, v3

    const/4 v3, 0x0

    invoke-direct/range {v1 .. v19}, Llyiahf/vczjk/t82;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;ZLlyiahf/vczjk/qt5;IZZZZZLlyiahf/vczjk/xc7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/xea;Llyiahf/vczjk/ce4;)V

    move-object v3, v1

    move-object/from16 v1, v17

    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->OoooOO0()Ljava/util/List;

    move-result-object v2

    const-string v4, "getTypeParameterList(...)"

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0, v3, v2}, Llyiahf/vczjk/u72;->OooO0O0(Llyiahf/vczjk/u72;Llyiahf/vczjk/y02;Ljava/util/List;)Llyiahf/vczjk/u72;

    move-result-object v13

    sget-object v2, Llyiahf/vczjk/c23;->OooOoO:Llyiahf/vczjk/z13;

    move/from16 v14, v21

    invoke-virtual {v2, v14}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v8

    sget-object v2, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    const/4 v9, 0x3

    if-eqz v8, :cond_1

    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->OoooOoO()Z

    move-result v4

    if-nez v4, :cond_2

    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->OoooOoo()Z

    move-result v4

    if-eqz v4, :cond_1

    goto :goto_1

    :cond_1
    move-object/from16 v10, p0

    goto :goto_2

    :cond_2
    :goto_1
    new-instance v4, Llyiahf/vczjk/x72;

    iget-object v5, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/s72;

    iget-object v5, v5, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance v6, Llyiahf/vczjk/ag5;

    const/4 v7, 0x1

    move-object/from16 v10, p0

    invoke-direct {v6, v10, v15, v9, v7}, Llyiahf/vczjk/ag5;-><init>(Llyiahf/vczjk/cg5;Llyiahf/vczjk/sg3;II)V

    invoke-direct {v4, v5, v6}, Llyiahf/vczjk/x72;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    goto :goto_3

    :goto_2
    move-object v4, v2

    :goto_3
    invoke-static {v15, v1}, Llyiahf/vczjk/eo6;->OooOoO(Llyiahf/vczjk/xc7;Llyiahf/vczjk/h87;)Llyiahf/vczjk/hd7;

    move-result-object v5

    iget-object v6, v13, Llyiahf/vczjk/u72;->OooO0oo:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/t3a;

    invoke-virtual {v6, v5}, Llyiahf/vczjk/t3a;->OooO0oO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/uk4;

    move-result-object v5

    invoke-virtual {v6}, Llyiahf/vczjk/t3a;->OooO0O0()Ljava/util/List;

    move-result-object v7

    iget-object v11, v0, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    check-cast v11, Llyiahf/vczjk/v02;

    instance-of v12, v11, Llyiahf/vczjk/by0;

    move-object/from16 v16, v11

    if-eqz v12, :cond_3

    move-object/from16 v12, v16

    check-cast v12, Llyiahf/vczjk/by0;

    goto :goto_4

    :cond_3
    const/4 v12, 0x0

    :goto_4
    if-eqz v12, :cond_4

    invoke-interface {v12}, Llyiahf/vczjk/by0;->o00000()Llyiahf/vczjk/mp4;

    move-result-object v12

    goto :goto_5

    :cond_4
    const/4 v12, 0x0

    :goto_5
    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->OoooOoO()Z

    move-result v16

    if-eqz v16, :cond_5

    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->Oooo0oo()Llyiahf/vczjk/hd7;

    move-result-object v16

    move-object/from16 v9, v16

    goto :goto_6

    :cond_5
    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->OoooOoo()Z

    move-result v16

    if-eqz v16, :cond_6

    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->Oooo()I

    move-result v9

    invoke-virtual {v1, v9}, Llyiahf/vczjk/h87;->OooO0Oo(I)Llyiahf/vczjk/hd7;

    move-result-object v9

    goto :goto_6

    :cond_6
    const/4 v9, 0x0

    :goto_6
    if-eqz v9, :cond_7

    invoke-virtual {v6, v9}, Llyiahf/vczjk/t3a;->OooO0oO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/uk4;

    move-result-object v9

    if-eqz v9, :cond_7

    invoke-static {v3, v9, v4}, Llyiahf/vczjk/dn8;->OoooO0O(Llyiahf/vczjk/co0;Llyiahf/vczjk/uk4;Llyiahf/vczjk/ko;)Llyiahf/vczjk/mp4;

    move-result-object v4

    goto :goto_7

    :cond_7
    const/4 v4, 0x0

    :goto_7
    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->Oooo0OO()Ljava/util/List;

    move-result-object v9

    invoke-interface {v9}, Ljava/util/Collection;->isEmpty()Z

    move-result v17

    if-nez v17, :cond_8

    goto :goto_8

    :cond_8
    const/4 v9, 0x0

    :goto_8
    if-nez v9, :cond_a

    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->Oooo0O0()Ljava/util/List;

    move-result-object v9

    const-string v11, "getContextReceiverTypeIdList(...)"

    invoke-static {v9, v11}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v11, Ljava/util/ArrayList;

    move-object/from16 v19, v4

    move-object/from16 v21, v5

    const/16 v4, 0xa

    invoke-static {v9, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v5

    invoke-direct {v11, v5}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_9
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_9

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Integer;

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    move-result v5

    invoke-virtual {v1, v5}, Llyiahf/vczjk/h87;->OooO0Oo(I)Llyiahf/vczjk/hd7;

    move-result-object v5

    invoke-virtual {v11, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_9

    :cond_9
    move-object v9, v11

    :goto_a
    move-object v4, v7

    goto :goto_b

    :cond_a
    move-object/from16 v19, v4

    move-object/from16 v21, v5

    goto :goto_a

    :goto_b
    new-instance v7, Ljava/util/ArrayList;

    const/16 v1, 0xa

    invoke-static {v9, v1}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v5

    invoke-direct {v7, v5}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    const/4 v5, 0x0

    :goto_c
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v11

    if-eqz v11, :cond_c

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v11

    add-int/lit8 v22, v5, 0x1

    if-ltz v5, :cond_b

    check-cast v11, Llyiahf/vczjk/hd7;

    invoke-virtual {v6, v11}, Llyiahf/vczjk/t3a;->OooO0oO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/uk4;

    move-result-object v11

    const/4 v9, 0x0

    invoke-static {v3, v11, v9, v2, v5}, Llyiahf/vczjk/dn8;->Oooo0OO(Llyiahf/vczjk/co0;Llyiahf/vczjk/uk4;Llyiahf/vczjk/qt5;Llyiahf/vczjk/ko;I)Llyiahf/vczjk/mp4;

    move-result-object v5

    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move/from16 v5, v22

    goto :goto_c

    :cond_b
    const/4 v9, 0x0

    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    throw v9

    :cond_c
    move-object v2, v3

    move-object v5, v12

    move-object/from16 v6, v19

    move-object/from16 v3, v21

    const/4 v9, 0x0

    invoke-virtual/range {v2 .. v7}, Llyiahf/vczjk/ua7;->o0000OOo(Llyiahf/vczjk/uk4;Ljava/util/List;Llyiahf/vczjk/mp4;Llyiahf/vczjk/mp4;Ljava/util/List;)V

    move-object v3, v2

    sget-object v1, Llyiahf/vczjk/c23;->OooO0OO:Llyiahf/vczjk/z13;

    invoke-virtual {v1, v14}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v2

    sget-object v4, Llyiahf/vczjk/c23;->OooO0Oo:Llyiahf/vczjk/a23;

    invoke-virtual {v4, v14}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/vd7;

    sget-object v6, Llyiahf/vczjk/c23;->OooO0o0:Llyiahf/vczjk/a23;

    invoke-virtual {v6, v14}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/rc7;

    if-eqz v5, :cond_1a

    if-eqz v7, :cond_19

    const/4 v11, 0x1

    if-eqz v2, :cond_d

    iget v1, v1, Llyiahf/vczjk/b23;->OooO0O0:I

    shl-int v1, v11, v1

    goto :goto_d

    :cond_d
    const/4 v1, 0x0

    :goto_d
    invoke-interface {v7}, Llyiahf/vczjk/w24;->getNumber()I

    move-result v2

    iget v7, v6, Llyiahf/vczjk/b23;->OooO0O0:I

    shl-int/2addr v2, v7

    or-int/2addr v1, v2

    invoke-interface {v5}, Llyiahf/vczjk/w24;->getNumber()I

    move-result v2

    iget v5, v4, Llyiahf/vczjk/b23;->OooO0O0:I

    shl-int/2addr v2, v5

    or-int/2addr v1, v2

    sget-object v2, Llyiahf/vczjk/c23;->Oooo0OO:Llyiahf/vczjk/z13;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v5, Llyiahf/vczjk/c23;->Oooo0o0:Llyiahf/vczjk/z13;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/c23;->Oooo0o:Llyiahf/vczjk/z13;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v12, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    if-eqz v8, :cond_10

    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->OoooOOO()Z

    move-result v8

    if-eqz v8, :cond_e

    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->Oooo0o0()I

    move-result v8

    goto :goto_e

    :cond_e
    move v8, v1

    :goto_e
    invoke-virtual {v2, v8}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v17

    invoke-virtual/range {v17 .. v17}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v17

    invoke-virtual {v5, v8}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v18

    invoke-virtual/range {v18 .. v18}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v18

    invoke-virtual {v7, v8}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v19

    invoke-virtual/range {v19 .. v19}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v19

    const/4 v9, 0x3

    invoke-virtual {v10, v15, v8, v9}, Llyiahf/vczjk/cg5;->OooO0O0(Llyiahf/vczjk/sg3;II)Llyiahf/vczjk/ko;

    move-result-object v9

    if-eqz v17, :cond_f

    move-object/from16 v16, v2

    new-instance v2, Llyiahf/vczjk/va7;

    invoke-virtual {v6, v8}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v22

    check-cast v22, Llyiahf/vczjk/rc7;

    invoke-static/range {v22 .. v22}, Llyiahf/vczjk/ws7;->OooOOo0(Llyiahf/vczjk/rc7;)Llyiahf/vczjk/yk5;

    move-result-object v22

    invoke-virtual {v4, v8}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/vd7;

    invoke-static {v8}, Llyiahf/vczjk/er8;->OooOO0o(Llyiahf/vczjk/vd7;)Llyiahf/vczjk/q72;

    move-result-object v8

    xor-int/lit8 v17, v17, 0x1

    invoke-virtual {v3}, Llyiahf/vczjk/ua7;->getKind()I

    move-result v10

    move/from16 v23, v11

    const/4 v11, 0x0

    move-object/from16 v21, v16

    move-object/from16 v16, v0

    move-object/from16 v0, v21

    move/from16 v21, v19

    move-object/from16 v19, v4

    move-object v4, v9

    move/from16 v9, v21

    move/from16 v24, v1

    move-object/from16 v21, v6

    move-object v1, v7

    move-object v6, v8

    move/from16 v7, v17

    move/from16 v8, v18

    const/16 v17, 0x0

    move-object/from16 v18, v13

    move-object v13, v5

    move-object/from16 v5, v22

    invoke-direct/range {v2 .. v12}, Llyiahf/vczjk/va7;-><init>(Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;ZZZILlyiahf/vczjk/va7;Llyiahf/vczjk/sx8;)V

    :goto_f
    move-object v11, v2

    goto :goto_10

    :cond_f
    move-object/from16 v16, v0

    move/from16 v24, v1

    move-object v0, v2

    move-object/from16 v19, v4

    move-object/from16 v21, v6

    move-object v1, v7

    move-object v4, v9

    move-object/from16 v18, v13

    const/16 v17, 0x0

    move-object v13, v5

    invoke-static {v3, v4}, Llyiahf/vczjk/dn8;->Oooo0oO(Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;)Llyiahf/vczjk/va7;

    move-result-object v2

    goto :goto_f

    :goto_10
    invoke-virtual {v3}, Llyiahf/vczjk/ua7;->OooOOoo()Llyiahf/vczjk/uk4;

    move-result-object v2

    invoke-virtual {v11, v2}, Llyiahf/vczjk/va7;->o0000O(Llyiahf/vczjk/uk4;)V

    goto :goto_11

    :cond_10
    move-object/from16 v16, v0

    move/from16 v24, v1

    move-object v0, v2

    move-object/from16 v19, v4

    move-object/from16 v21, v6

    move-object v1, v7

    move-object/from16 v17, v9

    move-object/from16 v18, v13

    move-object v13, v5

    move-object/from16 v11, v17

    :goto_11
    sget-object v2, Llyiahf/vczjk/c23;->OooOoOO:Llyiahf/vczjk/z13;

    invoke-virtual {v2, v14}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v2

    if-eqz v2, :cond_14

    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->OooooO0()Z

    move-result v2

    if-eqz v2, :cond_11

    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->OoooO0O()I

    move-result v2

    goto :goto_12

    :cond_11
    move/from16 v2, v24

    :goto_12
    invoke-virtual {v0, v2}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    invoke-virtual {v13, v2}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v8

    invoke-virtual {v1, v2}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v9

    const/4 v1, 0x4

    move-object/from16 v13, p0

    invoke-virtual {v13, v15, v2, v1}, Llyiahf/vczjk/cg5;->OooO0O0(Llyiahf/vczjk/sg3;II)Llyiahf/vczjk/ko;

    move-result-object v4

    if-eqz v0, :cond_13

    new-instance v5, Llyiahf/vczjk/hb7;

    move-object/from16 v6, v21

    invoke-virtual {v6, v2}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/rc7;

    invoke-static {v6}, Llyiahf/vczjk/ws7;->OooOOo0(Llyiahf/vczjk/rc7;)Llyiahf/vczjk/yk5;

    move-result-object v6

    move-object/from16 v7, v19

    invoke-virtual {v7, v2}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/vd7;

    invoke-static {v2}, Llyiahf/vczjk/er8;->OooOO0o(Llyiahf/vczjk/vd7;)Llyiahf/vczjk/q72;

    move-result-object v2

    const/16 v23, 0x1

    xor-int/lit8 v7, v0, 0x1

    invoke-virtual {v3}, Llyiahf/vczjk/ua7;->getKind()I

    move-result v10

    move-object v0, v11

    const/4 v11, 0x0

    move-object/from16 v25, v6

    move-object v6, v2

    move-object v2, v5

    move-object/from16 v5, v25

    move-object/from16 v25, v0

    move/from16 v0, v23

    invoke-direct/range {v2 .. v12}, Llyiahf/vczjk/hb7;-><init>(Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;ZZZILlyiahf/vczjk/hb7;Llyiahf/vczjk/sx8;)V

    sget-object v4, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    move-object/from16 v5, v18

    invoke-static {v5, v2, v4}, Llyiahf/vczjk/u72;->OooO0O0(Llyiahf/vczjk/u72;Llyiahf/vczjk/y02;Ljava/util/List;)Llyiahf/vczjk/u72;

    move-result-object v4

    invoke-virtual {v15}, Llyiahf/vczjk/xc7;->OoooO()Llyiahf/vczjk/pd7;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v5

    iget-object v4, v4, Llyiahf/vczjk/u72;->OooO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/cg5;

    invoke-virtual {v4, v5, v15, v1}, Llyiahf/vczjk/cg5;->OooO0oO(Ljava/util/List;Llyiahf/vczjk/sg3;I)Ljava/util/List;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/d21;->o00000o0(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/tca;

    if-eqz v1, :cond_12

    iput-object v1, v2, Llyiahf/vczjk/hb7;->OooOoo0:Llyiahf/vczjk/tca;

    move-object v11, v2

    goto :goto_13

    :cond_12
    invoke-static/range {v20 .. v20}, Llyiahf/vczjk/hb7;->o00000O0(I)V

    throw v17

    :cond_13
    move-object/from16 v25, v11

    const/4 v0, 0x1

    invoke-static {v3, v4}, Llyiahf/vczjk/dn8;->Oooo0oo(Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;)Llyiahf/vczjk/hb7;

    move-result-object v11

    goto :goto_13

    :cond_14
    move-object/from16 v13, p0

    move-object/from16 v25, v11

    const/4 v0, 0x1

    move-object/from16 v11, v17

    :goto_13
    sget-object v1, Llyiahf/vczjk/c23;->OooOooO:Llyiahf/vczjk/z13;

    invoke-virtual {v1, v14}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    if-eqz v1, :cond_15

    new-instance v1, Llyiahf/vczjk/zf5;

    const/4 v2, 0x0

    invoke-direct {v1, v13, v15, v3, v2}, Llyiahf/vczjk/zf5;-><init>(Llyiahf/vczjk/cg5;Llyiahf/vczjk/xc7;Llyiahf/vczjk/t82;I)V

    move-object/from16 v9, v17

    invoke-virtual {v3, v9, v1}, Llyiahf/vczjk/ua7;->o0000OO(Llyiahf/vczjk/n45;Llyiahf/vczjk/le3;)V

    :cond_15
    move-object/from16 v1, v16

    iget-object v1, v1, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v02;

    instance-of v2, v1, Llyiahf/vczjk/by0;

    if-eqz v2, :cond_16

    check-cast v1, Llyiahf/vczjk/by0;

    goto :goto_14

    :cond_16
    const/4 v1, 0x0

    :goto_14
    if-eqz v1, :cond_17

    invoke-interface {v1}, Llyiahf/vczjk/by0;->getKind()Llyiahf/vczjk/ly0;

    move-result-object v1

    goto :goto_15

    :cond_17
    const/4 v1, 0x0

    :goto_15
    sget-object v2, Llyiahf/vczjk/ly0;->OooOOo0:Llyiahf/vczjk/ly0;

    if-ne v1, v2, :cond_18

    new-instance v1, Llyiahf/vczjk/zf5;

    const/4 v2, 0x1

    invoke-direct {v1, v13, v15, v3, v2}, Llyiahf/vczjk/zf5;-><init>(Llyiahf/vczjk/cg5;Llyiahf/vczjk/xc7;Llyiahf/vczjk/t82;I)V

    const/4 v9, 0x0

    invoke-virtual {v3, v9, v1}, Llyiahf/vczjk/ua7;->o0000OO(Llyiahf/vczjk/n45;Llyiahf/vczjk/le3;)V

    :cond_18
    new-instance v1, Llyiahf/vczjk/fx2;

    const/4 v2, 0x0

    invoke-virtual {v13, v15, v2}, Llyiahf/vczjk/cg5;->OooO0OO(Llyiahf/vczjk/xc7;Z)Llyiahf/vczjk/ko;

    move-result-object v2

    invoke-direct {v1, v2}, Llyiahf/vczjk/l21;-><init>(Llyiahf/vczjk/ko;)V

    new-instance v2, Llyiahf/vczjk/fx2;

    invoke-virtual {v13, v15, v0}, Llyiahf/vczjk/cg5;->OooO0OO(Llyiahf/vczjk/xc7;Z)Llyiahf/vczjk/ko;

    move-result-object v0

    invoke-direct {v2, v0}, Llyiahf/vczjk/l21;-><init>(Llyiahf/vczjk/ko;)V

    move-object/from16 v0, v25

    invoke-virtual {v3, v0, v11, v1, v2}, Llyiahf/vczjk/ua7;->o0000OO0(Llyiahf/vczjk/va7;Llyiahf/vczjk/hb7;Llyiahf/vczjk/fx2;Llyiahf/vczjk/fx2;)V

    return-object v3

    :cond_19
    move-object v13, v10

    const/16 v0, 0xb

    invoke-static {v0}, Llyiahf/vczjk/c23;->OooO00o(I)V

    const/16 v17, 0x0

    throw v17

    :cond_1a
    move-object/from16 v17, v9

    move-object v13, v10

    const/16 v18, 0xa

    invoke-static/range {v18 .. v18}, Llyiahf/vczjk/c23;->OooO00o(I)V

    throw v17
.end method

.method public final OooO0o0(Llyiahf/vczjk/pc7;)Llyiahf/vczjk/u82;
    .locals 27

    move-object/from16 v0, p0

    move-object/from16 v7, p1

    const-string v1, "proto"

    invoke-static {v7, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v7}, Llyiahf/vczjk/pc7;->OoooOOo()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v7}, Llyiahf/vczjk/pc7;->getFlags()I

    move-result v1

    :goto_0
    move v13, v1

    goto :goto_1

    :cond_0
    invoke-virtual {v7}, Llyiahf/vczjk/pc7;->Oooo0oo()I

    move-result v1

    and-int/lit8 v2, v1, 0x3f

    shr-int/lit8 v1, v1, 0x8

    shl-int/lit8 v1, v1, 0x6

    add-int/2addr v1, v2

    goto :goto_0

    :goto_1
    const/4 v14, 0x1

    invoke-virtual {v0, v7, v13, v14}, Llyiahf/vczjk/cg5;->OooO0O0(Llyiahf/vczjk/sg3;II)Llyiahf/vczjk/ko;

    move-result-object v4

    invoke-virtual {v7}, Llyiahf/vczjk/pc7;->OoooOoo()Z

    move-result v1

    sget-object v15, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    iget-object v2, v0, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    if-nez v1, :cond_2

    invoke-virtual {v7}, Llyiahf/vczjk/pc7;->Ooooo00()Z

    move-result v1

    if-eqz v1, :cond_1

    goto :goto_2

    :cond_1
    move-object v1, v15

    goto :goto_3

    :cond_2
    :goto_2
    new-instance v1, Llyiahf/vczjk/x72;

    iget-object v3, v2, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/s72;

    iget-object v3, v3, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance v5, Llyiahf/vczjk/ag5;

    const/4 v6, 0x1

    invoke-direct {v5, v0, v7, v14, v6}, Llyiahf/vczjk/ag5;-><init>(Llyiahf/vczjk/cg5;Llyiahf/vczjk/sg3;II)V

    invoke-direct {v1, v3, v5}, Llyiahf/vczjk/x72;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    :goto_3
    iget-object v3, v2, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/v02;

    invoke-static {v3}, Llyiahf/vczjk/p72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hc3;

    move-result-object v3

    invoke-virtual {v7}, Llyiahf/vczjk/pc7;->Oooo0oO()I

    move-result v5

    iget-object v6, v2, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/rt5;

    invoke-static {v6, v5}, Llyiahf/vczjk/l4a;->OooOo(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/qt5;

    move-result-object v5

    invoke-virtual {v3, v5}, Llyiahf/vczjk/hc3;->OooO00o(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hc3;

    move-result-object v3

    sget-object v5, Llyiahf/vczjk/cb9;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-virtual {v3, v5}, Llyiahf/vczjk/hc3;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_3

    sget-object v3, Llyiahf/vczjk/xea;->OooO0O0:Llyiahf/vczjk/xea;

    :goto_4
    move-object v10, v3

    goto :goto_5

    :cond_3
    iget-object v3, v2, Llyiahf/vczjk/u72;->OooO0o0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/xea;

    goto :goto_4

    :goto_5
    new-instance v16, Llyiahf/vczjk/u82;

    invoke-virtual {v7}, Llyiahf/vczjk/pc7;->Oooo0oO()I

    move-result v3

    invoke-static {v6, v3}, Llyiahf/vczjk/l4a;->OooOo(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/qt5;

    move-result-object v5

    sget-object v3, Llyiahf/vczjk/c23;->OooOOOo:Llyiahf/vczjk/a23;

    invoke-virtual {v3, v13}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/qc7;

    invoke-static {v3}, Llyiahf/vczjk/er8;->OooOOo0(Llyiahf/vczjk/qc7;)I

    move-result v6

    iget-object v3, v2, Llyiahf/vczjk/u72;->OooO0Oo:Ljava/lang/Object;

    move-object v9, v3

    check-cast v9, Llyiahf/vczjk/h87;

    const/4 v12, 0x0

    iget-object v8, v2, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/v02;

    iget-object v11, v2, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v11, Llyiahf/vczjk/rt5;

    iget-object v3, v2, Llyiahf/vczjk/u72;->OooO0oO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ce4;

    move-object v0, v1

    move-object v14, v2

    move-object v2, v8

    move-object v8, v11

    move-object/from16 v1, v16

    move-object v11, v3

    const/4 v3, 0x0

    invoke-direct/range {v1 .. v12}, Llyiahf/vczjk/u82;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/ho8;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;ILlyiahf/vczjk/pc7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/xea;Llyiahf/vczjk/ce4;Llyiahf/vczjk/sx8;)V

    invoke-virtual {v7}, Llyiahf/vczjk/pc7;->OoooO()Ljava/util/List;

    move-result-object v2

    const-string v3, "getTypeParameterList(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v14, v1, v2}, Llyiahf/vczjk/u72;->OooO0O0(Llyiahf/vczjk/u72;Llyiahf/vczjk/y02;Ljava/util/List;)Llyiahf/vczjk/u72;

    move-result-object v2

    invoke-static {v7, v9}, Llyiahf/vczjk/eo6;->OooOo0o(Llyiahf/vczjk/pc7;Llyiahf/vczjk/h87;)Llyiahf/vczjk/hd7;

    move-result-object v3

    const/4 v4, 0x0

    iget-object v5, v2, Llyiahf/vczjk/u72;->OooO0oo:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/t3a;

    if-eqz v3, :cond_4

    invoke-virtual {v5, v3}, Llyiahf/vczjk/t3a;->OooO0oO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/uk4;

    move-result-object v3

    if-eqz v3, :cond_4

    invoke-static {v1, v3, v0}, Llyiahf/vczjk/dn8;->OoooO0O(Llyiahf/vczjk/co0;Llyiahf/vczjk/uk4;Llyiahf/vczjk/ko;)Llyiahf/vczjk/mp4;

    move-result-object v0

    move-object/from16 v17, v0

    goto :goto_6

    :cond_4
    move-object/from16 v17, v4

    :goto_6
    iget-object v0, v14, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v02;

    instance-of v3, v0, Llyiahf/vczjk/by0;

    if-eqz v3, :cond_5

    check-cast v0, Llyiahf/vczjk/by0;

    goto :goto_7

    :cond_5
    move-object v0, v4

    :goto_7
    if-eqz v0, :cond_6

    invoke-interface {v0}, Llyiahf/vczjk/by0;->o00000()Llyiahf/vczjk/mp4;

    move-result-object v0

    move-object/from16 v18, v0

    goto :goto_8

    :cond_6
    move-object/from16 v18, v4

    :goto_8
    invoke-virtual {v7}, Llyiahf/vczjk/pc7;->Oooo0o0()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v3

    if-nez v3, :cond_7

    goto :goto_9

    :cond_7
    move-object v0, v4

    :goto_9
    if-nez v0, :cond_9

    invoke-virtual {v7}, Llyiahf/vczjk/pc7;->Oooo0OO()Ljava/util/List;

    move-result-object v0

    const-string v3, "getContextReceiverTypeIdList(...)"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Ljava/util/ArrayList;

    const/16 v6, 0xa

    invoke-static {v0, v6}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v6

    invoke-direct {v3, v6}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_a
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_8

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/Integer;

    invoke-static {v6}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    move-result v6

    invoke-virtual {v9, v6}, Llyiahf/vczjk/h87;->OooO0Oo(I)Llyiahf/vczjk/hd7;

    move-result-object v6

    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_a

    :cond_8
    move-object v0, v3

    :cond_9
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    const/4 v6, 0x0

    :goto_b
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_c

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    add-int/lit8 v10, v6, 0x1

    if-ltz v6, :cond_b

    check-cast v8, Llyiahf/vczjk/hd7;

    invoke-virtual {v5, v8}, Llyiahf/vczjk/t3a;->OooO0oO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/uk4;

    move-result-object v8

    invoke-static {v1, v8, v4, v15, v6}, Llyiahf/vczjk/dn8;->Oooo0OO(Llyiahf/vczjk/co0;Llyiahf/vczjk/uk4;Llyiahf/vczjk/qt5;Llyiahf/vczjk/ko;I)Llyiahf/vczjk/mp4;

    move-result-object v6

    if-eqz v6, :cond_a

    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_a
    move v6, v10

    goto :goto_b

    :cond_b
    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    throw v4

    :cond_c
    invoke-virtual {v5}, Llyiahf/vczjk/t3a;->OooO0O0()Ljava/util/List;

    move-result-object v20

    invoke-virtual {v7}, Llyiahf/vczjk/pc7;->o000oOoO()Ljava/util/List;

    move-result-object v0

    const-string v4, "getValueParameterList(...)"

    invoke-static {v0, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v2, Llyiahf/vczjk/u72;->OooO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/cg5;

    const/4 v4, 0x1

    invoke-virtual {v2, v0, v7, v4}, Llyiahf/vczjk/cg5;->OooO0oO(Ljava/util/List;Llyiahf/vczjk/sg3;I)Ljava/util/List;

    move-result-object v21

    invoke-static {v7, v9}, Llyiahf/vczjk/eo6;->OooOoO0(Llyiahf/vczjk/pc7;Llyiahf/vczjk/h87;)Llyiahf/vczjk/hd7;

    move-result-object v0

    invoke-virtual {v5, v0}, Llyiahf/vczjk/t3a;->OooO0oO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/uk4;

    move-result-object v22

    sget-object v0, Llyiahf/vczjk/c23;->OooO0o0:Llyiahf/vczjk/a23;

    invoke-virtual {v0, v13}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/rc7;

    invoke-static {v0}, Llyiahf/vczjk/ws7;->OooOOo0(Llyiahf/vczjk/rc7;)Llyiahf/vczjk/yk5;

    move-result-object v23

    sget-object v0, Llyiahf/vczjk/c23;->OooO0Oo:Llyiahf/vczjk/a23;

    invoke-virtual {v0, v13}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/vd7;

    invoke-static {v0}, Llyiahf/vczjk/er8;->OooOO0o(Llyiahf/vczjk/vd7;)Llyiahf/vczjk/q72;

    move-result-object v24

    sget-object v25, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    move-object/from16 v16, v1

    move-object/from16 v19, v3

    invoke-virtual/range {v16 .. v25}, Llyiahf/vczjk/ho8;->o0000o(Llyiahf/vczjk/mp4;Llyiahf/vczjk/mp4;Ljava/util/List;Ljava/util/List;Ljava/util/List;Llyiahf/vczjk/uk4;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;Llyiahf/vczjk/bn2;)Llyiahf/vczjk/ho8;

    move-object/from16 v1, v16

    sget-object v0, Llyiahf/vczjk/c23;->OooOOo0:Llyiahf/vczjk/z13;

    invoke-virtual {v0, v13}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    iput-boolean v0, v1, Llyiahf/vczjk/tf3;->OooOoo0:Z

    sget-object v0, Llyiahf/vczjk/c23;->OooOOo:Llyiahf/vczjk/z13;

    invoke-virtual {v0, v13}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    iput-boolean v0, v1, Llyiahf/vczjk/tf3;->OooOoo:Z

    sget-object v0, Llyiahf/vczjk/c23;->OooOo0:Llyiahf/vczjk/z13;

    invoke-virtual {v0, v13}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    iput-boolean v0, v1, Llyiahf/vczjk/tf3;->OooOooO:Z

    sget-object v0, Llyiahf/vczjk/c23;->OooOOoo:Llyiahf/vczjk/z13;

    invoke-virtual {v0, v13}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    iput-boolean v0, v1, Llyiahf/vczjk/tf3;->OooOooo:Z

    sget-object v0, Llyiahf/vczjk/c23;->OooOo00:Llyiahf/vczjk/z13;

    invoke-virtual {v0, v13}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    iput-boolean v0, v1, Llyiahf/vczjk/tf3;->Oooo000:Z

    sget-object v0, Llyiahf/vczjk/c23;->OooOo0O:Llyiahf/vczjk/z13;

    invoke-virtual {v0, v13}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    iput-boolean v0, v1, Llyiahf/vczjk/tf3;->Oooo0O0:Z

    sget-object v0, Llyiahf/vczjk/c23;->OooOo0o:Llyiahf/vczjk/z13;

    invoke-virtual {v0, v13}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    iput-boolean v0, v1, Llyiahf/vczjk/tf3;->Oooo00O:Z

    sget-object v0, Llyiahf/vczjk/c23;->OooOo:Llyiahf/vczjk/z13;

    invoke-virtual {v0, v13}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    const/16 v26, 0x1

    xor-int/lit8 v0, v0, 0x1

    iput-boolean v0, v1, Llyiahf/vczjk/tf3;->Oooo0OO:Z

    iget-object v0, v14, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooOOO0:Llyiahf/vczjk/qp3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-object v1
.end method

.method public final OooO0oO(Ljava/util/List;Llyiahf/vczjk/sg3;I)Ljava/util/List;
    .locals 23

    move-object/from16 v1, p0

    iget-object v7, v1, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v0, v7, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v02;

    const-string v2, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.CallableDescriptor"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v9, v0

    check-cast v9, Llyiahf/vczjk/co0;

    invoke-interface {v9}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    const-string v2, "getContainingDeclaration(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/cg5;->OooO00o(Llyiahf/vczjk/v02;)Llyiahf/vczjk/yd7;

    move-result-object v2

    new-instance v8, Ljava/util/ArrayList;

    const/16 v0, 0xa

    move-object/from16 v3, p1

    invoke-static {v3, v0}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v0

    invoke-direct {v8, v0}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v20

    const/16 v21, 0x0

    move/from16 v5, v21

    :goto_0
    invoke-interface/range {v20 .. v20}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_6

    invoke-interface/range {v20 .. v20}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    add-int/lit8 v22, v5, 0x1

    const/4 v10, 0x0

    if-ltz v5, :cond_5

    move-object v6, v0

    check-cast v6, Llyiahf/vczjk/pd7;

    invoke-virtual {v6}, Llyiahf/vczjk/pd7;->OooOoOO()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {v6}, Llyiahf/vczjk/pd7;->getFlags()I

    move-result v0

    move v11, v0

    goto :goto_1

    :cond_0
    move/from16 v11, v21

    :goto_1
    if-eqz v2, :cond_1

    sget-object v0, Llyiahf/vczjk/c23;->OooO0OO:Llyiahf/vczjk/z13;

    invoke-virtual {v0, v11}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_1

    new-instance v12, Llyiahf/vczjk/j26;

    iget-object v0, v7, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v13, v0, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance v0, Llyiahf/vczjk/bg5;

    move-object/from16 v3, p2

    move/from16 v4, p3

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/bg5;-><init>(Llyiahf/vczjk/cg5;Llyiahf/vczjk/yd7;Llyiahf/vczjk/sg3;IILlyiahf/vczjk/pd7;)V

    invoke-direct {v12, v13, v0}, Llyiahf/vczjk/j26;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_1
    sget-object v12, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    :goto_2
    invoke-virtual {v6}, Llyiahf/vczjk/pd7;->OooOo0O()I

    move-result v0

    iget-object v1, v7, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/rt5;

    invoke-static {v1, v0}, Llyiahf/vczjk/l4a;->OooOo(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/qt5;

    move-result-object v13

    iget-object v0, v7, Llyiahf/vczjk/u72;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/h87;

    invoke-static {v6, v0}, Llyiahf/vczjk/eo6;->OooOoo(Llyiahf/vczjk/pd7;Llyiahf/vczjk/h87;)Llyiahf/vczjk/hd7;

    move-result-object v1

    iget-object v3, v7, Llyiahf/vczjk/u72;->OooO0oo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/t3a;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/t3a;->OooO0oO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/uk4;

    move-result-object v14

    sget-object v1, Llyiahf/vczjk/c23;->Oooo00o:Llyiahf/vczjk/z13;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v15

    sget-object v1, Llyiahf/vczjk/c23;->Oooo0:Llyiahf/vczjk/z13;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v16

    sget-object v1, Llyiahf/vczjk/c23;->Oooo0O0:Llyiahf/vczjk/z13;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v17

    invoke-virtual {v6}, Llyiahf/vczjk/pd7;->OooOooo()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-virtual {v6}, Llyiahf/vczjk/pd7;->OooOoO0()Llyiahf/vczjk/hd7;

    move-result-object v0

    goto :goto_3

    :cond_2
    invoke-virtual {v6}, Llyiahf/vczjk/pd7;->Oooo000()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-virtual {v6}, Llyiahf/vczjk/pd7;->OooOoO()I

    move-result v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/h87;->OooO0Oo(I)Llyiahf/vczjk/hd7;

    move-result-object v0

    goto :goto_3

    :cond_3
    move-object v0, v10

    :goto_3
    if-eqz v0, :cond_4

    invoke-virtual {v3, v0}, Llyiahf/vczjk/t3a;->OooO0oO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/uk4;

    move-result-object v10

    :cond_4
    move-object/from16 v18, v10

    sget-object v19, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    move-object v0, v8

    new-instance v8, Llyiahf/vczjk/tca;

    const/4 v10, 0x0

    move v11, v5

    invoke-direct/range {v8 .. v19}, Llyiahf/vczjk/tca;-><init>(Llyiahf/vczjk/co0;Llyiahf/vczjk/tca;ILlyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/uk4;ZZZLlyiahf/vczjk/uk4;Llyiahf/vczjk/sx8;)V

    invoke-virtual {v0, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v1, p0

    move-object v8, v0

    move/from16 v5, v22

    goto/16 :goto_0

    :cond_5
    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    throw v10

    :cond_6
    move-object v0, v8

    invoke-static {v0}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method
