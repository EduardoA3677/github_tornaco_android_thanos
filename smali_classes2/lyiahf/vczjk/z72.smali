.class public final Llyiahf/vczjk/z72;
.super Llyiahf/vczjk/ux0;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/y72;


# instance fields
.field public final OoooO:Llyiahf/vczjk/cc7;

.field public final OoooOO0:Llyiahf/vczjk/rt5;

.field public final OoooOOO:Llyiahf/vczjk/xea;

.field public final OoooOOo:Llyiahf/vczjk/ce4;

.field public final o000oOoO:Llyiahf/vczjk/h87;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/by0;Llyiahf/vczjk/il1;Llyiahf/vczjk/ko;ZILlyiahf/vczjk/cc7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/xea;Llyiahf/vczjk/ce4;Llyiahf/vczjk/sx8;)V
    .locals 11

    move-object/from16 v7, p6

    move-object/from16 v8, p7

    move-object/from16 v9, p8

    move-object/from16 v10, p9

    const-string v0, "containingDeclaration"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "annotations"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "kind"

    move/from16 v5, p5

    invoke-static {v5, v0}, Llyiahf/vczjk/u81;->OooOOo(ILjava/lang/String;)V

    const-string v0, "proto"

    invoke-static {v7, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "nameResolver"

    invoke-static {v8, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "typeTable"

    invoke-static {v9, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "versionRequirementTable"

    invoke-static {v10, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-nez p11, :cond_0

    sget-object v0, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    move-object v6, v0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move v4, p4

    move-object v0, p0

    goto :goto_0

    :cond_0
    move-object/from16 v6, p11

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move v4, p4

    :goto_0
    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/ux0;-><init>(Llyiahf/vczjk/by0;Llyiahf/vczjk/il1;Llyiahf/vczjk/ko;ZILlyiahf/vczjk/sx8;)V

    iput-object v7, p0, Llyiahf/vczjk/z72;->OoooO:Llyiahf/vczjk/cc7;

    iput-object v8, p0, Llyiahf/vczjk/z72;->OoooOO0:Llyiahf/vczjk/rt5;

    iput-object v9, p0, Llyiahf/vczjk/z72;->o000oOoO:Llyiahf/vczjk/h87;

    iput-object v10, p0, Llyiahf/vczjk/z72;->OoooOOO:Llyiahf/vczjk/xea;

    move-object/from16 v1, p10

    iput-object v1, p0, Llyiahf/vczjk/z72;->OoooOOo:Llyiahf/vczjk/ce4;

    return-void
.end method


# virtual methods
.method public final OooO0o()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo0O()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOooo()Llyiahf/vczjk/pi5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z72;->OoooO:Llyiahf/vczjk/cc7;

    return-object v0
.end method

.method public final Oooo0oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OoooO0O()Llyiahf/vczjk/h87;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z72;->o000oOoO:Llyiahf/vczjk/h87;

    return-object v0
.end method

.method public final OoooOo0()Llyiahf/vczjk/rt5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z72;->OoooOO0:Llyiahf/vczjk/rt5;

    return-object v0
.end method

.method public final Ooooo0o()Llyiahf/vczjk/j82;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z72;->OoooOOo:Llyiahf/vczjk/ce4;

    return-object v0
.end method

.method public final bridge synthetic o0000o0(ILlyiahf/vczjk/ko;Llyiahf/vczjk/v02;Llyiahf/vczjk/rf3;Llyiahf/vczjk/qt5;Llyiahf/vczjk/sx8;)Llyiahf/vczjk/ux0;
    .locals 0

    move-object p5, p2

    move-object p2, p3

    move-object p3, p4

    move p4, p1

    move-object p1, p0

    invoke-virtual/range {p1 .. p6}, Llyiahf/vczjk/z72;->o0000oOo(Llyiahf/vczjk/v02;Llyiahf/vczjk/rf3;ILlyiahf/vczjk/ko;Llyiahf/vczjk/sx8;)Llyiahf/vczjk/z72;

    move-result-object p2

    return-object p2
.end method

.method public final o0000oOo(Llyiahf/vczjk/v02;Llyiahf/vczjk/rf3;ILlyiahf/vczjk/ko;Llyiahf/vczjk/sx8;)Llyiahf/vczjk/z72;
    .locals 13

    const-string v0, "newOwner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "kind"

    move/from16 v6, p3

    invoke-static {v6, v0}, Llyiahf/vczjk/u81;->OooOOo(ILjava/lang/String;)V

    const-string v0, "annotations"

    move-object/from16 v4, p4

    invoke-static {v4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/z72;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/by0;

    move-object v3, p2

    check-cast v3, Llyiahf/vczjk/il1;

    iget-object v10, p0, Llyiahf/vczjk/z72;->OoooOOO:Llyiahf/vczjk/xea;

    iget-object v11, p0, Llyiahf/vczjk/z72;->OoooOOo:Llyiahf/vczjk/ce4;

    iget-boolean v5, p0, Llyiahf/vczjk/ux0;->OoooO0O:Z

    iget-object v7, p0, Llyiahf/vczjk/z72;->OoooO:Llyiahf/vczjk/cc7;

    iget-object v8, p0, Llyiahf/vczjk/z72;->OoooOO0:Llyiahf/vczjk/rt5;

    iget-object v9, p0, Llyiahf/vczjk/z72;->o000oOoO:Llyiahf/vczjk/h87;

    move-object/from16 v12, p5

    invoke-direct/range {v1 .. v12}, Llyiahf/vczjk/z72;-><init>(Llyiahf/vczjk/by0;Llyiahf/vczjk/il1;Llyiahf/vczjk/ko;ZILlyiahf/vczjk/cc7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/xea;Llyiahf/vczjk/ce4;Llyiahf/vczjk/sx8;)V

    iget-boolean p1, p0, Llyiahf/vczjk/tf3;->Oooo0OO:Z

    iput-boolean p1, v1, Llyiahf/vczjk/tf3;->Oooo0OO:Z

    return-object v1
.end method

.method public final bridge synthetic o000OO(ILlyiahf/vczjk/ko;Llyiahf/vczjk/v02;Llyiahf/vczjk/rf3;Llyiahf/vczjk/qt5;Llyiahf/vczjk/sx8;)Llyiahf/vczjk/tf3;
    .locals 0

    move-object p5, p2

    move-object p2, p3

    move-object p3, p4

    move p4, p1

    move-object p1, p0

    invoke-virtual/range {p1 .. p6}, Llyiahf/vczjk/z72;->o0000oOo(Llyiahf/vczjk/v02;Llyiahf/vczjk/rf3;ILlyiahf/vczjk/ko;Llyiahf/vczjk/sx8;)Llyiahf/vczjk/z72;

    move-result-object p2

    return-object p2
.end method
