.class public final Llyiahf/vczjk/u82;
.super Llyiahf/vczjk/ho8;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/y72;


# instance fields
.field public final OoooO:Llyiahf/vczjk/rt5;

.field public final OoooO0O:Llyiahf/vczjk/pc7;

.field public final OoooOO0:Llyiahf/vczjk/h87;

.field public final OoooOOO:Llyiahf/vczjk/ce4;

.field public final o000oOoO:Llyiahf/vczjk/xea;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/ho8;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;ILlyiahf/vczjk/pc7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/xea;Llyiahf/vczjk/ce4;Llyiahf/vczjk/sx8;)V
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

    move-object v4, p4

    move-object v0, p0

    goto :goto_0

    :cond_0
    move-object/from16 v6, p11

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    :goto_0
    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/ho8;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/ho8;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;ILlyiahf/vczjk/sx8;)V

    iput-object v7, p0, Llyiahf/vczjk/u82;->OoooO0O:Llyiahf/vczjk/pc7;

    iput-object v8, p0, Llyiahf/vczjk/u82;->OoooO:Llyiahf/vczjk/rt5;

    iput-object v9, p0, Llyiahf/vczjk/u82;->OoooOO0:Llyiahf/vczjk/h87;

    iput-object v10, p0, Llyiahf/vczjk/u82;->o000oOoO:Llyiahf/vczjk/xea;

    move-object/from16 v1, p10

    iput-object v1, p0, Llyiahf/vczjk/u82;->OoooOOO:Llyiahf/vczjk/ce4;

    return-void
.end method


# virtual methods
.method public final OooOooo()Llyiahf/vczjk/pi5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/u82;->OoooO0O:Llyiahf/vczjk/pc7;

    return-object v0
.end method

.method public final OoooO0O()Llyiahf/vczjk/h87;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/u82;->OoooOO0:Llyiahf/vczjk/h87;

    return-object v0
.end method

.method public final OoooOo0()Llyiahf/vczjk/rt5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/u82;->OoooO:Llyiahf/vczjk/rt5;

    return-object v0
.end method

.method public final Ooooo0o()Llyiahf/vczjk/j82;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/u82;->OoooOOO:Llyiahf/vczjk/ce4;

    return-object v0
.end method

.method public final o000OO(ILlyiahf/vczjk/ko;Llyiahf/vczjk/v02;Llyiahf/vczjk/rf3;Llyiahf/vczjk/qt5;Llyiahf/vczjk/sx8;)Llyiahf/vczjk/tf3;
    .locals 13

    const-string v0, "newOwner"

    move-object/from16 v2, p3

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "kind"

    invoke-static {p1, v0}, Llyiahf/vczjk/u81;->OooOOo(ILjava/lang/String;)V

    const-string v0, "annotations"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/u82;

    move-object/from16 v3, p4

    check-cast v3, Llyiahf/vczjk/ho8;

    if-nez p5, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    const-string v4, "getName(...)"

    invoke-static {v0, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v5, v0

    goto :goto_0

    :cond_0
    move-object/from16 v5, p5

    :goto_0
    iget-object v10, p0, Llyiahf/vczjk/u82;->o000oOoO:Llyiahf/vczjk/xea;

    iget-object v11, p0, Llyiahf/vczjk/u82;->OoooOOO:Llyiahf/vczjk/ce4;

    iget-object v7, p0, Llyiahf/vczjk/u82;->OoooO0O:Llyiahf/vczjk/pc7;

    iget-object v8, p0, Llyiahf/vczjk/u82;->OoooO:Llyiahf/vczjk/rt5;

    iget-object v9, p0, Llyiahf/vczjk/u82;->OoooOO0:Llyiahf/vczjk/h87;

    move v6, p1

    move-object v4, p2

    move-object/from16 v12, p6

    invoke-direct/range {v1 .. v12}, Llyiahf/vczjk/u82;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/ho8;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;ILlyiahf/vczjk/pc7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/xea;Llyiahf/vczjk/ce4;Llyiahf/vczjk/sx8;)V

    iget-boolean p1, p0, Llyiahf/vczjk/tf3;->Oooo0OO:Z

    iput-boolean p1, v1, Llyiahf/vczjk/tf3;->Oooo0OO:Z

    return-object v1
.end method
