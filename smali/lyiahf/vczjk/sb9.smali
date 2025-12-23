.class public final Llyiahf/vczjk/sb9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $contentColor:J

.field final synthetic $painter:Llyiahf/vczjk/jx0;

.field final synthetic $sizes:Llyiahf/vczjk/wb9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wb9;JLlyiahf/vczjk/jx0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sb9;->$sizes:Llyiahf/vczjk/wb9;

    iput-wide p2, p0, Llyiahf/vczjk/sb9;->$contentColor:J

    iput-object p4, p0, Llyiahf/vczjk/sb9;->$painter:Llyiahf/vczjk/jx0;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    move-object/from16 v9, p2

    check-cast v9, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v3, v2, 0xe

    const/4 v4, 0x2

    if-nez v3, :cond_1

    move-object v3, v9

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    move v3, v4

    :goto_0
    or-int/2addr v2, v3

    :cond_1
    and-int/lit8 v2, v2, 0x5b

    const/16 v3, 0x12

    if-ne v2, v3, :cond_3

    move-object v2, v9

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_4

    :cond_3
    :goto_1
    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v3, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    sget-object v5, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    iget-object v6, v0, Llyiahf/vczjk/sb9;->$sizes:Llyiahf/vczjk/wb9;

    iget-wide v7, v0, Llyiahf/vczjk/sb9;->$contentColor:J

    iget-object v10, v0, Llyiahf/vczjk/sb9;->$painter:Llyiahf/vczjk/jx0;

    const/4 v12, 0x0

    invoke-static {v5, v12}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v5

    move-object v13, v9

    check-cast v13, Llyiahf/vczjk/zf1;

    iget v11, v13, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v9, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v15, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v15, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v13, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_4

    invoke-virtual {v13, v15}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_4
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v12, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v9, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v14, v9, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v12, v13, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v12, :cond_5

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-static {v12, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v12

    if-nez v12, :cond_6

    :cond_5
    invoke-static {v11, v13, v11, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v9, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    if-eqz v1, :cond_7

    const v1, -0x5b071fef

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    iget v1, v6, Llyiahf/vczjk/wb9;->OooO0O0:F

    iget v5, v6, Llyiahf/vczjk/wb9;->OooO0OO:F

    add-float/2addr v1, v5

    int-to-float v3, v4

    mul-float/2addr v1, v3

    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/4 v10, 0x0

    const/16 v11, 0x18

    move-wide v3, v7

    const-wide/16 v6, 0x0

    const/4 v8, 0x0

    invoke-static/range {v2 .. v11}, Llyiahf/vczjk/fa7;->OooO00o(Llyiahf/vczjk/kl5;JFJILlyiahf/vczjk/rf1;II)V

    const/4 v1, 0x0

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_7
    const v1, -0x5b071e9d

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    move-object v2, v10

    const/16 v10, 0x38

    const/16 v11, 0x7c

    const-string v3, "Refreshing"

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    invoke-static/range {v2 .. v11}, Llyiahf/vczjk/c6a;->OooOOO(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;Llyiahf/vczjk/en1;FLlyiahf/vczjk/p21;Llyiahf/vczjk/rf1;II)V

    const/4 v1, 0x0

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    const/4 v1, 0x1

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_4
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
