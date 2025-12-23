.class public final Llyiahf/vczjk/i08;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/hb8;

.field public final synthetic OooOOOo:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOo:Landroid/content/Context;

.field public final synthetic OooOOo0:Llyiahf/vczjk/wa5;

.field public final synthetic OooOOoo:Ljava/lang/Object;

.field public final synthetic OooOo0:Ljava/lang/Object;

.field public final synthetic OooOo00:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/hb8;Llyiahf/vczjk/i48;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/wa5;Landroid/content/Context;Llyiahf/vczjk/cp8;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/i08;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i08;->OooOOO:Llyiahf/vczjk/qs5;

    iput-object p2, p0, Llyiahf/vczjk/i08;->OooOOOO:Llyiahf/vczjk/hb8;

    iput-object p3, p0, Llyiahf/vczjk/i08;->OooOOoo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/i08;->OooOOOo:Llyiahf/vczjk/qs5;

    iput-object p5, p0, Llyiahf/vczjk/i08;->OooOo00:Ljava/lang/Object;

    iput-object p6, p0, Llyiahf/vczjk/i08;->OooOOo0:Llyiahf/vczjk/wa5;

    iput-object p7, p0, Llyiahf/vczjk/i08;->OooOOo:Landroid/content/Context;

    iput-object p8, p0, Llyiahf/vczjk/i08;->OooOo0:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/xr1;Llyiahf/vczjk/lg0;Llyiahf/vczjk/hb8;Llyiahf/vczjk/h48;Llyiahf/vczjk/qs5;Llyiahf/vczjk/wa5;Landroid/content/Context;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/i08;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i08;->OooOOO:Llyiahf/vczjk/qs5;

    iput-object p2, p0, Llyiahf/vczjk/i08;->OooOOoo:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/i08;->OooOo00:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/i08;->OooOOOO:Llyiahf/vczjk/hb8;

    iput-object p5, p0, Llyiahf/vczjk/i08;->OooOo0:Ljava/lang/Object;

    iput-object p6, p0, Llyiahf/vczjk/i08;->OooOOOo:Llyiahf/vczjk/qs5;

    iput-object p7, p0, Llyiahf/vczjk/i08;->OooOOo0:Llyiahf/vczjk/wa5;

    iput-object p8, p0, Llyiahf/vczjk/i08;->OooOOo:Landroid/content/Context;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/i08;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/iw7;

    move-object/from16 v9, p2

    check-cast v9, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p3

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    const-string v3, "$this$ThanoxMediumAppBarScaffold"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v3, v1, 0x6

    if-nez v3, :cond_1

    move-object v3, v9

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v1, v3

    :cond_1
    and-int/lit8 v3, v1, 0x13

    const/16 v4, 0x12

    if-ne v3, v4, :cond_3

    move-object v3, v9

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_2

    :cond_3
    :goto_1
    iget-object v3, v0, Llyiahf/vczjk/i08;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/j28;

    iget-boolean v3, v3, Llyiahf/vczjk/j28;->OooO0OO:Z

    xor-int/lit8 v3, v3, 0x1

    new-instance v10, Llyiahf/vczjk/uz7;

    iget-object v11, v0, Llyiahf/vczjk/i08;->OooOOOO:Llyiahf/vczjk/hb8;

    iget-object v4, v0, Llyiahf/vczjk/i08;->OooOOoo:Ljava/lang/Object;

    move-object v12, v4

    check-cast v12, Llyiahf/vczjk/i48;

    iget-object v4, v0, Llyiahf/vczjk/i08;->OooOOo:Landroid/content/Context;

    iget-object v5, v0, Llyiahf/vczjk/i08;->OooOo0:Ljava/lang/Object;

    move-object/from16 v17, v5

    check-cast v17, Llyiahf/vczjk/cp8;

    iget-object v13, v0, Llyiahf/vczjk/i08;->OooOOOo:Llyiahf/vczjk/qs5;

    iget-object v5, v0, Llyiahf/vczjk/i08;->OooOo00:Ljava/lang/Object;

    move-object v14, v5

    check-cast v14, Llyiahf/vczjk/qs5;

    iget-object v15, v0, Llyiahf/vczjk/i08;->OooOOo0:Llyiahf/vczjk/wa5;

    move-object/from16 v16, v4

    invoke-direct/range {v10 .. v17}, Llyiahf/vczjk/uz7;-><init>(Llyiahf/vczjk/hb8;Llyiahf/vczjk/i48;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/wa5;Landroid/content/Context;Llyiahf/vczjk/cp8;)V

    const v4, 0x367d931e

    invoke-static {v4, v10, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    and-int/lit8 v1, v1, 0xe

    const/high16 v4, 0x180000

    or-int v10, v1, v4

    const/4 v5, 0x0

    const/16 v11, 0x1e

    const/4 v4, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    invoke-static/range {v2 .. v11}, Landroidx/compose/animation/OooO0O0;->OooO0OO(Llyiahf/vczjk/iw7;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_2
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/vk;

    move-object/from16 v8, p2

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    const-string v2, "$this$AnimatedVisibility"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v2, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    sget-object v3, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    const/4 v11, 0x0

    invoke-static {v2, v3, v8, v11}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    move-object v12, v8

    check-cast v12, Llyiahf/vczjk/zf1;

    iget v3, v12, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v8, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v5, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_4

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_4
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v8, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v4, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_5

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_6

    :cond_5
    invoke-static {v3, v12, v3, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v1, -0x6815fd56

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v13, v0, Llyiahf/vczjk/i08;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-virtual {v12, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    iget-object v3, v0, Llyiahf/vczjk/i08;->OooOOoo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/xr1;

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v2, v4

    iget-object v4, v0, Llyiahf/vczjk/i08;->OooOo00:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/lg0;

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v2, v5

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    sget-object v14, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v2, :cond_7

    if-ne v5, v14, :cond_8

    :cond_7
    new-instance v5, Llyiahf/vczjk/s20;

    const/4 v2, 0x1

    invoke-direct {v5, v3, v13, v4, v2}, Llyiahf/vczjk/s20;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/qs5;Llyiahf/vczjk/lg0;I)V

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    move-object v2, v5

    check-cast v2, Llyiahf/vczjk/le3;

    invoke-virtual {v12, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/xb1;->OooO00o:Llyiahf/vczjk/a91;

    const/high16 v9, 0x180000

    const/16 v10, 0x3e

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v2 .. v10}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    iget-object v2, v0, Llyiahf/vczjk/i08;->OooOOOO:Llyiahf/vczjk/hb8;

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v1, v3

    iget-object v3, v0, Llyiahf/vczjk/i08;->OooOo0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/h48;

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v1, v4

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v1, :cond_9

    if-ne v4, v14, :cond_a

    :cond_9
    new-instance v4, Llyiahf/vczjk/x5;

    const/16 v1, 0x14

    invoke-direct {v4, v2, v3, v1, v13}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    move-object v2, v4

    check-cast v2, Llyiahf/vczjk/le3;

    invoke-virtual {v12, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/xb1;->OooO0O0:Llyiahf/vczjk/a91;

    const/high16 v9, 0x180000

    const/16 v10, 0x3e

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v2 .. v10}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    const v1, -0x48fade91

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    iget-object v6, v0, Llyiahf/vczjk/i08;->OooOOOo:Llyiahf/vczjk/qs5;

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    iget-object v3, v0, Llyiahf/vczjk/i08;->OooOOo0:Llyiahf/vczjk/wa5;

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    iget-object v4, v0, Llyiahf/vczjk/i08;->OooOOo:Landroid/content/Context;

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_b

    if-ne v2, v14, :cond_c

    :cond_b
    new-instance v2, Llyiahf/vczjk/f08;

    const/4 v7, 0x0

    move-object v5, v13

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/f08;-><init>(Llyiahf/vczjk/wa5;Landroid/content/Context;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    check-cast v2, Llyiahf/vczjk/le3;

    invoke-virtual {v12, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/xb1;->OooO0OO:Llyiahf/vczjk/a91;

    const/high16 v9, 0x180000

    const/16 v10, 0x3e

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v2 .. v10}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    const/4 v1, 0x1

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
