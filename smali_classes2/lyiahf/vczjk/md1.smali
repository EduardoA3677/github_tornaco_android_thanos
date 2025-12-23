.class public final Llyiahf/vczjk/md1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/md1;

.field public static final OooOOOO:Llyiahf/vczjk/md1;

.field public static final OooOOOo:Llyiahf/vczjk/md1;

.field public static final OooOOo:Llyiahf/vczjk/md1;

.field public static final OooOOo0:Llyiahf/vczjk/md1;

.field public static final OooOOoo:Llyiahf/vczjk/md1;

.field public static final OooOo00:Llyiahf/vczjk/md1;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/md1;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/md1;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/md1;->OooOOO:Llyiahf/vczjk/md1;

    new-instance v0, Llyiahf/vczjk/md1;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/md1;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/md1;->OooOOOO:Llyiahf/vczjk/md1;

    new-instance v0, Llyiahf/vczjk/md1;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Llyiahf/vczjk/md1;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/md1;->OooOOOo:Llyiahf/vczjk/md1;

    new-instance v0, Llyiahf/vczjk/md1;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Llyiahf/vczjk/md1;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/md1;->OooOOo0:Llyiahf/vczjk/md1;

    new-instance v0, Llyiahf/vczjk/md1;

    const/4 v1, 0x4

    invoke-direct {v0, v1}, Llyiahf/vczjk/md1;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/md1;->OooOOo:Llyiahf/vczjk/md1;

    new-instance v0, Llyiahf/vczjk/md1;

    const/4 v1, 0x5

    invoke-direct {v0, v1}, Llyiahf/vczjk/md1;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/md1;->OooOOoo:Llyiahf/vczjk/md1;

    new-instance v0, Llyiahf/vczjk/md1;

    const/4 v1, 0x6

    invoke-direct {v0, v1}, Llyiahf/vczjk/md1;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/md1;->OooOo00:Llyiahf/vczjk/md1;

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/md1;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 46

    const/4 v0, 0x0

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v2, 0x2

    const/4 v3, 0x3

    move-object/from16 v4, p0

    iget v5, v4, Llyiahf/vczjk/md1;->OooOOO0:I

    packed-switch v5, :pswitch_data_0

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v5, p2

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    and-int/2addr v5, v3

    if-ne v5, v2, :cond_1

    move-object v5, v0

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v6

    if-nez v6, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    new-instance v5, Llyiahf/vczjk/iv5;

    invoke-direct {v5, v2}, Llyiahf/vczjk/iv5;-><init>(I)V

    const v2, -0x65b01708

    invoke-static {v2, v5, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    new-instance v5, Llyiahf/vczjk/iv5;

    invoke-direct {v5, v3}, Llyiahf/vczjk/iv5;-><init>(I)V

    const v3, 0x669463b6

    invoke-static {v3, v5, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v3

    const/4 v5, 0x0

    const/16 v6, 0x186

    invoke-static {v2, v5, v3, v0, v6}, Llyiahf/vczjk/l50;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    :goto_1
    return-object v1

    :pswitch_0
    move-object/from16 v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    move-object/from16 v6, p2

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    move-result v6

    and-int/2addr v3, v6

    const/4 v7, 0x1

    if-eq v3, v2, :cond_2

    move v2, v7

    goto :goto_2

    :cond_2
    move v2, v0

    :goto_2
    and-int/lit8 v3, v6, 0x1

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5, v3, v2}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_6

    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    invoke-static {}, Llyiahf/vczjk/qt3;->OooO00o()J

    move-result-wide v8

    sget-object v3, Landroidx/compose/foundation/layout/OooO0OO;->OooO00o:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v8, v9}, Llyiahf/vczjk/ae2;->OooO0O0(J)F

    move-result v3

    invoke-static {v8, v9}, Llyiahf/vczjk/ae2;->OooO00o(J)F

    move-result v6

    invoke-static {v2, v3, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOO0(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    invoke-static {v3, v0}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v3

    iget v6, v5, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v5, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v9, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v10, v5, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v10, :cond_3

    invoke-virtual {v5, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_3
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v5, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v8, v5, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v8, v5, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v8, :cond_4

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_5

    :cond_4
    invoke-static {v6, v5, v6, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_5
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v5, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/ja1;->OooO00o:Llyiahf/vczjk/a91;

    invoke-virtual {v2, v5, v0}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v5, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_4

    :cond_6
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_4
    return-object v1

    :pswitch_1
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    check-cast v1, Llyiahf/vczjk/zf1;

    const v2, -0x1e824845

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v2, Llyiahf/vczjk/nf0;->OooO00o:Llyiahf/vczjk/nf0;

    sget-object v2, Llyiahf/vczjk/poa;->OooOo0O:Ljava/util/WeakHashMap;

    invoke-static {v1}, Llyiahf/vczjk/qp3;->OooOo0o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/poa;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/zy4;

    iget-object v2, v2, Llyiahf/vczjk/poa;->OooOO0O:Llyiahf/vczjk/x8a;

    const/16 v5, 0x30

    invoke-direct {v3, v2, v5}, Llyiahf/vczjk/zy4;-><init>(Llyiahf/vczjk/kna;I)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v3

    :pswitch_2
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    check-cast v1, Llyiahf/vczjk/zf1;

    const v2, 0x3f8a6608

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v2, 0x4dac4df

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v2, Llyiahf/vczjk/q35;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lcom/bumptech/glide/request/RequestOptions;

    if-nez v2, :cond_7

    new-instance v2, Lcom/bumptech/glide/request/RequestOptions;

    invoke-direct {v2}, Lcom/bumptech/glide/request/RequestOptions;-><init>()V

    :cond_7
    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v2

    :pswitch_3
    move-object/from16 v0, p1

    check-cast v0, Ljava/io/File;

    move-object/from16 v1, p2

    check-cast v1, Ljava/io/IOException;

    const-string v2, "<unused var>"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "exception"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    throw v1

    :pswitch_4
    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/v02;

    move-object/from16 v0, p2

    check-cast v0, Llyiahf/vczjk/v02;

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object v0

    :pswitch_5
    move-object/from16 v10, p1

    check-cast v10, Llyiahf/vczjk/rf1;

    move-object/from16 v0, p2

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0

    and-int/2addr v0, v3

    if-ne v0, v2, :cond_9

    move-object v0, v10

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_8

    goto :goto_5

    :cond_8
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_6

    :cond_9
    :goto_5
    sget v0, Lgithub/tornaco/android/thanos/module/common/R$drawable;->module_common_ic_outline_delete_24:I

    invoke-static {v0, v10}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v5

    const/16 v11, 0x30

    const/16 v12, 0xc

    const-string v6, "Delete"

    const/4 v7, 0x0

    const-wide/16 v8, 0x0

    invoke-static/range {v5 .. v12}, Llyiahf/vczjk/zt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    :goto_6
    return-object v1

    :pswitch_6
    move-object/from16 v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    move-object/from16 v6, p2

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    move-result v6

    and-int/2addr v3, v6

    if-ne v3, v2, :cond_b

    move-object v2, v5

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_a

    goto :goto_7

    :cond_a
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_8

    :cond_b
    :goto_7
    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->module_locker_title_white_list_components:I

    invoke-static {v2, v5}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v13

    move-object v2, v5

    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, -0x4021aeb5

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v3, Llyiahf/vczjk/gm9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    move-object/from16 v33, v3

    check-cast v33, Llyiahf/vczjk/rn9;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v36, 0x0

    const v37, 0xfffe

    const/4 v14, 0x0

    const-wide/16 v15, 0x0

    const-wide/16 v17, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const-wide/16 v22, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const-wide/16 v26, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v30, 0x0

    const/16 v31, 0x0

    const/16 v32, 0x0

    const/16 v35, 0x0

    move-object/from16 v34, v5

    invoke-static/range {v13 .. v37}, Llyiahf/vczjk/hm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/cb3;Llyiahf/vczjk/ib3;Llyiahf/vczjk/ba3;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_8
    return-object v1

    :pswitch_7
    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v5, p2

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    and-int/2addr v3, v5

    if-ne v3, v2, :cond_d

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_c

    goto :goto_9

    :cond_c
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_a

    :cond_d
    :goto_9
    sget v2, Lgithub/tornaco/android/thanos/module/common/R$drawable;->module_common_ic_add_fill:I

    invoke-static {v2, v0}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v38

    const/16 v44, 0x30

    const/16 v45, 0xc

    const-string v39, "Add"

    const/16 v40, 0x0

    const-wide/16 v41, 0x0

    move-object/from16 v43, v0

    invoke-static/range {v38 .. v45}, Llyiahf/vczjk/zt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    :goto_a
    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
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
