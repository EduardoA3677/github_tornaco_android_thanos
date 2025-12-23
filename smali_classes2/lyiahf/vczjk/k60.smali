.class public final Llyiahf/vczjk/k60;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/String;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/k60;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/k60;->OooOOO:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 36

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/k60;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/4 v3, 0x3

    and-int/2addr v2, v3

    const/4 v4, 0x2

    if-ne v2, v4, :cond_1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_4

    :cond_1
    :goto_0
    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const v5, 0x3f23d70a    # 0.64f

    invoke-static {v2, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v1}, Llyiahf/vczjk/mt6;->OooOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/z98;

    move-result-object v5

    const/4 v6, 0x1

    invoke-static {v2, v5, v6}, Llyiahf/vczjk/mt6;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/z98;Z)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v5, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v7, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v8, 0x0

    invoke-static {v5, v7, v1, v8}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    move-object v7, v1

    check-cast v7, Llyiahf/vczjk/zf1;

    iget v9, v7, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v1, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v11, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_2

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_2
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v11, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v1, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v10, v1, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v10, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v10, :cond_3

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v10, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_4

    :cond_3
    invoke-static {v9, v7, v9, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_4
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v1, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v2, v0, Llyiahf/vczjk/k60;->OooOOO:Ljava/lang/String;

    const/16 v5, 0x3f

    invoke-static {v2, v5}, Landroid/text/Html;->fromHtml(Ljava/lang/String;I)Landroid/text/Spanned;

    move-result-object v2

    const-string v5, "fromHtml(...)"

    invoke-static {v2, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/ym;

    invoke-direct {v5}, Llyiahf/vczjk/ym;-><init>()V

    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v9

    iget-object v10, v5, Llyiahf/vczjk/ym;->OooOOO0:Ljava/lang/StringBuilder;

    invoke-virtual {v10, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    move-result v9

    const-class v10, Ljava/lang/Object;

    invoke-interface {v2, v8, v9, v10}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    move-result-object v9

    const-string v10, "getSpans(...)"

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    array-length v10, v9

    :goto_2
    if-ge v8, v10, :cond_c

    aget-object v11, v9, v8

    invoke-interface {v2, v11}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    move-result v12

    invoke-interface {v2, v11}, Landroid/text/Spanned;->getSpanEnd(Ljava/lang/Object;)I

    move-result v13

    instance-of v14, v11, Landroid/text/style/StyleSpan;

    if-eqz v14, :cond_8

    check-cast v11, Landroid/text/style/StyleSpan;

    invoke-virtual {v11}, Landroid/text/style/StyleSpan;->getStyle()I

    move-result v11

    if-eq v11, v6, :cond_7

    if-eq v11, v4, :cond_6

    if-eq v11, v3, :cond_5

    goto/16 :goto_3

    :cond_5
    new-instance v14, Llyiahf/vczjk/dy8;

    sget-object v19, Llyiahf/vczjk/ib3;->OooOo0O:Llyiahf/vczjk/ib3;

    new-instance v11, Llyiahf/vczjk/cb3;

    invoke-direct {v11, v6}, Llyiahf/vczjk/cb3;-><init>(I)V

    const/16 v31, 0x0

    const/16 v32, 0x0

    const-wide/16 v15, 0x0

    const-wide/16 v17, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const-wide/16 v24, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const-wide/16 v29, 0x0

    const v33, 0xfff3

    move-object/from16 v20, v11

    invoke-direct/range {v14 .. v33}, Llyiahf/vczjk/dy8;-><init>(JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/db3;Llyiahf/vczjk/ba3;Ljava/lang/String;JLlyiahf/vczjk/f90;Llyiahf/vczjk/ll9;Llyiahf/vczjk/e45;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ij8;I)V

    invoke-virtual {v5, v14, v12, v13}, Llyiahf/vczjk/ym;->OooO00o(Llyiahf/vczjk/dy8;II)V

    goto/16 :goto_3

    :cond_6
    new-instance v15, Llyiahf/vczjk/dy8;

    new-instance v11, Llyiahf/vczjk/cb3;

    invoke-direct {v11, v6}, Llyiahf/vczjk/cb3;-><init>(I)V

    const/16 v32, 0x0

    const/16 v33, 0x0

    const-wide/16 v16, 0x0

    const-wide/16 v18, 0x0

    const/16 v20, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const-wide/16 v25, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    const-wide/16 v30, 0x0

    const v34, 0xfff7

    move-object/from16 v21, v11

    invoke-direct/range {v15 .. v34}, Llyiahf/vczjk/dy8;-><init>(JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/db3;Llyiahf/vczjk/ba3;Ljava/lang/String;JLlyiahf/vczjk/f90;Llyiahf/vczjk/ll9;Llyiahf/vczjk/e45;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ij8;I)V

    invoke-virtual {v5, v15, v12, v13}, Llyiahf/vczjk/ym;->OooO00o(Llyiahf/vczjk/dy8;II)V

    goto/16 :goto_3

    :cond_7
    new-instance v16, Llyiahf/vczjk/dy8;

    sget-object v21, Llyiahf/vczjk/ib3;->OooOo0O:Llyiahf/vczjk/ib3;

    const/16 v33, 0x0

    const/16 v34, 0x0

    const-wide/16 v17, 0x0

    const-wide/16 v19, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const-wide/16 v26, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v30, 0x0

    const-wide/16 v31, 0x0

    const v35, 0xfffb

    invoke-direct/range {v16 .. v35}, Llyiahf/vczjk/dy8;-><init>(JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/db3;Llyiahf/vczjk/ba3;Ljava/lang/String;JLlyiahf/vczjk/f90;Llyiahf/vczjk/ll9;Llyiahf/vczjk/e45;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ij8;I)V

    move-object/from16 v11, v16

    invoke-virtual {v5, v11, v12, v13}, Llyiahf/vczjk/ym;->OooO00o(Llyiahf/vczjk/dy8;II)V

    goto/16 :goto_3

    :cond_8
    instance-of v14, v11, Landroid/text/style/UnderlineSpan;

    if-eqz v14, :cond_9

    new-instance v15, Llyiahf/vczjk/dy8;

    sget-object v32, Llyiahf/vczjk/vh9;->OooO0OO:Llyiahf/vczjk/vh9;

    const-wide/16 v30, 0x0

    const/16 v33, 0x0

    const-wide/16 v16, 0x0

    const-wide/16 v18, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const-wide/16 v25, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    const v34, 0xefff

    invoke-direct/range {v15 .. v34}, Llyiahf/vczjk/dy8;-><init>(JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/db3;Llyiahf/vczjk/ba3;Ljava/lang/String;JLlyiahf/vczjk/f90;Llyiahf/vczjk/ll9;Llyiahf/vczjk/e45;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ij8;I)V

    invoke-virtual {v5, v15, v12, v13}, Llyiahf/vczjk/ym;->OooO00o(Llyiahf/vczjk/dy8;II)V

    goto :goto_3

    :cond_9
    instance-of v14, v11, Landroid/text/style/ForegroundColorSpan;

    if-eqz v14, :cond_a

    new-instance v15, Llyiahf/vczjk/dy8;

    check-cast v11, Landroid/text/style/ForegroundColorSpan;

    invoke-virtual {v11}, Landroid/text/style/ForegroundColorSpan;->getForegroundColor()I

    move-result v11

    invoke-static {v11}, Llyiahf/vczjk/v34;->OooO0OO(I)J

    move-result-wide v16

    const/16 v32, 0x0

    const/16 v33, 0x0

    const-wide/16 v18, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const-wide/16 v25, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    const-wide/16 v30, 0x0

    const v34, 0xfffe

    invoke-direct/range {v15 .. v34}, Llyiahf/vczjk/dy8;-><init>(JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/db3;Llyiahf/vczjk/ba3;Ljava/lang/String;JLlyiahf/vczjk/f90;Llyiahf/vczjk/ll9;Llyiahf/vczjk/e45;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ij8;I)V

    invoke-virtual {v5, v15, v12, v13}, Llyiahf/vczjk/ym;->OooO00o(Llyiahf/vczjk/dy8;II)V

    goto :goto_3

    :cond_a
    instance-of v11, v11, Landroid/text/style/BulletSpan;

    if-eqz v11, :cond_b

    new-instance v14, Llyiahf/vczjk/dy8;

    const/16 v11, 0xc

    invoke-static {v11}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v17

    const/16 v31, 0x0

    const/16 v32, 0x0

    const-wide/16 v15, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const-wide/16 v24, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const-wide/16 v29, 0x0

    const v33, 0xfffd

    invoke-direct/range {v14 .. v33}, Llyiahf/vczjk/dy8;-><init>(JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/db3;Llyiahf/vczjk/ba3;Ljava/lang/String;JLlyiahf/vczjk/f90;Llyiahf/vczjk/ll9;Llyiahf/vczjk/e45;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ij8;I)V

    invoke-virtual {v5, v14, v12, v13}, Llyiahf/vczjk/ym;->OooO00o(Llyiahf/vczjk/dy8;II)V

    :cond_b
    :goto_3
    add-int/lit8 v8, v8, 0x1

    goto/16 :goto_2

    :cond_c
    invoke-virtual {v5}, Llyiahf/vczjk/ym;->OooO0OO()Llyiahf/vczjk/an;

    move-result-object v2

    const/16 v17, 0x0

    const v21, 0x7fffe

    const/4 v3, 0x0

    const-wide/16 v4, 0x0

    move v8, v6

    move-object v9, v7

    const-wide/16 v6, 0x0

    move v10, v8

    move-object v11, v9

    const-wide/16 v8, 0x0

    move v12, v10

    move-object v13, v11

    const-wide/16 v10, 0x0

    move v14, v12

    const/4 v12, 0x0

    move-object v15, v13

    const/4 v13, 0x0

    move/from16 v16, v14

    const/4 v14, 0x0

    move-object/from16 v18, v15

    const/4 v15, 0x0

    move/from16 v19, v16

    const/16 v16, 0x0

    move-object/from16 v20, v18

    const/16 v18, 0x0

    move-object/from16 v22, v20

    const/16 v20, 0x0

    move/from16 v0, v19

    move-object/from16 v19, v1

    move v1, v0

    move-object/from16 v0, v22

    invoke-static/range {v2 .. v21}, Llyiahf/vczjk/gm9;->OooO0OO(Llyiahf/vczjk/an;Llyiahf/vczjk/hl5;JJJJIZIILlyiahf/vczjk/bn2;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_4
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_0
    move-object/from16 v20, p1

    check-cast v20, Llyiahf/vczjk/rf1;

    move-object/from16 v0, p2

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0

    and-int/lit8 v0, v0, 0x3

    const/4 v1, 0x2

    if-ne v0, v1, :cond_e

    move-object/from16 v0, v20

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_d

    goto :goto_5

    :cond_d
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v0, p0

    goto :goto_6

    :cond_e
    :goto_5
    const/16 v22, 0x0

    const v23, 0x3fffe

    move-object/from16 v0, p0

    iget-object v1, v0, Llyiahf/vczjk/k60;->OooOOO:Ljava/lang/String;

    const/4 v2, 0x0

    const-wide/16 v3, 0x0

    const-wide/16 v5, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const-wide/16 v9, 0x0

    const/4 v11, 0x0

    const-wide/16 v12, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v21, 0x0

    invoke-static/range {v1 .. v23}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_6
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_1
    move-object/from16 v21, p1

    check-cast v21, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/lit8 v1, v1, 0x3

    const/4 v2, 0x2

    if-ne v1, v2, :cond_10

    move-object/from16 v1, v21

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_f

    goto :goto_7

    :cond_f
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_8

    :cond_10
    :goto_7
    const/16 v1, 0xc

    invoke-static {v1}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v6

    const-wide/high16 v1, 0x4029000000000000L    # 12.5

    invoke-static {v1, v2}, Llyiahf/vczjk/eo6;->OooOO0O(D)J

    move-result-wide v13

    const/16 v23, 0x30

    const v24, 0x3f7ee

    iget-object v2, v0, Llyiahf/vczjk/k60;->OooOOO:Ljava/lang/String;

    const/4 v3, 0x0

    const-wide/16 v4, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    const/4 v12, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v22, 0x6000

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_8
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_2
    move-object/from16 v21, p1

    check-cast v21, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/lit8 v1, v1, 0x3

    const/4 v2, 0x2

    if-ne v1, v2, :cond_12

    move-object/from16 v1, v21

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_11

    goto :goto_9

    :cond_11
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_a

    :cond_12
    :goto_9
    const/16 v1, 0xc

    invoke-static {v1}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v6

    const-wide/high16 v1, 0x4029000000000000L    # 12.5

    invoke-static {v1, v2}, Llyiahf/vczjk/eo6;->OooOO0O(D)J

    move-result-wide v13

    const/16 v23, 0x30

    const v24, 0x3f7ee

    iget-object v2, v0, Llyiahf/vczjk/k60;->OooOOO:Ljava/lang/String;

    const/4 v3, 0x0

    const-wide/16 v4, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    const/4 v12, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v22, 0x6000

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_a
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_3
    move-object/from16 v21, p1

    check-cast v21, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/lit8 v1, v1, 0x3

    const/4 v2, 0x2

    if-ne v1, v2, :cond_14

    move-object/from16 v1, v21

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_13

    goto :goto_b

    :cond_13
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_c

    :cond_14
    :goto_b
    const/16 v1, 0xc

    invoke-static {v1}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v6

    const-wide/high16 v1, 0x4029000000000000L    # 12.5

    invoke-static {v1, v2}, Llyiahf/vczjk/eo6;->OooOO0O(D)J

    move-result-wide v13

    const/16 v23, 0x30

    const v24, 0x3f7ee

    iget-object v2, v0, Llyiahf/vczjk/k60;->OooOOO:Ljava/lang/String;

    const/4 v3, 0x0

    const-wide/16 v4, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    const/4 v12, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v22, 0x6000

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_c
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_4
    move-object/from16 v21, p1

    check-cast v21, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/lit8 v1, v1, 0x3

    const/4 v2, 0x2

    if-ne v1, v2, :cond_16

    move-object/from16 v1, v21

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_15

    goto :goto_d

    :cond_15
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_e

    :cond_16
    :goto_d
    sget-object v1, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    move-object/from16 v2, v21

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/n6a;

    iget-object v1, v1, Llyiahf/vczjk/n6a;->OooOO0O:Llyiahf/vczjk/rn9;

    iget-object v2, v0, Llyiahf/vczjk/k60;->OooOOO:Ljava/lang/String;

    const/16 v23, 0x0

    const v24, 0x1fffe

    const/4 v3, 0x0

    const-wide/16 v4, 0x0

    const-wide/16 v6, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    const/4 v12, 0x0

    const-wide/16 v13, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v22, 0x0

    move-object/from16 v20, v1

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_e
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_5
    move-object/from16 v21, p1

    check-cast v21, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/lit8 v1, v1, 0x3

    const/4 v2, 0x2

    if-ne v1, v2, :cond_18

    move-object/from16 v1, v21

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_17

    goto :goto_f

    :cond_17
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_10

    :cond_18
    :goto_f
    sget-object v1, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    move-object/from16 v2, v21

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/n6a;

    iget-object v1, v1, Llyiahf/vczjk/n6a;->OooO0o:Llyiahf/vczjk/rn9;

    const/16 v23, 0x0

    const v24, 0x1fffe

    iget-object v2, v0, Llyiahf/vczjk/k60;->OooOOO:Ljava/lang/String;

    const/4 v3, 0x0

    const-wide/16 v4, 0x0

    const-wide/16 v6, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    const/4 v12, 0x0

    const-wide/16 v13, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v22, 0x6

    move-object/from16 v20, v1

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_10
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
