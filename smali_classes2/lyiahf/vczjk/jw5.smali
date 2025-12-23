.class public final Llyiahf/vczjk/jw5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qr5;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/qr5;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/jw5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/jw5;->OooOOO:Llyiahf/vczjk/qr5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 37

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/jw5;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/iw7;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    const-string v4, "$this$TextButton"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v3, 0x11

    const/16 v3, 0x10

    if-ne v1, v3, :cond_1

    move-object v1, v2

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    const v1, 0x104000a

    invoke-static {v1, v2}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v1

    iget-object v3, v0, Llyiahf/vczjk/jw5;->OooOOO:Llyiahf/vczjk/qr5;

    check-cast v3, Llyiahf/vczjk/bw8;

    invoke-virtual {v3}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v3

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " "

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, "s"

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    const/16 v23, 0x0

    const v24, 0x3fffe

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

    const/16 v20, 0x0

    const/16 v22, 0x0

    move-object/from16 v21, v2

    move-object v2, v1

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_1
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/iw7;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    const-string v4, "$this$TextButton"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v3, 0x11

    const/16 v3, 0x10

    if-ne v1, v3, :cond_3

    move-object v1, v2

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_3

    :cond_3
    :goto_2
    iget-object v1, v0, Llyiahf/vczjk/jw5;->OooOOO:Llyiahf/vczjk/qr5;

    check-cast v1, Llyiahf/vczjk/bw8;

    invoke-virtual {v1}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v3

    const v4, 0x104000a

    const/4 v5, 0x0

    if-lez v3, :cond_5

    move-object v13, v2

    check-cast v13, Llyiahf/vczjk/zf1;

    const v2, -0x2629d56e

    invoke-virtual {v13, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-static {v4, v13}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v1

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " "

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, "s"

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v6

    const v1, 0x20afa4f1

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v1, 0x6e3c21fe

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v1, v2, :cond_4

    sget-object v1, Llyiahf/vczjk/g13;->Oooo0:Llyiahf/vczjk/g13;

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    move-object v8, v1

    check-cast v8, Llyiahf/vczjk/oe3;

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v1, Llyiahf/vczjk/k91;

    const/16 v2, 0xb

    invoke-direct {v1, v2}, Llyiahf/vczjk/k91;-><init>(I)V

    const v2, 0x72008807

    invoke-static {v2, v1, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v12

    const v14, 0x180180

    const/16 v15, 0x3a

    const/4 v7, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    invoke-static/range {v6 .. v15}, Landroidx/compose/animation/OooO00o;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o4;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_5
    check-cast v2, Llyiahf/vczjk/zf1;

    const v1, -0x2626d783

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-static {v4, v2}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v14

    const/16 v35, 0x0

    const v36, 0x3fffe

    const/4 v15, 0x0

    const-wide/16 v16, 0x0

    const-wide/16 v18, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const-wide/16 v22, 0x0

    const/16 v24, 0x0

    const-wide/16 v25, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v30, 0x0

    const/16 v31, 0x0

    const/16 v32, 0x0

    const/16 v34, 0x0

    move-object/from16 v33, v2

    invoke-static/range {v14 .. v36}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
