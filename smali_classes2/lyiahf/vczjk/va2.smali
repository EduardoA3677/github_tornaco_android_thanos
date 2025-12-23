.class public final Llyiahf/vczjk/va2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ps9;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ps9;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/va2;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/va2;->OooOOO:Llyiahf/vczjk/ps9;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/va2;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/vk;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    const-string v3, "$this$AnimatedVisibility"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v10, v2

    check-cast v10, Llyiahf/vczjk/zf1;

    const v1, 0x4c5de2

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v1, v0, Llyiahf/vczjk/va2;->OooOOO:Llyiahf/vczjk/ps9;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_0

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v2, :cond_1

    :cond_0
    new-instance v3, Llyiahf/vczjk/qa2;

    const/4 v2, 0x2

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/qa2;-><init>(Llyiahf/vczjk/ps9;I)V

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/le3;

    const/4 v1, 0x0

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v9, Llyiahf/vczjk/ed1;->OooO0O0:Llyiahf/vczjk/a91;

    const/high16 v11, 0x180000

    const/16 v12, 0x3e

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    invoke-static/range {v4 .. v12}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/iw7;

    move-object/from16 v21, p2

    check-cast v21, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "$this$TextButton"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v2, 0x11

    const/16 v2, 0x10

    if-ne v1, v2, :cond_3

    move-object/from16 v1, v21

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_2

    goto :goto_0

    :cond_2
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_3
    :goto_0
    iget-object v1, v0, Llyiahf/vczjk/va2;->OooOOO:Llyiahf/vczjk/ps9;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-object/from16 v1, v21

    check-cast v1, Llyiahf/vczjk/zf1;

    const v2, 0x46c033ef

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v2, 0x104000a

    invoke-static {v2, v1}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v2

    const/4 v3, 0x0

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

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

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_1
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
