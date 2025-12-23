.class public final Llyiahf/vczjk/nx8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOOO:Ljava/util/List;

.field public final synthetic OooOOOo:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOo0:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(Ljava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/nx8;->OooOOO0:Llyiahf/vczjk/oe3;

    iput-boolean p5, p0, Llyiahf/vczjk/nx8;->OooOOO:Z

    iput-object p1, p0, Llyiahf/vczjk/nx8;->OooOOOO:Ljava/util/List;

    iput-object p4, p0, Llyiahf/vczjk/nx8;->OooOOOo:Llyiahf/vczjk/qs5;

    iput-object p3, p0, Llyiahf/vczjk/nx8;->OooOOo0:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/q31;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    const-string v4, "$this$DropdownMenu"

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

    goto/16 :goto_2

    :cond_1
    :goto_0
    new-instance v1, Llyiahf/vczjk/mx8;

    iget-boolean v3, v0, Llyiahf/vczjk/nx8;->OooOOO:Z

    iget-object v4, v0, Llyiahf/vczjk/nx8;->OooOOO0:Llyiahf/vczjk/oe3;

    invoke-direct {v1, v4, v3}, Llyiahf/vczjk/mx8;-><init>(Llyiahf/vczjk/oe3;Z)V

    const v5, -0x49d58212

    invoke-static {v5, v1, v2}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v6

    move-object v12, v2

    check-cast v12, Llyiahf/vczjk/zf1;

    const v1, -0x6815fd56

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v5

    or-int/2addr v2, v5

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    sget-object v15, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    iget-object v7, v0, Llyiahf/vczjk/nx8;->OooOOOo:Llyiahf/vczjk/qs5;

    if-nez v2, :cond_2

    if-ne v5, v15, :cond_3

    :cond_2
    new-instance v5, Llyiahf/vczjk/l3;

    invoke-direct {v5, v4, v3, v7}, Llyiahf/vczjk/l3;-><init>(Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/qs5;)V

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v5, Llyiahf/vczjk/le3;

    const/4 v2, 0x0

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v13, 0x6

    const/16 v14, 0x1fc

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    move-object v3, v7

    move-object v7, v5

    invoke-static/range {v6 .. v14}, Llyiahf/vczjk/fe;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/bh5;Llyiahf/vczjk/di6;Llyiahf/vczjk/rf1;II)V

    iget-object v4, v0, Llyiahf/vczjk/nx8;->OooOOOO:Ljava/util/List;

    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_6

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/vw;

    new-instance v6, Llyiahf/vczjk/pl9;

    const/4 v7, 0x1

    invoke-direct {v6, v5, v7}, Llyiahf/vczjk/pl9;-><init>(Ljava/lang/Object;I)V

    const v7, 0x154e9749

    invoke-static {v7, v6, v12}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v7

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v6, v0, Llyiahf/vczjk/nx8;->OooOOo0:Llyiahf/vczjk/oe3;

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    move-result v9

    invoke-virtual {v12, v9}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v9

    or-int/2addr v8, v9

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v8, :cond_4

    if-ne v9, v15, :cond_5

    :cond_4
    new-instance v9, Llyiahf/vczjk/x5;

    const/16 v8, 0x17

    invoke-direct {v9, v6, v5, v8, v3}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v12, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    move-object v8, v9

    check-cast v8, Llyiahf/vczjk/le3;

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v14, 0x6

    move-object v5, v15

    const/16 v15, 0x1fc

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    move-object v13, v12

    const/4 v12, 0x0

    invoke-static/range {v7 .. v15}, Llyiahf/vczjk/fe;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/bh5;Llyiahf/vczjk/di6;Llyiahf/vczjk/rf1;II)V

    move-object v15, v5

    move-object v12, v13

    goto :goto_1

    :cond_6
    :goto_2
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
