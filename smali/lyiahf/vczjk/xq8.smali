.class public final Llyiahf/vczjk/xq8;
.super Llyiahf/vczjk/jo4;
.source "SourceFile"


# instance fields
.field public OooOoOO:Llyiahf/vczjk/wz8;

.field public OooOoo:J

.field public OooOoo0:J

.field public OooOooO:Z

.field public final OooOooo:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wz8;)V
    .locals 2

    invoke-direct {p0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xq8;->OooOoOO:Llyiahf/vczjk/wz8;

    sget-wide v0, Landroidx/compose/animation/OooO0OO;->OooO00o:J

    iput-wide v0, p0, Llyiahf/vczjk/xq8;->OooOoo0:J

    const/16 p1, 0xf

    const/4 v0, 0x0

    invoke-static {v0, v0, p1}, Llyiahf/vczjk/uk1;->OooO0O0(III)J

    move-result-wide v0

    iput-wide v0, p0, Llyiahf/vczjk/xq8;->OooOoo:J

    const/4 p1, 0x0

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/xq8;->OooOooo:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 20

    move-object/from16 v1, p0

    move-wide/from16 v6, p3

    invoke-interface/range {p1 .. p1}, Llyiahf/vczjk/o34;->OoooOo0()Z

    move-result v0

    const/4 v2, 0x1

    if-eqz v0, :cond_0

    iput-wide v6, v1, Llyiahf/vczjk/xq8;->OooOoo:J

    iput-boolean v2, v1, Llyiahf/vczjk/xq8;->OooOooO:Z

    invoke-interface/range {p2 .. p4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v0

    :goto_0
    move-object v8, v0

    goto :goto_3

    :cond_0
    iget-boolean v0, v1, Llyiahf/vczjk/xq8;->OooOooO:Z

    if-eqz v0, :cond_1

    iget-wide v3, v1, Llyiahf/vczjk/xq8;->OooOoo:J

    :goto_1
    move-object/from16 v0, p2

    goto :goto_2

    :cond_1
    move-wide v3, v6

    goto :goto_1

    :goto_2
    invoke-interface {v0, v3, v4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v0

    goto :goto_0

    :goto_3
    iget v0, v8, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v3, v8, Llyiahf/vczjk/ow6;->OooOOO:I

    int-to-long v4, v0

    const/16 v9, 0x20

    shl-long/2addr v4, v9

    int-to-long v10, v3

    const-wide v12, 0xffffffffL

    and-long/2addr v10, v12

    or-long/2addr v10, v4

    invoke-interface/range {p1 .. p1}, Llyiahf/vczjk/o34;->OoooOo0()Z

    move-result v0

    if-eqz v0, :cond_2

    iput-wide v10, v1, Llyiahf/vczjk/xq8;->OooOoo0:J

    move/from16 p2, v9

    move-wide v0, v10

    move-wide/from16 v16, v0

    goto/16 :goto_9

    :cond_2
    iget-wide v3, v1, Llyiahf/vczjk/xq8;->OooOoo0:J

    sget-wide v14, Landroidx/compose/animation/OooO0OO;->OooO00o:J

    invoke-static {v3, v4, v14, v15}, Llyiahf/vczjk/b24;->OooO00o(JJ)Z

    move-result v0

    if-nez v0, :cond_3

    iget-wide v3, v1, Llyiahf/vczjk/xq8;->OooOoo0:J

    goto :goto_4

    :cond_3
    move-wide v3, v10

    :goto_4
    iget-object v14, v1, Llyiahf/vczjk/xq8;->OooOooo:Llyiahf/vczjk/qs5;

    move-object v0, v14

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/uq8;

    if-eqz v0, :cond_7

    iget-object v5, v0, Llyiahf/vczjk/uq8;->OooO00o:Llyiahf/vczjk/gi;

    invoke-virtual {v5}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Llyiahf/vczjk/b24;

    move/from16 p2, v9

    move-wide/from16 v16, v10

    iget-wide v9, v15, Llyiahf/vczjk/b24;->OooO00o:J

    invoke-static {v3, v4, v9, v10}, Llyiahf/vczjk/b24;->OooO00o(JJ)Z

    move-result v9

    if-nez v9, :cond_4

    iget-object v9, v5, Llyiahf/vczjk/gi;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast v9, Llyiahf/vczjk/fw8;

    invoke-virtual {v9}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Boolean;

    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v9

    if-nez v9, :cond_4

    goto :goto_5

    :cond_4
    const/4 v2, 0x0

    :goto_5
    iget-object v9, v5, Llyiahf/vczjk/gi;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v9, Llyiahf/vczjk/fw8;

    invoke-virtual {v9}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/b24;

    iget-wide v9, v9, Llyiahf/vczjk/b24;->OooO00o:J

    invoke-static {v3, v4, v9, v10}, Llyiahf/vczjk/b24;->OooO00o(JJ)Z

    move-result v9

    if-eqz v9, :cond_6

    if-eqz v2, :cond_5

    goto :goto_6

    :cond_5
    move-object v1, v0

    goto :goto_7

    :cond_6
    :goto_6
    invoke-virtual {v5}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/b24;

    iget-wide v9, v2, Llyiahf/vczjk/b24;->OooO00o:J

    iput-wide v9, v0, Llyiahf/vczjk/uq8;->OooO0O0:J

    invoke-virtual {v1}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v9

    move-object v1, v0

    new-instance v0, Llyiahf/vczjk/vq8;

    const/4 v5, 0x0

    move-wide v2, v3

    move-object/from16 v4, p0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/vq8;-><init>(Llyiahf/vczjk/uq8;JLlyiahf/vczjk/xq8;Llyiahf/vczjk/yo1;)V

    const/4 v2, 0x3

    const/4 v3, 0x0

    invoke-static {v9, v3, v3, v0, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :goto_7
    move-object v0, v1

    goto :goto_8

    :cond_7
    move/from16 p2, v9

    move-wide/from16 v16, v10

    new-instance v0, Llyiahf/vczjk/uq8;

    new-instance v1, Llyiahf/vczjk/gi;

    new-instance v5, Llyiahf/vczjk/b24;

    invoke-direct {v5, v3, v4}, Llyiahf/vczjk/b24;-><init>(J)V

    sget-object v9, Llyiahf/vczjk/gda;->OooO0oo:Llyiahf/vczjk/n1a;

    int-to-long v10, v2

    shl-long v18, v10, p2

    and-long/2addr v10, v12

    or-long v10, v18, v10

    new-instance v2, Llyiahf/vczjk/b24;

    invoke-direct {v2, v10, v11}, Llyiahf/vczjk/b24;-><init>(J)V

    const/16 v10, 0x8

    invoke-direct {v1, v5, v9, v2, v10}, Llyiahf/vczjk/gi;-><init>(Ljava/lang/Object;Llyiahf/vczjk/n1a;Ljava/lang/Object;I)V

    invoke-direct {v0, v1, v3, v4}, Llyiahf/vczjk/uq8;-><init>(Llyiahf/vczjk/gi;J)V

    :goto_8
    check-cast v14, Llyiahf/vczjk/fw8;

    invoke-virtual {v14, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v0, v0, Llyiahf/vczjk/uq8;->OooO00o:Llyiahf/vczjk/gi;

    invoke-virtual {v0}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/b24;

    iget-wide v0, v0, Llyiahf/vczjk/b24;->OooO00o:J

    invoke-static {v6, v7, v0, v1}, Llyiahf/vczjk/uk1;->OooO0Oo(JJ)J

    move-result-wide v0

    :goto_9
    shr-long v2, v0, p2

    long-to-int v4, v2

    and-long/2addr v0, v12

    long-to-int v5, v0

    new-instance v0, Llyiahf/vczjk/wq8;

    move-object/from16 v1, p0

    move-object/from16 v6, p1

    move-object v7, v8

    move-wide/from16 v2, v16

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/wq8;-><init>(Llyiahf/vczjk/xq8;JIILlyiahf/vczjk/nf5;Llyiahf/vczjk/ow6;)V

    sget-object v1, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    move-object/from16 v6, p1

    invoke-interface {v6, v4, v5, v1, v0}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object v0

    return-object v0
.end method

.method public final o000000()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/xq8;->OooOooo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public final o0O0O00()V
    .locals 2

    sget-wide v0, Landroidx/compose/animation/OooO0OO;->OooO00o:J

    iput-wide v0, p0, Llyiahf/vczjk/xq8;->OooOoo0:J

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/xq8;->OooOooO:Z

    return-void
.end method
