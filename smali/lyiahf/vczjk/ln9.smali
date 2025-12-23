.class public final Llyiahf/vczjk/ln9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/qn9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qn9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ln9;->this$0:Llyiahf/vczjk/qn9;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Ljava/util/List;

    iget-object v2, v0, Llyiahf/vczjk/ln9;->this$0:Llyiahf/vczjk/qn9;

    invoke-virtual {v2}, Llyiahf/vczjk/qn9;->o00000OO()Llyiahf/vczjk/fo6;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/ln9;->this$0:Llyiahf/vczjk/qn9;

    iget-object v4, v3, Llyiahf/vczjk/qn9;->OooOoo0:Llyiahf/vczjk/rn9;

    iget-object v3, v3, Llyiahf/vczjk/qn9;->Oooo00o:Llyiahf/vczjk/w21;

    if-eqz v3, :cond_0

    invoke-interface {v3}, Llyiahf/vczjk/w21;->OooO00o()J

    move-result-wide v5

    goto :goto_0

    :cond_0
    sget-wide v5, Llyiahf/vczjk/n21;->OooOO0:J

    :goto_0
    const-wide/16 v16, 0x0

    const v18, 0xfffffe

    const-wide/16 v7, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const-wide/16 v12, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    invoke-static/range {v4 .. v18}, Llyiahf/vczjk/rn9;->OooO0o0(Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/ba3;JLlyiahf/vczjk/vh9;IJI)Llyiahf/vczjk/rn9;

    move-result-object v21

    iget-object v3, v2, Llyiahf/vczjk/fo6;->OooOOOO:Llyiahf/vczjk/yn4;

    const/4 v4, 0x0

    if-nez v3, :cond_1

    :goto_1
    move-object v7, v4

    goto :goto_2

    :cond_1
    iget-object v5, v2, Llyiahf/vczjk/fo6;->OooO:Llyiahf/vczjk/o34;

    if-nez v5, :cond_2

    goto :goto_1

    :cond_2
    new-instance v6, Llyiahf/vczjk/an;

    iget-object v7, v2, Llyiahf/vczjk/fo6;->OooO00o:Ljava/lang/String;

    invoke-direct {v6, v7}, Llyiahf/vczjk/an;-><init>(Ljava/lang/String;)V

    iget-object v7, v2, Llyiahf/vczjk/fo6;->OooOO0:Llyiahf/vczjk/le;

    if-nez v7, :cond_3

    goto :goto_1

    :cond_3
    iget-object v7, v2, Llyiahf/vczjk/fo6;->OooOOO:Llyiahf/vczjk/do6;

    if-nez v7, :cond_4

    goto :goto_1

    :cond_4
    iget-wide v7, v2, Llyiahf/vczjk/fo6;->OooOOOo:J

    const-wide v9, -0x1fffffffdL

    and-long v29, v7, v9

    new-instance v7, Llyiahf/vczjk/mm9;

    new-instance v19, Llyiahf/vczjk/lm9;

    sget-object v22, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    iget v8, v2, Llyiahf/vczjk/fo6;->OooO0o:I

    iget-boolean v9, v2, Llyiahf/vczjk/fo6;->OooO0o0:Z

    iget v10, v2, Llyiahf/vczjk/fo6;->OooO0Oo:I

    iget-object v11, v2, Llyiahf/vczjk/fo6;->OooO0OO:Llyiahf/vczjk/aa3;

    move-object/from16 v27, v3

    move-object/from16 v26, v5

    move-object/from16 v20, v6

    move/from16 v23, v8

    move/from16 v24, v9

    move/from16 v25, v10

    move-object/from16 v28, v11

    invoke-direct/range {v19 .. v30}, Llyiahf/vczjk/lm9;-><init>(Llyiahf/vczjk/an;Llyiahf/vczjk/rn9;Ljava/util/List;IZILlyiahf/vczjk/f62;Llyiahf/vczjk/yn4;Llyiahf/vczjk/aa3;J)V

    move-object/from16 v3, v19

    move-object/from16 v23, v26

    move-object/from16 v24, v28

    new-instance v11, Llyiahf/vczjk/lq5;

    new-instance v19, Llyiahf/vczjk/oq5;

    invoke-direct/range {v19 .. v24}, Llyiahf/vczjk/oq5;-><init>(Llyiahf/vczjk/an;Llyiahf/vczjk/rn9;Ljava/util/List;Llyiahf/vczjk/f62;Llyiahf/vczjk/aa3;)V

    iget v15, v2, Llyiahf/vczjk/fo6;->OooO0o:I

    iget v5, v2, Llyiahf/vczjk/fo6;->OooO0Oo:I

    move/from16 v16, v5

    move-object/from16 v12, v19

    move-wide/from16 v13, v29

    invoke-direct/range {v11 .. v16}, Llyiahf/vczjk/lq5;-><init>(Llyiahf/vczjk/oq5;JII)V

    iget-wide v5, v2, Llyiahf/vczjk/fo6;->OooOO0o:J

    invoke-direct {v7, v3, v11, v5, v6}, Llyiahf/vczjk/mm9;-><init>(Llyiahf/vczjk/lm9;Llyiahf/vczjk/lq5;J)V

    :goto_2
    if-eqz v7, :cond_5

    invoke-interface {v1, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    move-object v4, v7

    :cond_5
    if-eqz v4, :cond_6

    const/4 v1, 0x1

    goto :goto_3

    :cond_6
    const/4 v1, 0x0

    :goto_3
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    return-object v1
.end method
