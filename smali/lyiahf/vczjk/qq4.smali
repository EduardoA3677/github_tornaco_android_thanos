.class public abstract Llyiahf/vczjk/qq4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/vt4;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/bq4;

.field public final OooO0O0:Llyiahf/vczjk/st4;

.field public final OooO0OO:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bq4;Llyiahf/vczjk/st4;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qq4;->OooO00o:Llyiahf/vczjk/bq4;

    iput-object p2, p0, Llyiahf/vczjk/qq4;->OooO0O0:Llyiahf/vczjk/st4;

    iput p3, p0, Llyiahf/vczjk/qq4;->OooO0OO:I

    return-void
.end method


# virtual methods
.method public final OooO00o(IIJI)Llyiahf/vczjk/ut4;
    .locals 7

    iget v6, p0, Llyiahf/vczjk/qq4;->OooO0OO:I

    move-object v0, p0

    move v1, p1

    move v4, p2

    move-wide v2, p3

    move v5, p5

    invoke-virtual/range {v0 .. v6}, Llyiahf/vczjk/qq4;->OooO0O0(IJIII)Llyiahf/vczjk/pq4;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0O0(IJIII)Llyiahf/vczjk/pq4;
    .locals 20

    move-object/from16 v0, p0

    move/from16 v2, p1

    iget-object v1, v0, Llyiahf/vczjk/qq4;->OooO00o:Llyiahf/vczjk/bq4;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/bq4;->OooO0O0(I)Ljava/lang/Object;

    move-result-object v3

    iget-object v1, v1, Llyiahf/vczjk/bq4;->OooO0O0:Llyiahf/vczjk/zp4;

    invoke-virtual {v1, v2}, Landroidx/compose/foundation/lazy/layout/OooO0O0;->OooO00o(I)Ljava/lang/Object;

    move-result-object v14

    iget-object v1, v0, Llyiahf/vczjk/qq4;->OooO0O0:Llyiahf/vczjk/st4;

    check-cast v1, Llyiahf/vczjk/tt4;

    move-wide/from16 v4, p2

    invoke-virtual {v1, v2, v4, v5}, Llyiahf/vczjk/tt4;->OooO00o(IJ)Ljava/util/List;

    move-result-object v11

    invoke-static {v4, v5}, Llyiahf/vczjk/rk1;->OooO0o(J)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-static {v4, v5}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v1

    goto :goto_0

    :cond_0
    invoke-static {v4, v5}, Llyiahf/vczjk/rk1;->OooO0o0(J)Z

    move-result v1

    if-nez v1, :cond_1

    const-string v1, "does not have fixed height"

    invoke-static {v1}, Llyiahf/vczjk/sz3;->OooO00o(Ljava/lang/String;)V

    :cond_1
    invoke-static {v4, v5}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v1

    :goto_0
    move-object v6, v0

    check-cast v6, Llyiahf/vczjk/hq4;

    iget-object v7, v6, Llyiahf/vczjk/hq4;->OooO0Oo:Llyiahf/vczjk/st4;

    check-cast v7, Llyiahf/vczjk/tt4;

    iget-object v7, v7, Llyiahf/vczjk/tt4;->OooOOO:Llyiahf/vczjk/e89;

    invoke-interface {v7}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v8

    iget-object v7, v6, Llyiahf/vczjk/hq4;->OooO0o0:Llyiahf/vczjk/er4;

    iget-object v15, v7, Llyiahf/vczjk/er4;->OooOOO0:Landroidx/compose/foundation/lazy/layout/OooO0OO;

    move v5, v1

    new-instance v1, Llyiahf/vczjk/pq4;

    iget-boolean v7, v6, Llyiahf/vczjk/hq4;->OooO0oO:Z

    iget-wide v12, v6, Llyiahf/vczjk/hq4;->OooOO0:J

    iget-boolean v4, v6, Llyiahf/vczjk/hq4;->OooO0o:Z

    iget v9, v6, Llyiahf/vczjk/hq4;->OooO0oo:I

    iget v10, v6, Llyiahf/vczjk/hq4;->OooO:I

    move-wide/from16 v16, p2

    move/from16 v18, p4

    move/from16 v19, p5

    move/from16 v6, p6

    invoke-direct/range {v1 .. v19}, Llyiahf/vczjk/pq4;-><init>(ILjava/lang/Object;ZIIZLlyiahf/vczjk/yn4;IILjava/util/List;JLjava/lang/Object;Landroidx/compose/foundation/lazy/layout/OooO0OO;JII)V

    return-object v1
.end method
