.class public final synthetic Llyiahf/vczjk/f35;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/gi;

.field public final synthetic OooOOO0:Llyiahf/vczjk/gi;

.field public final synthetic OooOOOO:Llyiahf/vczjk/lr5;

.field public final synthetic OooOOOo:Ljava/util/List;

.field public final synthetic OooOOo:F

.field public final synthetic OooOOo0:Llyiahf/vczjk/bq6;

.field public final synthetic OooOOoo:[F

.field public final synthetic OooOo0:Llyiahf/vczjk/qr5;

.field public final synthetic OooOo00:J


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/gi;Llyiahf/vczjk/gi;Llyiahf/vczjk/lr5;Ljava/util/List;Llyiahf/vczjk/bq6;F[FJLlyiahf/vczjk/qr5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/f35;->OooOOO0:Llyiahf/vczjk/gi;

    iput-object p2, p0, Llyiahf/vczjk/f35;->OooOOO:Llyiahf/vczjk/gi;

    iput-object p3, p0, Llyiahf/vczjk/f35;->OooOOOO:Llyiahf/vczjk/lr5;

    iput-object p4, p0, Llyiahf/vczjk/f35;->OooOOOo:Ljava/util/List;

    iput-object p5, p0, Llyiahf/vczjk/f35;->OooOOo0:Llyiahf/vczjk/bq6;

    iput p6, p0, Llyiahf/vczjk/f35;->OooOOo:F

    iput-object p7, p0, Llyiahf/vczjk/f35;->OooOOoo:[F

    iput-wide p8, p0, Llyiahf/vczjk/f35;->OooOo00:J

    iput-object p10, p0, Llyiahf/vczjk/f35;->OooOo0:Llyiahf/vczjk/qr5;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    move-object/from16 v1, p0

    iget-object v0, v1, Llyiahf/vczjk/f35;->OooOOOo:Ljava/util/List;

    iget-object v2, v1, Llyiahf/vczjk/f35;->OooOOo0:Llyiahf/vczjk/bq6;

    iget v3, v1, Llyiahf/vczjk/f35;->OooOOo:F

    iget-object v4, v1, Llyiahf/vczjk/f35;->OooOOoo:[F

    iget-wide v7, v1, Llyiahf/vczjk/f35;->OooOo00:J

    iget-object v5, v1, Llyiahf/vczjk/f35;->OooOo0:Llyiahf/vczjk/qr5;

    move-object/from16 v6, p1

    check-cast v6, Llyiahf/vczjk/mm1;

    iget-object v9, v1, Llyiahf/vczjk/f35;->OooOOO0:Llyiahf/vczjk/gi;

    invoke-virtual {v9}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Number;

    invoke-virtual {v9}, Ljava/lang/Number;->floatValue()F

    move-result v9

    const/16 v10, 0x5a

    int-to-float v10, v10

    mul-float/2addr v10, v9

    iget-object v11, v1, Llyiahf/vczjk/f35;->OooOOOO:Llyiahf/vczjk/lr5;

    check-cast v11, Llyiahf/vczjk/zv8;

    invoke-virtual {v11}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v11

    add-float/2addr v11, v10

    iget-object v10, v1, Llyiahf/vczjk/f35;->OooOOO:Llyiahf/vczjk/gi;

    invoke-virtual {v10}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/lang/Number;

    invoke-virtual {v10}, Ljava/lang/Number;->floatValue()F

    move-result v10

    add-float/2addr v10, v11

    check-cast v6, Llyiahf/vczjk/to4;

    iget-object v11, v6, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v11}, Llyiahf/vczjk/hg2;->o00o0O()J

    move-result-wide v11

    iget-object v13, v6, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    iget-object v14, v13, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    move-object v15, v5

    move-object/from16 p1, v6

    invoke-virtual {v14}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v5

    invoke-virtual {v14}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v16

    invoke-interface/range {v16 .. v16}, Llyiahf/vczjk/eq0;->OooO0oO()V

    :try_start_0
    iget-object v1, v14, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/vz5;

    invoke-virtual {v1, v10, v11, v12}, Llyiahf/vczjk/vz5;->OooOOOo(FJ)V

    move-object v1, v15

    check-cast v1, Llyiahf/vczjk/bw8;

    invoke-virtual {v1}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v1

    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ao5;

    const/4 v1, 0x0

    const/16 v10, 0x78

    invoke-static {v0, v9, v2, v1, v10}, Llyiahf/vczjk/fu6;->OooOoo0(Llyiahf/vczjk/ao5;FLlyiahf/vczjk/bq6;ZI)Llyiahf/vczjk/bq6;

    invoke-interface {v13}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v0

    invoke-static {v4}, Llyiahf/vczjk/ze5;->OooO0Oo([F)V

    const/16 v9, 0x20

    shr-long v9, v0, v9

    long-to-int v9, v9

    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v9

    mul-float/2addr v9, v3

    const-wide v10, 0xffffffffL

    and-long/2addr v10, v0

    long-to-int v10, v10

    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v10

    mul-float/2addr v10, v3

    const/4 v3, 0x4

    invoke-static {v4, v9, v10, v3}, Llyiahf/vczjk/ze5;->OooO0oO([FFFI)V

    check-cast v2, Llyiahf/vczjk/qe;

    invoke-virtual {v2, v4}, Llyiahf/vczjk/qe;->OooOO0O([F)V

    invoke-static {v0, v1}, Llyiahf/vczjk/tn6;->OooOO0O(J)J

    move-result-wide v0

    invoke-virtual {v2}, Llyiahf/vczjk/qe;->OooO0Oo()Llyiahf/vczjk/wj7;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/wj7;->OooO0O0()J

    move-result-wide v3

    invoke-static {v0, v1, v3, v4}, Llyiahf/vczjk/p86;->OooO0o0(JJ)J

    move-result-wide v0

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/qe;->OooOO0o(J)V

    sget-object v10, Llyiahf/vczjk/i03;->OooO00o:Llyiahf/vczjk/i03;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    const/4 v9, 0x0

    const/16 v11, 0x34

    move-wide/from16 v17, v5

    move-object v6, v2

    move-wide/from16 v1, v17

    move-object/from16 v5, p1

    :try_start_1
    invoke-static/range {v5 .. v11}, Llyiahf/vczjk/hg2;->o00Ooo(Llyiahf/vczjk/hg2;Llyiahf/vczjk/bq6;JFLlyiahf/vczjk/ig2;I)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    invoke-static {v14, v1, v2}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :catchall_0
    move-exception v0

    goto :goto_0

    :catchall_1
    move-exception v0

    move-wide v1, v5

    :goto_0
    invoke-static {v14, v1, v2}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    throw v0
.end method
