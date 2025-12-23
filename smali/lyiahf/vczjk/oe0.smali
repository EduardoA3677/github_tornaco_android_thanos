.class public final Llyiahf/vczjk/oe0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $borderSize:J

.field final synthetic $borderStroke:Llyiahf/vczjk/h79;

.field final synthetic $brush:Llyiahf/vczjk/ri0;

.field final synthetic $cornerRadius:J

.field final synthetic $fillArea:Z

.field final synthetic $halfStroke:F

.field final synthetic $strokeWidth:F

.field final synthetic $topLeft:J


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/gx8;JFFJJLlyiahf/vczjk/h79;)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/oe0;->$fillArea:Z

    iput-object p2, p0, Llyiahf/vczjk/oe0;->$brush:Llyiahf/vczjk/ri0;

    iput-wide p3, p0, Llyiahf/vczjk/oe0;->$cornerRadius:J

    iput p5, p0, Llyiahf/vczjk/oe0;->$halfStroke:F

    iput p6, p0, Llyiahf/vczjk/oe0;->$strokeWidth:F

    iput-wide p7, p0, Llyiahf/vczjk/oe0;->$topLeft:J

    iput-wide p9, p0, Llyiahf/vczjk/oe0;->$borderSize:J

    iput-object p11, p0, Llyiahf/vczjk/oe0;->$borderStroke:Llyiahf/vczjk/h79;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    check-cast p1, Llyiahf/vczjk/mm1;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/to4;

    invoke-virtual {v0}, Llyiahf/vczjk/to4;->OooO00o()V

    iget-boolean p1, p0, Llyiahf/vczjk/oe0;->$fillArea:Z

    if-eqz p1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/oe0;->$brush:Llyiahf/vczjk/ri0;

    iget-wide v6, p0, Llyiahf/vczjk/oe0;->$cornerRadius:J

    const/4 v8, 0x0

    const/16 v9, 0xf6

    const-wide/16 v2, 0x0

    const-wide/16 v4, 0x0

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/hg2;->o00ooo(Llyiahf/vczjk/mm1;Llyiahf/vczjk/ri0;JJJLlyiahf/vczjk/ig2;I)V

    goto/16 :goto_0

    :cond_0
    iget-wide v1, p0, Llyiahf/vczjk/oe0;->$cornerRadius:J

    const/16 p1, 0x20

    shr-long/2addr v1, p1

    long-to-int v1, v1

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    iget v2, p0, Llyiahf/vczjk/oe0;->$halfStroke:F

    cmpg-float v1, v1, v2

    if-gez v1, :cond_1

    iget v4, p0, Llyiahf/vczjk/oe0;->$strokeWidth:F

    iget-object v1, v0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v1}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v2

    shr-long/2addr v2, p1

    long-to-int p1, v2

    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    iget v2, p0, Llyiahf/vczjk/oe0;->$strokeWidth:F

    sub-float v6, p1, v2

    invoke-interface {v1}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v2

    const-wide v7, 0xffffffffL

    and-long/2addr v2, v7

    long-to-int p1, v2

    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    iget v2, p0, Llyiahf/vczjk/oe0;->$strokeWidth:F

    sub-float v7, p1, v2

    move-object p1, v1

    iget-object v1, p0, Llyiahf/vczjk/oe0;->$brush:Llyiahf/vczjk/ri0;

    iget-wide v9, p0, Llyiahf/vczjk/oe0;->$cornerRadius:J

    iget-object p1, p1, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    invoke-virtual {p1}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v11

    invoke-virtual {p1}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/eq0;->OooO0oO()V

    :try_start_0
    iget-object v2, p1, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/vz5;

    iget-object v2, v2, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/uqa;

    invoke-virtual {v2}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v3

    const/4 v8, 0x0

    move v5, v4

    invoke-interface/range {v3 .. v8}, Llyiahf/vczjk/eq0;->OooOOOO(FFFFI)V

    move-wide v6, v9

    const/16 v9, 0xf6

    const-wide/16 v2, 0x0

    const-wide/16 v4, 0x0

    const/4 v8, 0x0

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/hg2;->o00ooo(Llyiahf/vczjk/mm1;Llyiahf/vczjk/ri0;JJJLlyiahf/vczjk/ig2;I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {p1, v11, v12}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    goto :goto_0

    :catchall_0
    move-exception v0

    invoke-static {p1, v11, v12}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    throw v0

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/oe0;->$brush:Llyiahf/vczjk/ri0;

    move p1, v2

    iget-wide v2, p0, Llyiahf/vczjk/oe0;->$topLeft:J

    iget-wide v4, p0, Llyiahf/vczjk/oe0;->$borderSize:J

    iget-wide v6, p0, Llyiahf/vczjk/oe0;->$cornerRadius:J

    invoke-static {p1, v6, v7}, Llyiahf/vczjk/e16;->Oooo0o0(FJ)J

    move-result-wide v6

    iget-object v8, p0, Llyiahf/vczjk/oe0;->$borderStroke:Llyiahf/vczjk/h79;

    const/16 v9, 0xd0

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/hg2;->o00ooo(Llyiahf/vczjk/mm1;Llyiahf/vczjk/ri0;JJJLlyiahf/vczjk/ig2;I)V

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
