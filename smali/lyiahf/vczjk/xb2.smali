.class public final Llyiahf/vczjk/xb2;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:Llyiahf/vczjk/zp6;

.field public OooO0O0:Llyiahf/vczjk/we4;

.field public OooO0OO:D

.field public OooO0Oo:J

.field public OooO0o:Llyiahf/vczjk/m22;

.field public OooO0o0:J


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/ci7;
    .locals 12

    iget-object v5, p0, Llyiahf/vczjk/xb2;->OooO00o:Llyiahf/vczjk/zp6;

    if-eqz v5, :cond_1

    iget-wide v0, p0, Llyiahf/vczjk/xb2;->OooO0OO:D

    const-wide/16 v2, 0x0

    cmpl-double v2, v0, v2

    if-lez v2, :cond_0

    :try_start_0
    invoke-virtual {v5}, Llyiahf/vczjk/zp6;->OooO0o()Ljava/io/File;

    move-result-object v2

    invoke-virtual {v2}, Ljava/io/File;->mkdir()Z

    invoke-virtual {v2}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v2

    new-instance v3, Landroid/os/StatFs;

    invoke-direct {v3, v2}, Landroid/os/StatFs;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3}, Landroid/os/StatFs;->getBlockCountLong()J

    move-result-wide v6

    long-to-double v6, v6

    mul-double/2addr v0, v6

    invoke-virtual {v3}, Landroid/os/StatFs;->getBlockSizeLong()J

    move-result-wide v2

    long-to-double v2, v2

    mul-double/2addr v0, v2

    double-to-long v6, v0

    iget-wide v8, p0, Llyiahf/vczjk/xb2;->OooO0Oo:J

    iget-wide v10, p0, Llyiahf/vczjk/xb2;->OooO0o0:J

    invoke-static/range {v6 .. v11}, Llyiahf/vczjk/vt6;->OooOo00(JJJ)J

    move-result-wide v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    iget-wide v0, p0, Llyiahf/vczjk/xb2;->OooO0Oo:J

    :goto_0
    move-wide v1, v0

    goto :goto_1

    :cond_0
    const-wide/16 v0, 0x0

    goto :goto_0

    :goto_1
    new-instance v0, Llyiahf/vczjk/ci7;

    iget-object v4, p0, Llyiahf/vczjk/xb2;->OooO0O0:Llyiahf/vczjk/we4;

    iget-object v3, p0, Llyiahf/vczjk/xb2;->OooO0o:Llyiahf/vczjk/m22;

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/ci7;-><init>(JLlyiahf/vczjk/m22;Llyiahf/vczjk/we4;Llyiahf/vczjk/zp6;)V

    return-object v0

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "directory == null"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
