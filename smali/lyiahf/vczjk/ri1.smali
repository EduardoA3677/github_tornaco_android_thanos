.class public final Llyiahf/vczjk/ri1;
.super Llyiahf/vczjk/si1;
.source "SourceFile"


# instance fields
.field public final OooO0o:Llyiahf/vczjk/ot7;

.field public final OooO0o0:Llyiahf/vczjk/ot7;

.field public final OooO0oO:[F


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ot7;Llyiahf/vczjk/ot7;)V
    .locals 8

    const/4 v0, 0x3

    const/4 v1, 0x0

    invoke-direct {p0, p2, p1, p2, v1}, Llyiahf/vczjk/si1;-><init>(Llyiahf/vczjk/a31;Llyiahf/vczjk/a31;Llyiahf/vczjk/a31;[F)V

    iput-object p1, p0, Llyiahf/vczjk/ri1;->OooO0o0:Llyiahf/vczjk/ot7;

    iput-object p2, p0, Llyiahf/vczjk/ri1;->OooO0o:Llyiahf/vczjk/ot7;

    iget-object v1, p2, Llyiahf/vczjk/ot7;->OooO0Oo:Llyiahf/vczjk/jma;

    iget-object v2, p1, Llyiahf/vczjk/ot7;->OooO0Oo:Llyiahf/vczjk/jma;

    invoke-static {v2, v1}, Llyiahf/vczjk/yi4;->Oooo0O0(Llyiahf/vczjk/jma;Llyiahf/vczjk/jma;)Z

    move-result v1

    iget-object p1, p1, Llyiahf/vczjk/ot7;->OooO:[F

    iget-object v3, p2, Llyiahf/vczjk/ot7;->OooOO0:[F

    if-eqz v1, :cond_0

    invoke-static {v3, p1}, Llyiahf/vczjk/yi4;->OooooOO([F[F)[F

    move-result-object p1

    goto :goto_0

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/jma;->OooO00o()[F

    move-result-object v1

    iget-object v4, p2, Llyiahf/vczjk/ot7;->OooO0Oo:Llyiahf/vczjk/jma;

    invoke-virtual {v4}, Llyiahf/vczjk/jma;->OooO00o()[F

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/ye5;->OooO0Oo:Llyiahf/vczjk/jma;

    invoke-static {v2, v6}, Llyiahf/vczjk/yi4;->Oooo0O0(Llyiahf/vczjk/jma;Llyiahf/vczjk/jma;)Z

    move-result v2

    sget-object v7, Llyiahf/vczjk/uz5;->OooOOOO:Llyiahf/vczjk/uz5;

    iget-object v7, v7, Llyiahf/vczjk/uz5;->OooOOO:Ljava/lang/Object;

    check-cast v7, [F

    if-nez v2, :cond_1

    new-array v2, v0, [F

    fill-array-data v2, :array_0

    invoke-static {v7, v1, v2}, Llyiahf/vczjk/yi4;->Oooo00o([F[F[F)[F

    move-result-object v1

    invoke-static {v1, p1}, Llyiahf/vczjk/yi4;->OooooOO([F[F)[F

    move-result-object p1

    :cond_1
    invoke-static {v4, v6}, Llyiahf/vczjk/yi4;->Oooo0O0(Llyiahf/vczjk/jma;Llyiahf/vczjk/jma;)Z

    move-result v1

    if-nez v1, :cond_2

    new-array v0, v0, [F

    fill-array-data v0, :array_1

    invoke-static {v7, v5, v0}, Llyiahf/vczjk/yi4;->Oooo00o([F[F[F)[F

    move-result-object v0

    iget-object p2, p2, Llyiahf/vczjk/ot7;->OooO:[F

    invoke-static {v0, p2}, Llyiahf/vczjk/yi4;->OooooOO([F[F)[F

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/yi4;->OoooOoO([F)[F

    move-result-object v3

    :cond_2
    invoke-static {v3, p1}, Llyiahf/vczjk/yi4;->OooooOO([F[F)[F

    move-result-object p1

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/ri1;->OooO0oO:[F

    return-void

    nop

    :array_0
    .array-data 4
        0x3f76d699    # 0.964212f
        0x3f800000    # 1.0f
        0x3f533f85
    .end array-data

    :array_1
    .array-data 4
        0x3f76d699    # 0.964212f
        0x3f800000    # 1.0f
        0x3f533f85
    .end array-data
.end method


# virtual methods
.method public final OooO00o(J)J
    .locals 7

    invoke-static {p1, p2}, Llyiahf/vczjk/n21;->OooO0oo(J)F

    move-result v0

    invoke-static {p1, p2}, Llyiahf/vczjk/n21;->OooO0oO(J)F

    move-result v1

    invoke-static {p1, p2}, Llyiahf/vczjk/n21;->OooO0o0(J)F

    move-result v2

    invoke-static {p1, p2}, Llyiahf/vczjk/n21;->OooO0Oo(J)F

    move-result p1

    iget-object p2, p0, Llyiahf/vczjk/ri1;->OooO0o0:Llyiahf/vczjk/ot7;

    float-to-double v3, v0

    iget-object p2, p2, Llyiahf/vczjk/ot7;->OooOOOo:Llyiahf/vczjk/jt7;

    invoke-virtual {p2, v3, v4}, Llyiahf/vczjk/jt7;->OooO0oo(D)D

    move-result-wide v3

    double-to-float v0, v3

    float-to-double v3, v1

    invoke-virtual {p2, v3, v4}, Llyiahf/vczjk/jt7;->OooO0oo(D)D

    move-result-wide v3

    double-to-float v1, v3

    float-to-double v2, v2

    invoke-virtual {p2, v2, v3}, Llyiahf/vczjk/jt7;->OooO0oo(D)D

    move-result-wide v2

    double-to-float p2, v2

    iget-object v2, p0, Llyiahf/vczjk/ri1;->OooO0oO:[F

    const/4 v3, 0x0

    aget v3, v2, v3

    mul-float/2addr v3, v0

    const/4 v4, 0x3

    aget v4, v2, v4

    mul-float/2addr v4, v1

    add-float/2addr v4, v3

    const/4 v3, 0x6

    aget v3, v2, v3

    mul-float/2addr v3, p2

    add-float/2addr v3, v4

    const/4 v4, 0x1

    aget v4, v2, v4

    mul-float/2addr v4, v0

    const/4 v5, 0x4

    aget v5, v2, v5

    mul-float/2addr v5, v1

    add-float/2addr v5, v4

    const/4 v4, 0x7

    aget v4, v2, v4

    mul-float/2addr v4, p2

    add-float/2addr v4, v5

    const/4 v5, 0x2

    aget v5, v2, v5

    mul-float/2addr v5, v0

    const/4 v0, 0x5

    aget v0, v2, v0

    mul-float/2addr v0, v1

    add-float/2addr v0, v5

    const/16 v1, 0x8

    aget v1, v2, v1

    mul-float/2addr v1, p2

    add-float/2addr v1, v0

    iget-object p2, p0, Llyiahf/vczjk/ri1;->OooO0o:Llyiahf/vczjk/ot7;

    iget-object v0, p2, Llyiahf/vczjk/ot7;->OooOOO0:Llyiahf/vczjk/jt7;

    float-to-double v2, v3

    invoke-virtual {v0, v2, v3}, Llyiahf/vczjk/jt7;->OooO0oo(D)D

    move-result-wide v2

    double-to-float v0, v2

    float-to-double v2, v4

    iget-object v4, p2, Llyiahf/vczjk/ot7;->OooOOO0:Llyiahf/vczjk/jt7;

    invoke-virtual {v4, v2, v3}, Llyiahf/vczjk/jt7;->OooO0oo(D)D

    move-result-wide v2

    double-to-float v2, v2

    float-to-double v5, v1

    invoke-virtual {v4, v5, v6}, Llyiahf/vczjk/jt7;->OooO0oo(D)D

    move-result-wide v3

    double-to-float v1, v3

    invoke-static {v0, v2, v1, p1, p2}, Llyiahf/vczjk/v34;->OooO0O0(FFFFLlyiahf/vczjk/a31;)J

    move-result-wide p1

    return-wide p1
.end method
