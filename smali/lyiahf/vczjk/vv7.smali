.class public final Llyiahf/vczjk/vv7;
.super Llyiahf/vczjk/ng0;
.source "SourceFile"


# virtual methods
.method public final OooOoO0(Llyiahf/vczjk/nk8;FF)V
    .locals 7

    mul-float/2addr p3, p2

    const/high16 p2, 0x42b40000    # 90.0f

    const/4 v0, 0x0

    const/high16 v1, 0x43340000    # 180.0f

    invoke-virtual {p1, v0, p3, v1, p2}, Llyiahf/vczjk/nk8;->OooO0o0(FFFF)V

    const/high16 p2, 0x40000000    # 2.0f

    mul-float v3, p3, p2

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/high16 v5, 0x43340000    # 180.0f

    const/high16 v6, 0x42b40000    # 90.0f

    move v4, v3

    move-object v0, p1

    invoke-virtual/range {v0 .. v6}, Llyiahf/vczjk/nk8;->OooO00o(FFFFFF)V

    return-void
.end method
