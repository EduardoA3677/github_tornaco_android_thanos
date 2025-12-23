.class public abstract Llyiahf/vczjk/se;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final OooO00o()Llyiahf/vczjk/qe;
    .locals 2

    new-instance v0, Llyiahf/vczjk/qe;

    new-instance v1, Landroid/graphics/Path;

    invoke-direct {v1}, Landroid/graphics/Path;-><init>()V

    invoke-direct {v0, v1}, Llyiahf/vczjk/qe;-><init>(Landroid/graphics/Path;)V

    return-object v0
.end method

.method public static final OooO0O0(Ljava/lang/String;)V
    .locals 1

    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
