.class public final Llyiahf/vczjk/kz2;
.super Llyiahf/vczjk/nz2;
.source "SourceFile"


# instance fields
.field public OooO0O0:Z


# virtual methods
.method public final OooO00o()Ljava/io/File;
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/kz2;->OooO0O0:Z

    if-eqz v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/kz2;->OooO0O0:Z

    iget-object v0, p0, Llyiahf/vczjk/nz2;->OooO00o:Ljava/io/File;

    return-object v0
.end method
