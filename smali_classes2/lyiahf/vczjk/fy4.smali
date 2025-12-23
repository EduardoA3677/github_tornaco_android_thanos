.class public Llyiahf/vczjk/fy4;
.super Llyiahf/vczjk/dha;
.source "SourceFile"


# instance fields
.field public final OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

.field public OooO0OO:Z

.field public final OooO0Oo:Llyiahf/vczjk/ey4;


# direct methods
.method public constructor <init>()V
    .locals 3

    invoke-direct {p0}, Llyiahf/vczjk/dha;-><init>()V

    new-instance v0, Lgithub/tornaco/android/thanos/core/Logger;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    const-string v2, "-lifecycle"

    invoke-virtual {v1, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    iput-object v0, p0, Llyiahf/vczjk/fy4;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    new-instance v0, Llyiahf/vczjk/ey4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ey4;-><init>(Llyiahf/vczjk/fy4;)V

    iput-object v0, p0, Llyiahf/vczjk/fy4;->OooO0Oo:Llyiahf/vczjk/ey4;

    return-void
.end method


# virtual methods
.method public OooO0o()V
    .locals 1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/fy4;->OooO0OO:Z

    return-void
.end method

.method public final OooO0o0(Llyiahf/vczjk/ky4;)V
    .locals 1

    const-string v0, "lifecycle"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/fy4;->OooO0Oo:Llyiahf/vczjk/ey4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ky4;->OooO00o(Llyiahf/vczjk/ty4;)V

    return-void
.end method

.method public OooO0oO()V
    .locals 1

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/fy4;->OooO0OO:Z

    return-void
.end method
