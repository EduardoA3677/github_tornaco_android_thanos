.class public final Llyiahf/vczjk/ef1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h68;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/f68;

.field public final OooOOO0:Llyiahf/vczjk/wy4;


# direct methods
.method public constructor <init>()V
    .locals 4

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/wy4;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/wy4;-><init>(Llyiahf/vczjk/uy4;Z)V

    iput-object v0, p0, Llyiahf/vczjk/ef1;->OooOOO0:Llyiahf/vczjk/wy4;

    new-instance v1, Llyiahf/vczjk/g68;

    new-instance v2, Llyiahf/vczjk/ku7;

    const/4 v3, 0x4

    invoke-direct {v2, p0, v3}, Llyiahf/vczjk/ku7;-><init>(Ljava/lang/Object;I)V

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/g68;-><init>(Llyiahf/vczjk/h68;Llyiahf/vczjk/ku7;)V

    new-instance v2, Llyiahf/vczjk/f68;

    invoke-direct {v2, v1}, Llyiahf/vczjk/f68;-><init>(Llyiahf/vczjk/g68;)V

    new-instance v1, Landroid/os/Bundle;

    invoke-direct {v1}, Landroid/os/Bundle;-><init>()V

    invoke-virtual {v2, v1}, Llyiahf/vczjk/f68;->OooO00o(Landroid/os/Bundle;)V

    iput-object v2, p0, Llyiahf/vczjk/ef1;->OooOOO:Llyiahf/vczjk/f68;

    sget-object v1, Llyiahf/vczjk/jy4;->OooOOo0:Llyiahf/vczjk/jy4;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/wy4;->OooO0oo(Llyiahf/vczjk/jy4;)V

    return-void
.end method


# virtual methods
.method public final getLifecycle()Llyiahf/vczjk/ky4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ef1;->OooOOO0:Llyiahf/vczjk/wy4;

    return-object v0
.end method

.method public final getSavedStateRegistry()Llyiahf/vczjk/e68;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ef1;->OooOOO:Llyiahf/vczjk/f68;

    iget-object v0, v0, Llyiahf/vczjk/f68;->OooO0O0:Llyiahf/vczjk/e68;

    return-object v0
.end method
