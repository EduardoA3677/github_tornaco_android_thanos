.class public final Llyiahf/vczjk/r92;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Landroid/content/Context;

.field public OooO0O0:Z

.field public final OooO0OO:Llyiahf/vczjk/jl8;

.field public OooO0Oo:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr1;Landroid/content/Context;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/r92;->OooO00o:Landroid/content/Context;

    new-instance p2, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v0, "DeviceStateLooper"

    invoke-direct {p2, v0}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    const/4 p2, 0x0

    const/4 v0, 0x7

    invoke-static {v0, p2}, Llyiahf/vczjk/zsa;->OooOO0o(ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jl8;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/r92;->OooO0OO:Llyiahf/vczjk/jl8;

    new-instance v0, Llyiahf/vczjk/q92;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/q92;-><init>(Llyiahf/vczjk/r92;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v0}, Llyiahf/vczjk/tp6;->OooOooo(Llyiahf/vczjk/xr1;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    return-void
.end method
