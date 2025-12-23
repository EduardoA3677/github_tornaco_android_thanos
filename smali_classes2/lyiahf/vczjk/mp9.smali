.class public final Llyiahf/vczjk/mp9;
.super Landroid/os/RemoteCallbackList;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/yp9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yp9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mp9;->OooO00o:Llyiahf/vczjk/yp9;

    invoke-direct {p0}, Landroid/os/RemoteCallbackList;-><init>()V

    return-void
.end method


# virtual methods
.method public final onCallbackDied(Landroid/os/IInterface;)V
    .locals 3

    check-cast p1, Lgithub/tornaco/android/thanos/core/IApp;

    invoke-super {p0, p1}, Landroid/os/RemoteCallbackList;->onCallbackDied(Landroid/os/IInterface;)V

    iget-object p1, p0, Llyiahf/vczjk/mp9;->OooO00o:Llyiahf/vczjk/yp9;

    invoke-static {p1}, Llyiahf/vczjk/tp6;->OooOo(Llyiahf/vczjk/sd9;)Llyiahf/vczjk/xr1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/lp9;

    const/4 v2, 0x0

    invoke-direct {v1, p1, p0, v2}, Llyiahf/vczjk/lp9;-><init>(Llyiahf/vczjk/yp9;Llyiahf/vczjk/mp9;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/tp6;->OooOooo(Llyiahf/vczjk/xr1;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    return-void
.end method
