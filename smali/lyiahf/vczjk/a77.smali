.class public final Llyiahf/vczjk/a77;
.super Llyiahf/vczjk/vo1;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Llyiahf/vczjk/vo1;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0007\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Llyiahf/vczjk/a77;",
        "Llyiahf/vczjk/vo1;",
        "Llyiahf/vczjk/s67;",
        "ui_prcRelease"
    }
    k = 0x1
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final OooO0oo:Llyiahf/vczjk/sc9;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 3

    new-instance v0, Llyiahf/vczjk/p35;

    const/16 v1, 0x11

    invoke-direct {v0, v1}, Llyiahf/vczjk/p35;-><init>(I)V

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/vo1;-><init>(Landroid/content/Context;Llyiahf/vczjk/le3;)V

    new-instance v0, Llyiahf/vczjk/kt;

    const/4 v1, 0x6

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/a77;->OooO0oo:Llyiahf/vczjk/sc9;

    new-instance v0, Llyiahf/vczjk/kt;

    const/4 v1, 0x7

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/u67;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/u67;-><init>(Llyiahf/vczjk/a77;Llyiahf/vczjk/yo1;)V

    const/4 v2, 0x3

    invoke-static {p1, v1, v1, v0, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method

.method public static final OooO0oo(Llyiahf/vczjk/a77;Landroid/app/ActivityManager$RunningServiceInfo;)Ljava/lang/String;
    .locals 5

    const-string v0, "."

    const-string v1, "getClassName(...)"

    iget-object p0, p0, Llyiahf/vczjk/vo1;->OooO0o:Landroid/content/Context;

    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v2

    iget-object v3, p1, Landroid/app/ActivityManager$RunningServiceInfo;->service:Landroid/content/ComponentName;

    const/4 v4, 0x0

    invoke-virtual {v2, v3, v4}, Landroid/content/pm/PackageManager;->getServiceInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ServiceInfo;

    move-result-object v2

    const-string v3, "getServiceInfo(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget v3, v2, Landroid/content/pm/ServiceInfo;->labelRes:I

    if-nez v3, :cond_1

    iget-object v3, v2, Landroid/content/pm/ServiceInfo;->nonLocalizedLabel:Ljava/lang/CharSequence;

    if-eqz v3, :cond_0

    goto :goto_0

    :cond_0
    iget-object p0, p1, Landroid/app/ActivityManager$RunningServiceInfo;->service:Landroid/content/ComponentName;

    invoke-virtual {p0}, Landroid/content/ComponentName;->getClassName()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, v0, p0}, Llyiahf/vczjk/z69;->Ooooooo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :catchall_0
    move-exception p0

    goto :goto_1

    :cond_1
    :goto_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object p0

    invoke-virtual {v2, p0}, Landroid/content/pm/PackageItemInfo;->loadLabel(Landroid/content/pm/PackageManager;)Ljava/lang/CharSequence;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-object p0

    :goto_1
    invoke-static {p0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v2

    if-nez v2, :cond_2

    goto :goto_2

    :cond_2
    iget-object p0, p1, Landroid/app/ActivityManager$RunningServiceInfo;->service:Landroid/content/ComponentName;

    invoke-virtual {p0}, Landroid/content/ComponentName;->getClassName()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, v0, p0}, Llyiahf/vczjk/z69;->Ooooooo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    :goto_2
    check-cast p0, Ljava/lang/String;

    return-object p0
.end method


# virtual methods
.method public final OooO()V
    .locals 4

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/y67;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/y67;-><init>(Llyiahf/vczjk/a77;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v2, v2, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method
