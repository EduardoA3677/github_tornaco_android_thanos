.class public Llyiahf/vczjk/qk2;
.super Llyiahf/vczjk/qqa;
.source "SourceFile"


# virtual methods
.method public Oooo(Llyiahf/vczjk/fd9;Llyiahf/vczjk/fd9;Landroid/view/Window;Landroid/view/View;ZZ)V
    .locals 1

    const-string v0, "statusBarStyle"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "navigationBarStyle"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "window"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "view"

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    invoke-static {p3, v0}, Llyiahf/vczjk/dl6;->OooOO0O(Landroid/view/Window;Z)V

    if-eqz p5, :cond_0

    iget p1, p1, Llyiahf/vczjk/fd9;->OooO0O0:I

    goto :goto_0

    :cond_0
    iget p1, p1, Llyiahf/vczjk/fd9;->OooO00o:I

    :goto_0
    invoke-virtual {p3, p1}, Landroid/view/Window;->setStatusBarColor(I)V

    if-eqz p6, :cond_1

    iget p1, p2, Llyiahf/vczjk/fd9;->OooO0O0:I

    goto :goto_1

    :cond_1
    iget p1, p2, Llyiahf/vczjk/fd9;->OooO00o:I

    :goto_1
    invoke-virtual {p3, p1}, Landroid/view/Window;->setNavigationBarColor(I)V

    new-instance p1, Llyiahf/vczjk/wg7;

    invoke-direct {p1, p4}, Llyiahf/vczjk/wg7;-><init>(Landroid/view/View;)V

    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 p4, 0x23

    if-lt p2, p4, :cond_2

    new-instance p2, Llyiahf/vczjk/moa;

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/loa;-><init>(Landroid/view/Window;Llyiahf/vczjk/wg7;)V

    goto :goto_2

    :cond_2
    const/16 p4, 0x1e

    if-lt p2, p4, :cond_3

    new-instance p2, Llyiahf/vczjk/loa;

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/loa;-><init>(Landroid/view/Window;Llyiahf/vczjk/wg7;)V

    goto :goto_2

    :cond_3
    const/16 p4, 0x1a

    if-lt p2, p4, :cond_4

    new-instance p2, Llyiahf/vczjk/koa;

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/joa;-><init>(Landroid/view/Window;Llyiahf/vczjk/wg7;)V

    goto :goto_2

    :cond_4
    new-instance p2, Llyiahf/vczjk/joa;

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/joa;-><init>(Landroid/view/Window;Llyiahf/vczjk/wg7;)V

    :goto_2
    xor-int/lit8 p1, p5, 0x1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/rl6;->OooOoO(Z)V

    xor-int/lit8 p1, p6, 0x1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/rl6;->OooOoO0(Z)V

    return-void
.end method
