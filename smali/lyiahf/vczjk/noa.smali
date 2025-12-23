.class public final Llyiahf/vczjk/noa;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/rl6;


# direct methods
.method public constructor <init>(Landroid/view/Window;Landroid/view/View;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/wg7;

    invoke-direct {v0, p2}, Llyiahf/vczjk/wg7;-><init>(Landroid/view/View;)V

    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x23

    if-lt p2, v1, :cond_0

    new-instance p2, Llyiahf/vczjk/moa;

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/loa;-><init>(Landroid/view/Window;Llyiahf/vczjk/wg7;)V

    iput-object p2, p0, Llyiahf/vczjk/noa;->OooO00o:Llyiahf/vczjk/rl6;

    return-void

    :cond_0
    const/16 v1, 0x1e

    if-lt p2, v1, :cond_1

    new-instance p2, Llyiahf/vczjk/loa;

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/loa;-><init>(Landroid/view/Window;Llyiahf/vczjk/wg7;)V

    iput-object p2, p0, Llyiahf/vczjk/noa;->OooO00o:Llyiahf/vczjk/rl6;

    return-void

    :cond_1
    const/16 v1, 0x1a

    if-lt p2, v1, :cond_2

    new-instance p2, Llyiahf/vczjk/koa;

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/joa;-><init>(Landroid/view/Window;Llyiahf/vczjk/wg7;)V

    iput-object p2, p0, Llyiahf/vczjk/noa;->OooO00o:Llyiahf/vczjk/rl6;

    return-void

    :cond_2
    new-instance p2, Llyiahf/vczjk/joa;

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/joa;-><init>(Landroid/view/Window;Llyiahf/vczjk/wg7;)V

    iput-object p2, p0, Llyiahf/vczjk/noa;->OooO00o:Llyiahf/vczjk/rl6;

    return-void
.end method

.method public constructor <init>(Landroid/view/WindowInsetsController;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x23

    if-lt v0, v1, :cond_0

    new-instance v0, Llyiahf/vczjk/moa;

    new-instance v1, Llyiahf/vczjk/wg7;

    invoke-direct {v1, p1}, Llyiahf/vczjk/wg7;-><init>(Landroid/view/WindowInsetsController;)V

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/loa;-><init>(Landroid/view/WindowInsetsController;Llyiahf/vczjk/wg7;)V

    iput-object v0, p0, Llyiahf/vczjk/noa;->OooO00o:Llyiahf/vczjk/rl6;

    return-void

    :cond_0
    new-instance v0, Llyiahf/vczjk/loa;

    new-instance v1, Llyiahf/vczjk/wg7;

    invoke-direct {v1, p1}, Llyiahf/vczjk/wg7;-><init>(Landroid/view/WindowInsetsController;)V

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/loa;-><init>(Landroid/view/WindowInsetsController;Llyiahf/vczjk/wg7;)V

    iput-object v0, p0, Llyiahf/vczjk/noa;->OooO00o:Llyiahf/vczjk/rl6;

    return-void
.end method
