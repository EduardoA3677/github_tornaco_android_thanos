.class public Llyiahf/vczjk/loa;
.super Llyiahf/vczjk/rl6;
.source "SourceFile"


# instance fields
.field public final OooO0OO:Landroid/view/WindowInsetsController;

.field public final OooO0Oo:Llyiahf/vczjk/wg7;

.field public final OooO0o0:Landroid/view/Window;


# direct methods
.method public constructor <init>(Landroid/view/Window;Llyiahf/vczjk/wg7;)V
    .locals 1

    invoke-static {p1}, Llyiahf/vczjk/ona;->OooOO0O(Landroid/view/Window;)Landroid/view/WindowInsetsController;

    move-result-object v0

    invoke-direct {p0, v0, p2}, Llyiahf/vczjk/loa;-><init>(Landroid/view/WindowInsetsController;Llyiahf/vczjk/wg7;)V

    iput-object p1, p0, Llyiahf/vczjk/loa;->OooO0o0:Landroid/view/Window;

    return-void
.end method

.method public constructor <init>(Landroid/view/WindowInsetsController;Llyiahf/vczjk/wg7;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/ao8;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/ao8;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/loa;->OooO0OO:Landroid/view/WindowInsetsController;

    iput-object p2, p0, Llyiahf/vczjk/loa;->OooO0Oo:Llyiahf/vczjk/wg7;

    return-void
.end method


# virtual methods
.method public final OooOo00()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/loa;->OooO0Oo:Llyiahf/vczjk/wg7;

    iget-object v0, v0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/gv7;

    invoke-virtual {v0}, Llyiahf/vczjk/gv7;->OooO0O0()V

    iget-object v0, p0, Llyiahf/vczjk/loa;->OooO0OO:Landroid/view/WindowInsetsController;

    const/4 v1, 0x0

    invoke-static {v0, v1}, Llyiahf/vczjk/o0O0OOO0;->OooOoo0(Landroid/view/WindowInsetsController;I)V

    return-void
.end method

.method public final OooOoO(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/loa;->OooO0o0:Landroid/view/Window;

    if-eqz p1, :cond_1

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object p1

    invoke-virtual {p1}, Landroid/view/View;->getSystemUiVisibility()I

    move-result v0

    or-int/lit16 v0, v0, 0x2000

    invoke-virtual {p1, v0}, Landroid/view/View;->setSystemUiVisibility(I)V

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/loa;->OooO0OO:Landroid/view/WindowInsetsController;

    invoke-static {p1}, Llyiahf/vczjk/ona;->OooOOo0(Landroid/view/WindowInsetsController;)V

    return-void

    :cond_1
    if-eqz v0, :cond_2

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object p1

    invoke-virtual {p1}, Landroid/view/View;->getSystemUiVisibility()I

    move-result v0

    and-int/lit16 v0, v0, -0x2001

    invoke-virtual {p1, v0}, Landroid/view/View;->setSystemUiVisibility(I)V

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/loa;->OooO0OO:Landroid/view/WindowInsetsController;

    invoke-static {p1}, Llyiahf/vczjk/ona;->OooOo0O(Landroid/view/WindowInsetsController;)V

    return-void
.end method

.method public final OooOoO0(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/loa;->OooO0o0:Landroid/view/Window;

    if-eqz p1, :cond_1

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object p1

    invoke-virtual {p1}, Landroid/view/View;->getSystemUiVisibility()I

    move-result v0

    or-int/lit8 v0, v0, 0x10

    invoke-virtual {p1, v0}, Landroid/view/View;->setSystemUiVisibility(I)V

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/loa;->OooO0OO:Landroid/view/WindowInsetsController;

    invoke-static {p1}, Llyiahf/vczjk/ona;->OooOoO0(Landroid/view/WindowInsetsController;)V

    return-void

    :cond_1
    if-eqz v0, :cond_2

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object p1

    invoke-virtual {p1}, Landroid/view/View;->getSystemUiVisibility()I

    move-result v0

    and-int/lit8 v0, v0, -0x11

    invoke-virtual {p1, v0}, Landroid/view/View;->setSystemUiVisibility(I)V

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/loa;->OooO0OO:Landroid/view/WindowInsetsController;

    invoke-static {p1}, Llyiahf/vczjk/ona;->OooOoOO(Landroid/view/WindowInsetsController;)V

    return-void
.end method

.method public final OooOoOO()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/loa;->OooO0Oo:Llyiahf/vczjk/wg7;

    iget-object v0, v0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/gv7;

    invoke-virtual {v0}, Llyiahf/vczjk/gv7;->OooO0OO()V

    iget-object v0, p0, Llyiahf/vczjk/loa;->OooO0OO:Landroid/view/WindowInsetsController;

    const/4 v1, 0x0

    invoke-static {v0, v1}, Llyiahf/vczjk/o0O0OOO0;->OooOOo0(Landroid/view/WindowInsetsController;I)V

    return-void
.end method
