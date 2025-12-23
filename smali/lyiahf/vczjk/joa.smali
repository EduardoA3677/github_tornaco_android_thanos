.class public Llyiahf/vczjk/joa;
.super Llyiahf/vczjk/rl6;
.source "SourceFile"


# instance fields
.field public final OooO0OO:Landroid/view/Window;

.field public final OooO0Oo:Llyiahf/vczjk/wg7;


# direct methods
.method public constructor <init>(Landroid/view/Window;Llyiahf/vczjk/wg7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/joa;->OooO0OO:Landroid/view/Window;

    iput-object p2, p0, Llyiahf/vczjk/joa;->OooO0Oo:Llyiahf/vczjk/wg7;

    return-void
.end method


# virtual methods
.method public final OooOo00()V
    .locals 4

    const/4 v0, 0x1

    move v1, v0

    :goto_0
    const/16 v2, 0x200

    if-gt v1, v2, :cond_4

    const/16 v2, 0x8

    and-int v3, v2, v1

    if-nez v3, :cond_0

    goto :goto_1

    :cond_0
    if-eq v1, v0, :cond_3

    const/4 v3, 0x2

    if-eq v1, v3, :cond_2

    if-eq v1, v2, :cond_1

    goto :goto_1

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/joa;->OooO0Oo:Llyiahf/vczjk/wg7;

    iget-object v2, v2, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/gv7;

    invoke-virtual {v2}, Llyiahf/vczjk/gv7;->OooO0O0()V

    goto :goto_1

    :cond_2
    invoke-virtual {p0, v3}, Llyiahf/vczjk/joa;->OooOooo(I)V

    goto :goto_1

    :cond_3
    const/4 v2, 0x4

    invoke-virtual {p0, v2}, Llyiahf/vczjk/joa;->OooOooo(I)V

    :goto_1
    shl-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_4
    return-void
.end method

.method public final OooOoO(Z)V
    .locals 2

    const/16 v0, 0x2000

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/joa;->OooO0OO:Landroid/view/Window;

    const/high16 v1, 0x4000000

    invoke-virtual {p1, v1}, Landroid/view/Window;->clearFlags(I)V

    const/high16 v1, -0x80000000

    invoke-virtual {p1, v1}, Landroid/view/Window;->addFlags(I)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/joa;->OooOooo(I)V

    return-void

    :cond_0
    invoke-virtual {p0, v0}, Llyiahf/vczjk/joa;->Oooo000(I)V

    return-void
.end method

.method public final OooOoOO()V
    .locals 4

    const/4 v0, 0x1

    move v1, v0

    :goto_0
    const/16 v2, 0x200

    if-gt v1, v2, :cond_4

    const/16 v2, 0x8

    and-int v3, v2, v1

    if-nez v3, :cond_0

    goto :goto_1

    :cond_0
    if-eq v1, v0, :cond_3

    const/4 v3, 0x2

    if-eq v1, v3, :cond_2

    if-eq v1, v2, :cond_1

    goto :goto_1

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/joa;->OooO0Oo:Llyiahf/vczjk/wg7;

    iget-object v2, v2, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/gv7;

    invoke-virtual {v2}, Llyiahf/vczjk/gv7;->OooO0OO()V

    goto :goto_1

    :cond_2
    invoke-virtual {p0, v3}, Llyiahf/vczjk/joa;->Oooo000(I)V

    goto :goto_1

    :cond_3
    const/4 v2, 0x4

    invoke-virtual {p0, v2}, Llyiahf/vczjk/joa;->Oooo000(I)V

    iget-object v2, p0, Llyiahf/vczjk/joa;->OooO0OO:Landroid/view/Window;

    const/16 v3, 0x400

    invoke-virtual {v2, v3}, Landroid/view/Window;->clearFlags(I)V

    :goto_1
    shl-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_4
    return-void
.end method

.method public final OooOooo(I)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/joa;->OooO0OO:Landroid/view/Window;

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object v0

    invoke-virtual {v0}, Landroid/view/View;->getSystemUiVisibility()I

    move-result v1

    or-int/2addr p1, v1

    invoke-virtual {v0, p1}, Landroid/view/View;->setSystemUiVisibility(I)V

    return-void
.end method

.method public final Oooo000(I)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/joa;->OooO0OO:Landroid/view/Window;

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object v0

    invoke-virtual {v0}, Landroid/view/View;->getSystemUiVisibility()I

    move-result v1

    not-int p1, p1

    and-int/2addr p1, v1

    invoke-virtual {v0, p1}, Landroid/view/View;->setSystemUiVisibility(I)V

    return-void
.end method
