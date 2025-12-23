.class public final Llyiahf/vczjk/koa;
.super Llyiahf/vczjk/joa;
.source "SourceFile"


# virtual methods
.method public final OooOoO0(Z)V
    .locals 2

    const/16 v0, 0x10

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/joa;->OooO0OO:Landroid/view/Window;

    const/high16 v1, 0x8000000

    invoke-virtual {p1, v1}, Landroid/view/Window;->clearFlags(I)V

    const/high16 v1, -0x80000000

    invoke-virtual {p1, v1}, Landroid/view/Window;->addFlags(I)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/joa;->OooOooo(I)V

    return-void

    :cond_0
    invoke-virtual {p0, v0}, Llyiahf/vczjk/joa;->Oooo000(I)V

    return-void
.end method
