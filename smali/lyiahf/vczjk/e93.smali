.class public final Llyiahf/vczjk/e93;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u83;


# virtual methods
.method public final OooO0o(Llyiahf/vczjk/s83;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v0, v0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/c6a;->OooOoO0(Llyiahf/vczjk/jl5;)Landroid/view/View;

    move-result-object v0

    invoke-virtual {v0}, Landroid/view/View;->hasFocusable()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-interface {p1, v0}, Llyiahf/vczjk/s83;->OooO0Oo(Z)V

    return-void
.end method
