.class public final Llyiahf/vczjk/hy6;
.super Llyiahf/vczjk/vo3;
.source "SourceFile"


# virtual methods
.method public final bridge synthetic OooOO0O()Ljava/lang/Object;
    .locals 1

    const-string v0, "androidx.compose.ui.input.pointer.PointerHoverIcon"

    return-object v0
.end method

.method public final o00000Oo(Llyiahf/vczjk/iy6;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/ch1;->OooOo0:Llyiahf/vczjk/l39;

    invoke-static {p0, v0}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/jy6;

    if-eqz v0, :cond_1

    check-cast v0, Llyiahf/vczjk/na;

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/iy6;->OooO00o:Llyiahf/vczjk/wp3;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/u34;->OooOOo0:Llyiahf/vczjk/bf;

    :cond_0
    sget-object v1, Llyiahf/vczjk/qb;->OooO00o:Llyiahf/vczjk/qb;

    iget-object v0, v0, Llyiahf/vczjk/na;->OooO0O0:Llyiahf/vczjk/xa;

    invoke-virtual {v1, v0, p1}, Llyiahf/vczjk/qb;->OooO00o(Landroid/view/View;Llyiahf/vczjk/iy6;)V

    :cond_1
    return-void
.end method

.method public final o0000Ooo(I)Z
    .locals 1

    const/4 v0, 0x3

    if-ne p1, v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x4

    if-ne p1, v0, :cond_1

    :goto_0
    const/4 p1, 0x0

    return p1

    :cond_1
    const/4 p1, 0x1

    return p1
.end method
