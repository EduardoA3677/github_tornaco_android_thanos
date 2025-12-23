.class public final Llyiahf/vczjk/p79;
.super Llyiahf/vczjk/vo3;
.source "SourceFile"


# virtual methods
.method public final bridge synthetic OooOO0O()Ljava/lang/Object;
    .locals 1

    const-string v0, "androidx.compose.ui.input.pointer.StylusHoverIcon"

    return-object v0
.end method

.method public final o00000Oo(Llyiahf/vczjk/iy6;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/ch1;->OooOo0:Llyiahf/vczjk/l39;

    invoke-static {p0, v0}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/jy6;

    if-eqz v0, :cond_0

    check-cast v0, Llyiahf/vczjk/na;

    iput-object p1, v0, Llyiahf/vczjk/na;->OooO00o:Llyiahf/vczjk/iy6;

    :cond_0
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
    const/4 p1, 0x1

    return p1

    :cond_1
    const/4 p1, 0x0

    return p1
.end method
