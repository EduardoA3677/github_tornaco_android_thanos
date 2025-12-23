.class public final Llyiahf/vczjk/ay5;
.super Llyiahf/vczjk/sg5;
.source "SourceFile"


# virtual methods
.method public final addSubMenu(IIILjava/lang/CharSequence;)Landroid/view/SubMenu;
    .locals 0

    invoke-virtual {p0, p1, p2, p3, p4}, Llyiahf/vczjk/sg5;->OooO00o(IIILjava/lang/CharSequence;)Llyiahf/vczjk/dh5;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/nx5;

    iget-object p3, p0, Llyiahf/vczjk/sg5;->OooO00o:Landroid/content/Context;

    const/4 p4, 0x1

    invoke-direct {p2, p3, p0, p1, p4}, Llyiahf/vczjk/nx5;-><init>(Landroid/content/Context;Llyiahf/vczjk/sg5;Llyiahf/vczjk/dh5;I)V

    iput-object p2, p1, Llyiahf/vczjk/dh5;->OooOOOO:Llyiahf/vczjk/u79;

    iget-object p1, p1, Llyiahf/vczjk/dh5;->OooO0o0:Ljava/lang/CharSequence;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u79;->setHeaderTitle(Ljava/lang/CharSequence;)Landroid/view/SubMenu;

    return-object p2
.end method
