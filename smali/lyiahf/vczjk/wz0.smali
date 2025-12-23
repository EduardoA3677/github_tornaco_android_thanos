.class public Llyiahf/vczjk/wz0;
.super Llyiahf/vczjk/o0000O0O;
.source "SourceFile"


# virtual methods
.method public final o00000oO(Llyiahf/vczjk/oy6;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 6

    new-instance v2, Llyiahf/vczjk/uz0;

    const/4 v0, 0x0

    invoke-direct {v2, p0, v0}, Llyiahf/vczjk/uz0;-><init>(Llyiahf/vczjk/wz0;Llyiahf/vczjk/yo1;)V

    new-instance v3, Llyiahf/vczjk/vz0;

    invoke-direct {v3, p0}, Llyiahf/vczjk/vz0;-><init>(Llyiahf/vczjk/wz0;)V

    sget-object v0, Llyiahf/vczjk/dg9;->OooO00o:Llyiahf/vczjk/df9;

    new-instance v4, Llyiahf/vczjk/o37;

    invoke-direct {v4, p1}, Llyiahf/vczjk/o37;-><init>(Llyiahf/vczjk/f62;)V

    new-instance v0, Llyiahf/vczjk/mf9;

    const/4 v5, 0x0

    move-object v1, p1

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/mf9;-><init>(Llyiahf/vczjk/oy6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, p2}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-ne p1, p2, :cond_0

    goto :goto_0

    :cond_0
    move-object p1, v0

    :goto_0
    if-ne p1, p2, :cond_1

    return-object p1

    :cond_1
    return-object v0
.end method

.method public final o0000oO(Landroid/view/KeyEvent;)V
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/o0000O0O;->Oooo00o:Llyiahf/vczjk/le3;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    return-void
.end method

.method public final o0000oo(Landroid/view/KeyEvent;)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method
