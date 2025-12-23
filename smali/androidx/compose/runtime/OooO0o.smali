.class public abstract Landroidx/compose/runtime/OooO0o;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final OooO(Ljava/lang/Object;Llyiahf/vczjk/gw8;)Llyiahf/vczjk/qs5;
    .locals 1

    new-instance v0, Landroidx/compose/runtime/ParcelableSnapshotMutableState;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/fw8;-><init>(Ljava/lang/Object;Llyiahf/vczjk/gw8;)V

    return-object v0
.end method

.method public static final OooO00o(Llyiahf/vczjk/f43;Ljava/lang/Object;Llyiahf/vczjk/or1;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/qs5;
    .locals 3

    and-int/lit8 p4, p5, 0x2

    if-eqz p4, :cond_0

    sget-object p2, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    :cond_0
    check-cast p3, Llyiahf/vczjk/zf1;

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p4

    invoke-virtual {p3, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p5

    or-int/2addr p4, p5

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p5

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/4 v1, 0x0

    if-nez p4, :cond_1

    if-ne p5, v0, :cond_2

    :cond_1
    new-instance p5, Llyiahf/vczjk/mw8;

    invoke-direct {p5, p2, p0, v1}, Llyiahf/vczjk/mw8;-><init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;)V

    invoke-virtual {p3, p5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2
    check-cast p5, Llyiahf/vczjk/ze3;

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p4

    if-ne p4, v0, :cond_3

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p4

    invoke-virtual {p3, p4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast p4, Llyiahf/vczjk/qs5;

    invoke-virtual {p3, p5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p1

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez p1, :cond_4

    if-ne v2, v0, :cond_5

    :cond_4
    new-instance v2, Llyiahf/vczjk/jw8;

    invoke-direct {v2, p5, p4, v1}, Llyiahf/vczjk/jw8;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    invoke-virtual {p3, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v2, Llyiahf/vczjk/ze3;

    invoke-static {p0, p2, v2, p3}, Llyiahf/vczjk/c6a;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;)V

    return-object p4
.end method

.method public static final OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;
    .locals 6

    sget-object v2, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    invoke-interface {p0}, Llyiahf/vczjk/q29;->getValue()Ljava/lang/Object;

    move-result-object v1

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    move-object v3, p1

    invoke-static/range {v0 .. v5}, Landroidx/compose/runtime/OooO0o;->OooO00o(Llyiahf/vczjk/f43;Ljava/lang/Object;Llyiahf/vczjk/or1;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/qs5;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0OO()Llyiahf/vczjk/ws5;
    .locals 3

    sget-object v0, Llyiahf/vczjk/hw8;->OooO0O0:Llyiahf/vczjk/ed5;

    invoke-virtual {v0}, Llyiahf/vczjk/ed5;->OooOOOo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ws5;

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/ws5;

    const/4 v2, 0x0

    new-array v2, v2, [Llyiahf/vczjk/vf1;

    invoke-direct {v1, v2}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ed5;->Oooo0o0(Ljava/lang/Object;)V

    :cond_0
    return-object v1
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/le3;)Llyiahf/vczjk/w62;
    .locals 2

    sget-object v0, Llyiahf/vczjk/hw8;->OooO00o:Llyiahf/vczjk/ed5;

    new-instance v0, Llyiahf/vczjk/w62;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/w62;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/gw8;)V

    return-object v0
.end method

.method public static final OooO0o(F)Llyiahf/vczjk/lr5;
    .locals 1

    new-instance v0, Landroidx/compose/runtime/ParcelableSnapshotMutableFloatState;

    invoke-direct {v0, p0}, Landroidx/compose/runtime/ParcelableSnapshotMutableFloatState;-><init>(F)V

    return-object v0
.end method

.method public static final OooO0o0(Llyiahf/vczjk/le3;Llyiahf/vczjk/gw8;)Llyiahf/vczjk/w62;
    .locals 1

    sget-object v0, Llyiahf/vczjk/hw8;->OooO00o:Llyiahf/vczjk/ed5;

    new-instance v0, Llyiahf/vczjk/w62;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/w62;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/gw8;)V

    return-object v0
.end method

.method public static final OooO0oO(I)Llyiahf/vczjk/qr5;
    .locals 1

    new-instance v0, Landroidx/compose/runtime/ParcelableSnapshotMutableIntState;

    invoke-direct {v0, p0}, Landroidx/compose/runtime/ParcelableSnapshotMutableIntState;-><init>(I)V

    return-object v0
.end method

.method public static final OooO0oo(J)Llyiahf/vczjk/xv8;
    .locals 1

    new-instance v0, Landroidx/compose/runtime/ParcelableSnapshotMutableLongState;

    invoke-direct {v0, p0, p1}, Landroidx/compose/runtime/ParcelableSnapshotMutableLongState;-><init>(J)V

    return-object v0
.end method

.method public static OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;
    .locals 2

    sget-object v0, Llyiahf/vczjk/rp3;->OooOo0O:Llyiahf/vczjk/rp3;

    new-instance v1, Landroidx/compose/runtime/ParcelableSnapshotMutableState;

    invoke-direct {v1, p0, v0}, Llyiahf/vczjk/fw8;-><init>(Ljava/lang/Object;Llyiahf/vczjk/gw8;)V

    return-object v1
.end method

.method public static final OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;
    .locals 2

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, v1, :cond_0

    invoke-static {p0}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_0
    check-cast v0, Llyiahf/vczjk/qs5;

    invoke-interface {v0, p0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    return-object v0
.end method

.method public static final OooOO0o(Llyiahf/vczjk/le3;)Llyiahf/vczjk/s48;
    .locals 2

    new-instance v0, Llyiahf/vczjk/pw8;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/pw8;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/yo1;)V

    new-instance p0, Llyiahf/vczjk/s48;

    invoke-direct {p0, v0}, Llyiahf/vczjk/s48;-><init>(Llyiahf/vczjk/ze3;)V

    return-object p0
.end method
