.class public interface abstract Llyiahf/vczjk/o73;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/dw7;


# virtual methods
.method public OooO00o(I[I[ILlyiahf/vczjk/nf5;)V
    .locals 7

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/s73;

    invoke-interface {p4}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v5

    iget-object v1, v0, Llyiahf/vczjk/s73;->OooO00o:Llyiahf/vczjk/nx;

    move v3, p1

    move-object v4, p2

    move-object v6, p3

    move-object v2, p4

    invoke-interface/range {v1 .. v6}, Llyiahf/vczjk/nx;->OooO0o0(Llyiahf/vczjk/f62;I[ILlyiahf/vczjk/yn4;[I)V

    return-void
.end method

.method public OooO0O0(IIZI)J
    .locals 1

    sget-object v0, Llyiahf/vczjk/fw7;->OooO00o:Llyiahf/vczjk/hw7;

    const/4 v0, 0x0

    if-nez p3, :cond_0

    invoke-static {p1, p2, v0, p4}, Llyiahf/vczjk/uk1;->OooO00o(IIII)J

    move-result-wide p1

    return-wide p1

    :cond_0
    invoke-static {p1, p2, v0, p4}, Llyiahf/vczjk/vc6;->OooOo0(IIII)J

    move-result-wide p1

    return-wide p1
.end method

.method public OooO0o0(Llyiahf/vczjk/ow6;)I
    .locals 0

    invoke-virtual {p1}, Llyiahf/vczjk/ow6;->Oooooo()I

    move-result p1

    return p1
.end method

.method public OooO0oO(Llyiahf/vczjk/ow6;)I
    .locals 0

    invoke-virtual {p1}, Llyiahf/vczjk/ow6;->OooooOo()I

    move-result p1

    return p1
.end method

.method public OooO0oo([Llyiahf/vczjk/ow6;Llyiahf/vczjk/nf5;I[III[IIII)Llyiahf/vczjk/mf5;
    .locals 11

    sget-object v8, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    new-instance v0, Llyiahf/vczjk/n73;

    move-object v6, p0

    move-object v5, p1

    move v9, p3

    move-object v10, p4

    move/from16 v7, p6

    move-object/from16 v1, p7

    move/from16 v2, p8

    move/from16 v3, p9

    move/from16 v4, p10

    invoke-direct/range {v0 .. v10}, Llyiahf/vczjk/n73;-><init>([IIII[Llyiahf/vczjk/ow6;Llyiahf/vczjk/o73;ILlyiahf/vczjk/yn4;I[I)V

    sget-object p1, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    move/from16 p3, p5

    move/from16 v7, p6

    invoke-interface {p2, p3, v7, p1, v0}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method
