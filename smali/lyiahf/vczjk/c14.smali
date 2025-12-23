.class public final Llyiahf/vczjk/c14;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/eo4;
.implements Llyiahf/vczjk/nl5;
.implements Llyiahf/vczjk/rl5;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/qs5;

.field public final OooOOO0:Llyiahf/vczjk/kna;

.field public final OooOOOO:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kna;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/c14;->OooOOO0:Llyiahf/vczjk/kna;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/c14;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/c14;->OooOOOO:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/c14;->OooOOO:Llyiahf/vczjk/qs5;

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/kna;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v2

    invoke-interface {v1, p1, v2}, Llyiahf/vczjk/kna;->OooO0O0(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I

    move-result v1

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/kna;

    invoke-interface {v2, p1}, Llyiahf/vczjk/kna;->OooO0OO(Llyiahf/vczjk/nf5;)I

    move-result v2

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/kna;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v4

    invoke-interface {v3, p1, v4}, Llyiahf/vczjk/kna;->OooO0Oo(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I

    move-result v3

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/kna;

    invoke-interface {v0, p1}, Llyiahf/vczjk/kna;->OooO00o(Llyiahf/vczjk/f62;)I

    move-result v0

    add-int/2addr v3, v1

    add-int/2addr v0, v2

    neg-int v4, v3

    neg-int v5, v0

    invoke-static {v4, v5, p3, p4}, Llyiahf/vczjk/uk1;->OooO(IIJ)J

    move-result-wide v4

    invoke-interface {p2, v4, v5}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget v4, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    add-int/2addr v4, v3

    invoke-static {v4, p3, p4}, Llyiahf/vczjk/uk1;->OooO0oO(IJ)I

    move-result v3

    iget v4, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    add-int/2addr v4, v0

    invoke-static {v4, p3, p4}, Llyiahf/vczjk/uk1;->OooO0o(IJ)I

    move-result p3

    new-instance p4, Llyiahf/vczjk/b14;

    invoke-direct {p4, p2, v1, v2}, Llyiahf/vczjk/b14;-><init>(Llyiahf/vczjk/ow6;II)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, v3, p3, p2, p4}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o(Llyiahf/vczjk/sl5;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/uoa;->OooO00o:Llyiahf/vczjk/ie7;

    invoke-interface {p1, v0}, Llyiahf/vczjk/sl5;->OooO0OO(Llyiahf/vczjk/ie7;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/kna;

    new-instance v0, Llyiahf/vczjk/bs2;

    iget-object v1, p0, Llyiahf/vczjk/c14;->OooOOO0:Llyiahf/vczjk/kna;

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/bs2;-><init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/kna;)V

    iget-object v2, p0, Llyiahf/vczjk/c14;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    new-instance v0, Llyiahf/vczjk/x8a;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/x8a;-><init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/kna;)V

    iget-object p1, p0, Llyiahf/vczjk/c14;->OooOOOO:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO0o0()Llyiahf/vczjk/kna;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/c14;->OooOOOO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/kna;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    if-ne p0, p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/c14;

    if-nez v0, :cond_1

    const/4 p1, 0x0

    return p1

    :cond_1
    check-cast p1, Llyiahf/vczjk/c14;

    iget-object p1, p1, Llyiahf/vczjk/c14;->OooOOO0:Llyiahf/vczjk/kna;

    iget-object v0, p0, Llyiahf/vczjk/c14;->OooOOO0:Llyiahf/vczjk/kna;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final getKey()Llyiahf/vczjk/ie7;
    .locals 1

    sget-object v0, Llyiahf/vczjk/uoa;->OooO00o:Llyiahf/vczjk/ie7;

    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/c14;->OooOOO0:Llyiahf/vczjk/kna;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0
.end method
