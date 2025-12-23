.class public final Llyiahf/vczjk/ai6;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/go4;


# instance fields
.field public OooOoOO:F

.field public OooOoo:F

.field public OooOoo0:F

.field public OooOooO:F

.field public OooOooo:Z


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 5

    iget v0, p0, Llyiahf/vczjk/ai6;->OooOoOO:F

    invoke-interface {p1, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/ai6;->OooOoo:F

    invoke-interface {p1, v1}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v1

    add-int/2addr v1, v0

    iget v0, p0, Llyiahf/vczjk/ai6;->OooOoo0:F

    invoke-interface {p1, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    iget v2, p0, Llyiahf/vczjk/ai6;->OooOooO:F

    invoke-interface {p1, v2}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v2

    add-int/2addr v2, v0

    neg-int v0, v1

    neg-int v3, v2

    invoke-static {v0, v3, p3, p4}, Llyiahf/vczjk/uk1;->OooO(IIJ)J

    move-result-wide v3

    invoke-interface {p2, v3, v4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget v0, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    add-int/2addr v0, v1

    invoke-static {v0, p3, p4}, Llyiahf/vczjk/uk1;->OooO0oO(IJ)I

    move-result v0

    iget v1, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    add-int/2addr v1, v2

    invoke-static {v1, p3, p4}, Llyiahf/vczjk/uk1;->OooO0o(IJ)I

    move-result p3

    new-instance p4, Llyiahf/vczjk/zh6;

    invoke-direct {p4, p0, p2, p1}, Llyiahf/vczjk/zh6;-><init>(Llyiahf/vczjk/ai6;Llyiahf/vczjk/ow6;Llyiahf/vczjk/nf5;)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, v0, p3, p2, p4}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method
