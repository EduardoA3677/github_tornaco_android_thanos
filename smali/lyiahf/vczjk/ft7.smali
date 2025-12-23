.class public final Llyiahf/vczjk/ft7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f62;


# instance fields
.field public OooOOO:F

.field public OooOOO0:I

.field public OooOOOO:F

.field public OooOOOo:F

.field public OooOOo:F

.field public OooOOo0:F

.field public OooOOoo:F

.field public OooOo:J

.field public OooOo0:J

.field public OooOo00:J

.field public OooOo0O:F

.field public OooOo0o:F

.field public OooOoO:Z

.field public OooOoO0:Llyiahf/vczjk/qj8;

.field public OooOoOO:J

.field public OooOoo:Llyiahf/vczjk/yn4;

.field public OooOoo0:Llyiahf/vczjk/f62;

.field public OooOooO:Llyiahf/vczjk/qqa;


# virtual methods
.method public final OooO00o(F)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOOo:F

    cmpg-float v0, v0, p1

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    or-int/lit8 v0, v0, 0x4

    iput v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    iput p1, p0, Llyiahf/vczjk/ft7;->OooOOOo:F

    return-void
.end method

.method public final OooO0O0()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ft7;->OooOoo0:Llyiahf/vczjk/f62;

    invoke-interface {v0}, Llyiahf/vczjk/f62;->OooO0O0()F

    move-result v0

    return v0
.end method

.method public final OooO0OO(J)V
    .locals 2

    iget-wide v0, p0, Llyiahf/vczjk/ft7;->OooOo00:J

    invoke-static {v0, v1, p1, p2}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result v0

    if-nez v0, :cond_0

    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    or-int/lit8 v0, v0, 0x40

    iput v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    iput-wide p1, p0, Llyiahf/vczjk/ft7;->OooOo00:J

    :cond_0
    return-void
.end method

.method public final OooO0Oo(Z)V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/ft7;->OooOoO:Z

    if-eq v0, p1, :cond_0

    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    or-int/lit16 v0, v0, 0x4000

    iput v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    iput-boolean p1, p0, Llyiahf/vczjk/ft7;->OooOoO:Z

    :cond_0
    return-void
.end method

.method public final OooO0o(F)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ft7;->OooOo0O:F

    cmpg-float v0, v0, p1

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    or-int/lit16 v0, v0, 0x400

    iput v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    iput p1, p0, Llyiahf/vczjk/ft7;->OooOo0O:F

    return-void
.end method

.method public final OooO0oO(F)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOO:F

    cmpg-float v0, v0, p1

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    or-int/lit8 v0, v0, 0x1

    iput v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    iput p1, p0, Llyiahf/vczjk/ft7;->OooOOO:F

    return-void
.end method

.method public final OooOO0O(F)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOOO:F

    cmpg-float v0, v0, p1

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    or-int/lit8 v0, v0, 0x2

    iput v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    iput p1, p0, Llyiahf/vczjk/ft7;->OooOOOO:F

    return-void
.end method

.method public final OooOO0o(F)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOoo:F

    cmpg-float v0, v0, p1

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    or-int/lit8 v0, v0, 0x20

    iput v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    iput p1, p0, Llyiahf/vczjk/ft7;->OooOOoo:F

    return-void
.end method

.method public final OooOOO0(Llyiahf/vczjk/qj8;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ft7;->OooOoO0:Llyiahf/vczjk/qj8;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    or-int/lit16 v0, v0, 0x2000

    iput v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ft7;->OooOoO0:Llyiahf/vczjk/qj8;

    :cond_0
    return-void
.end method

.method public final OooOOOo(J)V
    .locals 2

    iget-wide v0, p0, Llyiahf/vczjk/ft7;->OooOo0:J

    invoke-static {v0, v1, p1, p2}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result v0

    if-nez v0, :cond_0

    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    or-int/lit16 v0, v0, 0x80

    iput v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    iput-wide p1, p0, Llyiahf/vczjk/ft7;->OooOo0:J

    :cond_0
    return-void
.end method

.method public final OooOOo(J)V
    .locals 2

    iget-wide v0, p0, Llyiahf/vczjk/ft7;->OooOo:J

    invoke-static {v0, v1, p1, p2}, Llyiahf/vczjk/ey9;->OooO00o(JJ)Z

    move-result v0

    if-nez v0, :cond_0

    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    or-int/lit16 v0, v0, 0x1000

    iput v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    iput-wide p1, p0, Llyiahf/vczjk/ft7;->OooOo:J

    :cond_0
    return-void
.end method

.method public final OooOo0(F)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOo:F

    cmpg-float v0, v0, p1

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    or-int/lit8 v0, v0, 0x10

    iput v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    iput p1, p0, Llyiahf/vczjk/ft7;->OooOOo:F

    return-void
.end method

.method public final OooOo00(F)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOo0:F

    cmpg-float v0, v0, p1

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    or-int/lit8 v0, v0, 0x8

    iput v0, p0, Llyiahf/vczjk/ft7;->OooOOO0:I

    iput p1, p0, Llyiahf/vczjk/ft7;->OooOOo0:F

    return-void
.end method

.method public final o000oOoO()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ft7;->OooOoo0:Llyiahf/vczjk/f62;

    invoke-interface {v0}, Llyiahf/vczjk/f62;->o000oOoO()F

    move-result v0

    return v0
.end method
