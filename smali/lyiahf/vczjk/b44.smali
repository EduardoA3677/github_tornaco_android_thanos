.class public final Llyiahf/vczjk/b44;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nf5;
.implements Llyiahf/vczjk/o34;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/o34;

.field public final OooOOO0:Llyiahf/vczjk/yn4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/o34;Llyiahf/vczjk/yn4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/b44;->OooOOO0:Llyiahf/vczjk/yn4;

    iput-object p1, p0, Llyiahf/vczjk/b44;->OooOOO:Llyiahf/vczjk/o34;

    return-void
.end method


# virtual methods
.method public final OooO0O0()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b44;->OooOOO:Llyiahf/vczjk/o34;

    invoke-interface {v0}, Llyiahf/vczjk/f62;->OooO0O0()F

    move-result v0

    return v0
.end method

.method public final OooOOO(F)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/b44;->OooOOO:Llyiahf/vczjk/o34;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->OooOOO(F)J

    move-result-wide v0

    return-wide v0
.end method

.method public final OooOOOO(J)J
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b44;->OooOOO:Llyiahf/vczjk/o34;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->OooOOOO(J)J

    move-result-wide p1

    return-wide p1
.end method

.method public final OooOOo0(J)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b44;->OooOOO:Llyiahf/vczjk/o34;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->OooOOo0(J)F

    move-result p1

    return p1
.end method

.method public final OooOo(IILjava/util/Map;Llyiahf/vczjk/ow;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;
    .locals 1

    const/4 p5, 0x0

    if-gez p1, :cond_0

    move p1, p5

    :cond_0
    if-gez p2, :cond_1

    move p2, p5

    :cond_1
    const/high16 p5, -0x1000000

    and-int v0, p1, p5

    if-nez v0, :cond_2

    and-int/2addr p5, p2

    if-nez p5, :cond_2

    goto :goto_0

    :cond_2
    new-instance p5, Ljava/lang/StringBuilder;

    const-string v0, "Size("

    invoke-direct {p5, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p5, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v0, " x "

    invoke-virtual {p5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p5, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v0, ") is out of range. Each dimension must be between 0 and 16777215."

    invoke-virtual {p5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p5

    invoke-static {p5}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :goto_0
    new-instance p5, Llyiahf/vczjk/a44;

    invoke-direct {p5, p1, p2, p3, p4}, Llyiahf/vczjk/a44;-><init>(IILjava/util/Map;Llyiahf/vczjk/ow;)V

    return-object p5
.end method

.method public final OooOooo(F)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/b44;->OooOOO:Llyiahf/vczjk/o34;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->OooOooo(F)J

    move-result-wide v0

    return-wide v0
.end method

.method public final Oooo0OO(I)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b44;->OooOOO:Llyiahf/vczjk/o34;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->Oooo0OO(I)F

    move-result p1

    return p1
.end method

.method public final Oooo0o(F)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b44;->OooOOO:Llyiahf/vczjk/o34;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->Oooo0o(F)F

    move-result p1

    return p1
.end method

.method public final OoooOo0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b44;->OooOOO:Llyiahf/vczjk/o34;

    invoke-interface {v0}, Llyiahf/vczjk/o34;->OoooOo0()Z

    move-result v0

    return v0
.end method

.method public final Ooooo00(F)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b44;->OooOOO:Llyiahf/vczjk/o34;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result p1

    return p1
.end method

.method public final getLayoutDirection()Llyiahf/vczjk/yn4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b44;->OooOOO0:Llyiahf/vczjk/yn4;

    return-object v0
.end method

.method public final o000oOoO()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b44;->OooOOO:Llyiahf/vczjk/o34;

    invoke-interface {v0}, Llyiahf/vczjk/f62;->o000oOoO()F

    move-result v0

    return v0
.end method

.method public final o00Oo0(F)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b44;->OooOOO:Llyiahf/vczjk/o34;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p1

    return p1
.end method

.method public final o00oO0o(J)J
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b44;->OooOOO:Llyiahf/vczjk/o34;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->o00oO0o(J)J

    move-result-wide p1

    return-wide p1
.end method

.method public final o0ooOO0(J)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b44;->OooOOO:Llyiahf/vczjk/o34;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->o0ooOO0(J)F

    move-result p1

    return p1
.end method
