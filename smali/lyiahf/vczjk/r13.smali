.class public final Llyiahf/vczjk/r13;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/kna;


# instance fields
.field public final OooO00o:F

.field public final OooO0O0:F

.field public final OooO0OO:F

.field public final OooO0Oo:F


# direct methods
.method public constructor <init>(FFFF)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/r13;->OooO00o:F

    iput p2, p0, Llyiahf/vczjk/r13;->OooO0O0:F

    iput p3, p0, Llyiahf/vczjk/r13;->OooO0OO:F

    iput p4, p0, Llyiahf/vczjk/r13;->OooO0Oo:F

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/f62;)I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/r13;->OooO0Oo:F

    invoke-interface {p1, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p1

    return p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I
    .locals 0

    iget p2, p0, Llyiahf/vczjk/r13;->OooO00o:F

    invoke-interface {p1, p2}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p1

    return p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/nf5;)I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/r13;->OooO0O0:F

    invoke-interface {p1, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p1

    return p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I
    .locals 0

    iget p2, p0, Llyiahf/vczjk/r13;->OooO0OO:F

    invoke-interface {p1, p2}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p1

    return p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    if-ne p0, p1, :cond_0

    goto :goto_0

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/r13;

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    check-cast p1, Llyiahf/vczjk/r13;

    iget v0, p1, Llyiahf/vczjk/r13;->OooO00o:F

    iget v1, p0, Llyiahf/vczjk/r13;->OooO00o:F

    invoke-static {v1, v0}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v0

    if-eqz v0, :cond_2

    iget v0, p0, Llyiahf/vczjk/r13;->OooO0O0:F

    iget v1, p1, Llyiahf/vczjk/r13;->OooO0O0:F

    invoke-static {v0, v1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v0

    if-eqz v0, :cond_2

    iget v0, p0, Llyiahf/vczjk/r13;->OooO0OO:F

    iget v1, p1, Llyiahf/vczjk/r13;->OooO0OO:F

    invoke-static {v0, v1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v0

    if-eqz v0, :cond_2

    iget v0, p0, Llyiahf/vczjk/r13;->OooO0Oo:F

    iget p1, p1, Llyiahf/vczjk/r13;->OooO0Oo:F

    invoke-static {v0, p1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result p1

    if-eqz p1, :cond_2

    :goto_0
    const/4 p1, 0x1

    return p1

    :cond_2
    :goto_1
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 3

    iget v0, p0, Llyiahf/vczjk/r13;->OooO00o:F

    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

    move-result v0

    const/16 v1, 0x1f

    mul-int/2addr v0, v1

    iget v2, p0, Llyiahf/vczjk/r13;->OooO0O0:F

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/u81;->OooO0OO(IFI)I

    move-result v0

    iget v2, p0, Llyiahf/vczjk/r13;->OooO0OO:F

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/u81;->OooO0OO(IFI)I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/r13;->OooO0Oo:F

    invoke-static {v1}, Ljava/lang/Float;->hashCode(F)I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Insets(left="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget v1, p0, Llyiahf/vczjk/r13;->OooO00o:F

    const-string v2, ", top="

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/ix8;->OooOOo(FLjava/lang/StringBuilder;Ljava/lang/String;)V

    iget v1, p0, Llyiahf/vczjk/r13;->OooO0O0:F

    const-string v2, ", right="

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/ix8;->OooOOo(FLjava/lang/StringBuilder;Ljava/lang/String;)V

    iget v1, p0, Llyiahf/vczjk/r13;->OooO0OO:F

    const-string v2, ", bottom="

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/ix8;->OooOOo(FLjava/lang/StringBuilder;Ljava/lang/String;)V

    iget v1, p0, Llyiahf/vczjk/r13;->OooO0Oo:F

    invoke-static {v1}, Llyiahf/vczjk/wd2;->OooO0O0(F)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
