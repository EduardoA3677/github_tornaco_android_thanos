.class public final Llyiahf/vczjk/mja;
.super Llyiahf/vczjk/oja;
.source "SourceFile"


# instance fields
.field public final OooO0o:I

.field public final OooO0o0:I


# direct methods
.method public constructor <init>(IIIIII)V
    .locals 0

    invoke-direct {p0, p3, p4, p5, p6}, Llyiahf/vczjk/oja;-><init>(IIII)V

    iput p1, p0, Llyiahf/vczjk/mja;->OooO0o0:I

    iput p2, p0, Llyiahf/vczjk/mja;->OooO0o:I

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Llyiahf/vczjk/mja;

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Llyiahf/vczjk/mja;

    iget v1, p1, Llyiahf/vczjk/mja;->OooO0o0:I

    iget v3, p0, Llyiahf/vczjk/mja;->OooO0o0:I

    if-ne v3, v1, :cond_2

    iget v1, p0, Llyiahf/vczjk/mja;->OooO0o:I

    iget v3, p1, Llyiahf/vczjk/mja;->OooO0o:I

    if-ne v1, v3, :cond_2

    iget v1, p1, Llyiahf/vczjk/oja;->OooO00o:I

    iget v3, p0, Llyiahf/vczjk/oja;->OooO00o:I

    if-ne v3, v1, :cond_2

    iget v1, p1, Llyiahf/vczjk/oja;->OooO0O0:I

    iget v3, p0, Llyiahf/vczjk/oja;->OooO0O0:I

    if-ne v3, v1, :cond_2

    iget v1, p1, Llyiahf/vczjk/oja;->OooO0OO:I

    iget v3, p0, Llyiahf/vczjk/oja;->OooO0OO:I

    if-ne v3, v1, :cond_2

    iget p1, p1, Llyiahf/vczjk/oja;->OooO0Oo:I

    iget v1, p0, Llyiahf/vczjk/oja;->OooO0Oo:I

    if-ne v1, p1, :cond_2

    return v0

    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 2

    invoke-super {p0}, Llyiahf/vczjk/oja;->hashCode()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/mja;->OooO0o0:I

    invoke-static {v1}, Ljava/lang/Integer;->hashCode(I)I

    move-result v1

    add-int/2addr v1, v0

    iget v0, p0, Llyiahf/vczjk/mja;->OooO0o:I

    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

    move-result v0

    add-int/2addr v0, v1

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "ViewportHint.Access(\n            |    pageOffset="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget v1, p0, Llyiahf/vczjk/mja;->OooO0o0:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ",\n            |    indexInPage="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Llyiahf/vczjk/mja;->OooO0o:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ",\n            |    presentedItemsBefore="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Llyiahf/vczjk/oja;->OooO00o:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ",\n            |    presentedItemsAfter="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Llyiahf/vczjk/oja;->OooO0O0:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ",\n            |    originalPageOffsetFirst="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Llyiahf/vczjk/oja;->OooO0OO:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ",\n            |    originalPageOffsetLast="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Llyiahf/vczjk/oja;->OooO0Oo:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ",\n            |)"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/a79;->OooOoO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
