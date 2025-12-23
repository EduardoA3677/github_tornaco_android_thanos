.class public final Llyiahf/vczjk/ffa;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/eo4;


# instance fields
.field public final OooOOO:I

.field public final OooOOO0:Llyiahf/vczjk/vj9;

.field public final OooOOOO:Llyiahf/vczjk/gy9;

.field public final OooOOOo:Llyiahf/vczjk/le3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vj9;ILlyiahf/vczjk/gy9;Llyiahf/vczjk/le3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ffa;->OooOOO0:Llyiahf/vczjk/vj9;

    iput p2, p0, Llyiahf/vczjk/ffa;->OooOOO:I

    iput-object p3, p0, Llyiahf/vczjk/ffa;->OooOOOO:Llyiahf/vczjk/gy9;

    iput-object p4, p0, Llyiahf/vczjk/ffa;->OooOOOo:Llyiahf/vczjk/le3;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 7

    const/4 v4, 0x0

    const v5, 0x7fffffff

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v6, 0x7

    move-wide v0, p3

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/rk1;->OooO00o(JIIIII)J

    move-result-wide p3

    invoke-interface {p2, p3, p4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p4

    invoke-static {p3, p4}, Ljava/lang/Math;->min(II)I

    move-result p3

    iget p4, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    new-instance v0, Llyiahf/vczjk/efa;

    invoke-direct {v0, p1, p0, p2, p3}, Llyiahf/vczjk/efa;-><init>(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ffa;Llyiahf/vczjk/ow6;I)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p4, p3, p2, v0}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Llyiahf/vczjk/ffa;

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Llyiahf/vczjk/ffa;

    iget-object v1, p1, Llyiahf/vczjk/ffa;->OooOOO0:Llyiahf/vczjk/vj9;

    iget-object v3, p0, Llyiahf/vczjk/ffa;->OooOOO0:Llyiahf/vczjk/vj9;

    invoke-static {v3, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2

    return v2

    :cond_2
    iget v1, p0, Llyiahf/vczjk/ffa;->OooOOO:I

    iget v3, p1, Llyiahf/vczjk/ffa;->OooOOO:I

    if-eq v1, v3, :cond_3

    return v2

    :cond_3
    iget-object v1, p0, Llyiahf/vczjk/ffa;->OooOOOO:Llyiahf/vczjk/gy9;

    iget-object v3, p1, Llyiahf/vczjk/ffa;->OooOOOO:Llyiahf/vczjk/gy9;

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4

    return v2

    :cond_4
    iget-object v1, p0, Llyiahf/vczjk/ffa;->OooOOOo:Llyiahf/vczjk/le3;

    iget-object p1, p1, Llyiahf/vczjk/ffa;->OooOOOo:Llyiahf/vczjk/le3;

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_5

    return v2

    :cond_5
    return v0
.end method

.method public final hashCode()I
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ffa;->OooOOO0:Llyiahf/vczjk/vj9;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    const/16 v1, 0x1f

    mul-int/2addr v0, v1

    iget v2, p0, Llyiahf/vczjk/ffa;->OooOOO:I

    invoke-static {v2, v0, v1}, Llyiahf/vczjk/u81;->OooO0Oo(III)I

    move-result v0

    iget-object v2, p0, Llyiahf/vczjk/ffa;->OooOOOO:Llyiahf/vczjk/gy9;

    invoke-virtual {v2}, Llyiahf/vczjk/gy9;->hashCode()I

    move-result v2

    add-int/2addr v2, v0

    mul-int/2addr v2, v1

    iget-object v0, p0, Llyiahf/vczjk/ffa;->OooOOOo:Llyiahf/vczjk/le3;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    add-int/2addr v0, v2

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "VerticalScrollLayoutModifier(scrollerPosition="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/ffa;->OooOOO0:Llyiahf/vczjk/vj9;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", cursorOffset="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Llyiahf/vczjk/ffa;->OooOOO:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ", transformedText="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/ffa;->OooOOOO:Llyiahf/vczjk/gy9;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", textLayoutResultProvider="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/ffa;->OooOOOo:Llyiahf/vczjk/le3;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
