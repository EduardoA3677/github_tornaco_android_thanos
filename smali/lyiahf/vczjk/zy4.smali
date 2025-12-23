.class public final Llyiahf/vczjk/zy4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/kna;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/kna;

.field public final OooO0O0:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kna;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zy4;->OooO00o:Llyiahf/vczjk/kna;

    iput p2, p0, Llyiahf/vczjk/zy4;->OooO0O0:I

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/f62;)I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/zy4;->OooO0O0:I

    and-int/lit8 v0, v0, 0x20

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/zy4;->OooO00o:Llyiahf/vczjk/kna;

    invoke-interface {v0, p1}, Llyiahf/vczjk/kna;->OooO00o(Llyiahf/vczjk/f62;)I

    move-result p1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I
    .locals 2

    sget-object v0, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    if-ne p2, v0, :cond_0

    const/16 v0, 0x8

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    iget v1, p0, Llyiahf/vczjk/zy4;->OooO0O0:I

    and-int/2addr v0, v1

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/zy4;->OooO00o:Llyiahf/vczjk/kna;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/kna;->OooO0O0(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I

    move-result p1

    return p1

    :cond_1
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/nf5;)I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/zy4;->OooO0O0:I

    and-int/lit8 v0, v0, 0x10

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/zy4;->OooO00o:Llyiahf/vczjk/kna;

    invoke-interface {v0, p1}, Llyiahf/vczjk/kna;->OooO0OO(Llyiahf/vczjk/nf5;)I

    move-result p1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I
    .locals 2

    sget-object v0, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    if-ne p2, v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x1

    :goto_0
    iget v1, p0, Llyiahf/vczjk/zy4;->OooO0O0:I

    and-int/2addr v0, v1

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/zy4;->OooO00o:Llyiahf/vczjk/kna;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/kna;->OooO0Oo(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I

    move-result p1

    return p1

    :cond_1
    const/4 p1, 0x0

    return p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Llyiahf/vczjk/zy4;

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Llyiahf/vczjk/zy4;

    iget-object v1, p1, Llyiahf/vczjk/zy4;->OooO00o:Llyiahf/vczjk/kna;

    iget-object v3, p0, Llyiahf/vczjk/zy4;->OooO00o:Llyiahf/vczjk/kna;

    invoke-static {v3, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    iget p1, p1, Llyiahf/vczjk/zy4;->OooO0O0:I

    iget v1, p0, Llyiahf/vczjk/zy4;->OooO0O0:I

    if-ne v1, p1, :cond_2

    return v0

    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/zy4;->OooO00o:Llyiahf/vczjk/kna;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    iget v1, p0, Llyiahf/vczjk/zy4;->OooO0O0:I

    invoke-static {v1}, Ljava/lang/Integer;->hashCode(I)I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/zy4;->OooO00o:Llyiahf/vczjk/kna;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " only "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "WindowInsetsSides("

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    iget v3, p0, Llyiahf/vczjk/zy4;->OooO0O0:I

    sget v4, Llyiahf/vczjk/rd3;->OooO0o:I

    and-int v5, v3, v4

    if-ne v5, v4, :cond_0

    const-string v4, "Start"

    invoke-static {v2, v4}, Llyiahf/vczjk/rd3;->OooOooO(Ljava/lang/StringBuilder;Ljava/lang/String;)V

    :cond_0
    sget v4, Llyiahf/vczjk/rd3;->OooO0oo:I

    and-int v5, v3, v4

    if-ne v5, v4, :cond_1

    const-string v4, "Left"

    invoke-static {v2, v4}, Llyiahf/vczjk/rd3;->OooOooO(Ljava/lang/StringBuilder;Ljava/lang/String;)V

    :cond_1
    and-int/lit8 v4, v3, 0x10

    const/16 v5, 0x10

    if-ne v4, v5, :cond_2

    const-string v4, "Top"

    invoke-static {v2, v4}, Llyiahf/vczjk/rd3;->OooOooO(Ljava/lang/StringBuilder;Ljava/lang/String;)V

    :cond_2
    sget v4, Llyiahf/vczjk/rd3;->OooO0oO:I

    and-int v5, v3, v4

    if-ne v5, v4, :cond_3

    const-string v4, "End"

    invoke-static {v2, v4}, Llyiahf/vczjk/rd3;->OooOooO(Ljava/lang/StringBuilder;Ljava/lang/String;)V

    :cond_3
    sget v4, Llyiahf/vczjk/rd3;->OooO:I

    and-int v5, v3, v4

    if-ne v5, v4, :cond_4

    const-string v4, "Right"

    invoke-static {v2, v4}, Llyiahf/vczjk/rd3;->OooOooO(Ljava/lang/StringBuilder;Ljava/lang/String;)V

    :cond_4
    const/16 v4, 0x20

    and-int/2addr v3, v4

    if-ne v3, v4, :cond_5

    const-string v3, "Bottom"

    invoke-static {v2, v3}, Llyiahf/vczjk/rd3;->OooOooO(Ljava/lang/StringBuilder;Ljava/lang/String;)V

    :cond_5
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    const-string v3, "toString(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v2, 0x29

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
