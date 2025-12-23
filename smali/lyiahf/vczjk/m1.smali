.class public final Llyiahf/vczjk/m1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/kna;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ei6;

.field public final OooO0O0:Llyiahf/vczjk/kna;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ei6;Llyiahf/vczjk/kna;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/m1;->OooO00o:Llyiahf/vczjk/ei6;

    iput-object p2, p0, Llyiahf/vczjk/m1;->OooO0O0:Llyiahf/vczjk/kna;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/f62;)I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/m1;->OooO00o:Llyiahf/vczjk/ei6;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ei6;->OooO00o(Llyiahf/vczjk/f62;)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/m1;->OooO0O0:Llyiahf/vczjk/kna;

    invoke-interface {v1, p1}, Llyiahf/vczjk/kna;->OooO00o(Llyiahf/vczjk/f62;)I

    move-result p1

    add-int/2addr p1, v0

    return p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/m1;->OooO00o:Llyiahf/vczjk/ei6;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/ei6;->OooO0O0(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/m1;->OooO0O0:Llyiahf/vczjk/kna;

    invoke-interface {v1, p1, p2}, Llyiahf/vczjk/kna;->OooO0O0(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I

    move-result p1

    add-int/2addr p1, v0

    return p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/nf5;)I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/m1;->OooO00o:Llyiahf/vczjk/ei6;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ei6;->OooO0OO(Llyiahf/vczjk/nf5;)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/m1;->OooO0O0:Llyiahf/vczjk/kna;

    invoke-interface {v1, p1}, Llyiahf/vczjk/kna;->OooO0OO(Llyiahf/vczjk/nf5;)I

    move-result p1

    add-int/2addr p1, v0

    return p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/m1;->OooO00o:Llyiahf/vczjk/ei6;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/ei6;->OooO0Oo(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/m1;->OooO0O0:Llyiahf/vczjk/kna;

    invoke-interface {v1, p1, p2}, Llyiahf/vczjk/kna;->OooO0Oo(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I

    move-result p1

    add-int/2addr p1, v0

    return p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    if-ne p0, p1, :cond_0

    goto :goto_0

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/m1;

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    check-cast p1, Llyiahf/vczjk/m1;

    iget-object v0, p1, Llyiahf/vczjk/m1;->OooO00o:Llyiahf/vczjk/ei6;

    iget-object v1, p0, Llyiahf/vczjk/m1;->OooO00o:Llyiahf/vczjk/ei6;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ei6;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object p1, p1, Llyiahf/vczjk/m1;->OooO0O0:Llyiahf/vczjk/kna;

    iget-object v0, p0, Llyiahf/vczjk/m1;->OooO0O0:Llyiahf/vczjk/kna;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

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
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/m1;->OooO00o:Llyiahf/vczjk/ei6;

    iget-object v0, v0, Llyiahf/vczjk/ei6;->OooO00o:Llyiahf/vczjk/bi6;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/m1;->OooO0O0:Llyiahf/vczjk/kna;

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    mul-int/lit8 v1, v1, 0x1f

    add-int/2addr v1, v0

    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/m1;->OooO00o:Llyiahf/vczjk/ei6;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " + "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/m1;->OooO0O0:Llyiahf/vczjk/kna;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
