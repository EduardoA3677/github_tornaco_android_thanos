.class public final Llyiahf/vczjk/gt1;
.super Llyiahf/vczjk/hj1;
.source "SourceFile"


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/ft1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ft1;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-boolean v0, p1, Llyiahf/vczjk/wu0;->OooOOO0:Z

    if-nez v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/gt1;->OooOOO0:Llyiahf/vczjk/ft1;

    return-void

    :cond_0
    new-instance p1, Llyiahf/vczjk/s92;

    const/4 v0, 0x0

    const-string v1, "mutable instance"

    invoke-direct {p1, v1, v0}, Llyiahf/vczjk/vr2;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    throw p1
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/String;
    .locals 4

    const-string v0, "{"

    const-string v1, "}"

    iget-object v2, p0, Llyiahf/vczjk/gt1;->OooOOO0:Llyiahf/vczjk/ft1;

    const/4 v3, 0x1

    invoke-virtual {v2, v0, v1, v3}, Llyiahf/vczjk/x13;->OooO0oO(Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/hj1;)I
    .locals 1

    check-cast p1, Llyiahf/vczjk/gt1;

    iget-object p1, p1, Llyiahf/vczjk/gt1;->OooOOO0:Llyiahf/vczjk/ft1;

    iget-object v0, p0, Llyiahf/vczjk/gt1;->OooOOO0:Llyiahf/vczjk/ft1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ft1;->OooO0oo(Llyiahf/vczjk/ft1;)I

    move-result p1

    return p1
.end method

.method public final OooO0o0()Ljava/lang/String;
    .locals 1

    const-string v0, "array"

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/gt1;

    if-nez v0, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    check-cast p1, Llyiahf/vczjk/gt1;

    iget-object p1, p1, Llyiahf/vczjk/gt1;->OooOOO0:Llyiahf/vczjk/ft1;

    iget-object v0, p0, Llyiahf/vczjk/gt1;->OooOOO0:Llyiahf/vczjk/ft1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x13;->equals(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gt1;->OooOOO0:Llyiahf/vczjk/ft1;

    iget-object v0, v0, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    invoke-static {v0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    const-string v0, "array{"

    const-string v1, "}"

    iget-object v2, p0, Llyiahf/vczjk/gt1;->OooOOO0:Llyiahf/vczjk/ft1;

    const/4 v3, 0x0

    invoke-virtual {v2, v0, v1, v3}, Llyiahf/vczjk/x13;->OooO0oO(Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
