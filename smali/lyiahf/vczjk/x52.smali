.class public final Llyiahf/vczjk/x52;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/vk2;


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/zk2;)V
    .locals 3

    iget-object v0, p1, Llyiahf/vczjk/zk2;->OooOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/n11;

    invoke-virtual {v0}, Llyiahf/vczjk/n11;->OooOOO()I

    move-result v0

    const-string v1, ""

    const/4 v2, 0x0

    invoke-virtual {p1, v2, v0, v1}, Llyiahf/vczjk/zk2;->OooO(IILjava/lang/String;)V

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 0

    instance-of p1, p1, Llyiahf/vczjk/x52;

    return p1
.end method

.method public final hashCode()I
    .locals 2

    sget-object v0, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    const-class v1, Llyiahf/vczjk/x52;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/gf4;->hashCode()I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "DeleteAllCommand()"

    return-object v0
.end method
