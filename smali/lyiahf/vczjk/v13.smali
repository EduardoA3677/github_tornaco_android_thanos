.class public abstract Llyiahf/vczjk/v13;
.super Llyiahf/vczjk/aw1;
.source "SourceFile"


# virtual methods
.method public final OooO0O0()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/aw1;->OooO00o:Llyiahf/vczjk/od2;

    iget-object v0, v0, Llyiahf/vczjk/od2;->OooO0Oo:Llyiahf/vczjk/u34;

    invoke-virtual {v0}, Llyiahf/vczjk/u34;->OooOO0o()I

    move-result v0

    return v0
.end method

.method public final OooO0oO()Ljava/lang/String;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/aw1;->OooO00o:Llyiahf/vczjk/od2;

    iget-object v1, v0, Llyiahf/vczjk/od2;->OooO0Oo:Llyiahf/vczjk/u34;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0}, Llyiahf/vczjk/od2;->OooO00o()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v1, p0}, Llyiahf/vczjk/u34;->OooOooo(Llyiahf/vczjk/v13;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, p0}, Llyiahf/vczjk/u34;->Oooo000(Llyiahf/vczjk/v13;)Ljava/lang/String;

    move-result-object v1

    const/16 v3, 0x64

    invoke-static {v3, v0}, Llyiahf/vczjk/ix8;->OooOOO0(ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v3

    if-eqz v3, :cond_0

    const/16 v3, 0x20

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_0
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v2

    if-eqz v2, :cond_1

    const-string v2, " // "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final OooOO0(I)Llyiahf/vczjk/aw1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/aw1;->OooO0OO:Llyiahf/vczjk/tn7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/tn7;->OooOO0O(I)Llyiahf/vczjk/tn7;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/aw1;->OooOO0O(Llyiahf/vczjk/tn7;)Llyiahf/vczjk/aw1;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0o(Llyiahf/vczjk/ol0;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/aw1;->OooO00o:Llyiahf/vczjk/od2;

    iget-object v0, v0, Llyiahf/vczjk/od2;->OooO0Oo:Llyiahf/vczjk/u34;

    invoke-virtual {v0, p1, p0}, Llyiahf/vczjk/u34;->o00Ooo(Llyiahf/vczjk/ol0;Llyiahf/vczjk/v13;)V

    return-void
.end method
