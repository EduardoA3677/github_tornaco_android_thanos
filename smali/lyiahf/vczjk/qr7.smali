.class public final Llyiahf/vczjk/qr7;
.super Llyiahf/vczjk/e3a;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected _referencedType:Llyiahf/vczjk/x64;


# virtual methods
.method public final Oooo(Ljava/lang/StringBuilder;)Ljava/lang/StringBuilder;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/qr7;->_referencedType:Llyiahf/vczjk/x64;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->Oooo(Ljava/lang/StringBuilder;)Ljava/lang/StringBuilder;

    move-result-object p1

    :cond_0
    return-object p1
.end method

.method public final Oooo0oO()Llyiahf/vczjk/i3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/qr7;->_referencedType:Llyiahf/vczjk/x64;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->Oooo0oO()Llyiahf/vczjk/i3a;

    move-result-object v0

    return-object v0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    return-object v0
.end method

.method public final OoooO00(Ljava/lang/StringBuilder;)Ljava/lang/StringBuilder;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/qr7;->_referencedType:Llyiahf/vczjk/x64;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->Oooo(Ljava/lang/StringBuilder;)Ljava/lang/StringBuilder;

    move-result-object p1

    return-object p1

    :cond_0
    const-string v0, "?"

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    return-object p1
.end method

.method public final OooooOo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 0

    if-ne p1, p0, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final o000oOoO()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/qr7;->_referencedType:Llyiahf/vczjk/x64;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->o000oOoO()Llyiahf/vczjk/x64;

    move-result-object v0

    return-object v0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/e3a;->_superClass:Llyiahf/vczjk/x64;

    return-object v0
.end method

.method public final o00o0O(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public final o00oO0O(Llyiahf/vczjk/e94;)Llyiahf/vczjk/x64;
    .locals 0

    return-object p0
.end method

.method public final o00oO0o(Ljava/lang/Object;)Llyiahf/vczjk/x64;
    .locals 0

    return-object p0
.end method

.method public final o0OOO0o(Ljava/lang/Object;)Llyiahf/vczjk/x64;
    .locals 0

    return-object p0
.end method

.method public final o0ooOOo()Llyiahf/vczjk/x64;
    .locals 0

    return-object p0
.end method

.method public final o0ooOoO(Ljava/lang/Object;)Llyiahf/vczjk/x64;
    .locals 0

    return-object p0
.end method

.method public final oo000o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
    .locals 0

    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    const/16 v0, 0x28

    const-string v1, "[recursive type; "

    invoke-static {v0, v1}, Llyiahf/vczjk/ix8;->OooOOO0(ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/qr7;->_referencedType:Llyiahf/vczjk/x64;

    if-nez v1, :cond_0

    const-string v1, "UNRESOLVED"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :goto_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
