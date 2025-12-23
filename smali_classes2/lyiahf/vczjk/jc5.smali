.class public final Llyiahf/vczjk/jc5;
.super Llyiahf/vczjk/x11;
.source "SourceFile"


# instance fields
.field public OooO:Z

.field public OooO0oo:Ljava/util/ArrayList;


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/y16;
    .locals 1

    sget-object v0, Llyiahf/vczjk/y16;->OooOOOO:Llyiahf/vczjk/y16;

    return-object v0
.end method

.method public final OooO0OO()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/jc5;->OooO0oo:Ljava/util/ArrayList;

    return-object v0
.end method

.method public final OooO0Oo(Ljava/lang/Class;Ljava/lang/Class;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/jc5;->OooO0oo:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/f26;

    iget-object v2, v1, Llyiahf/vczjk/f26;->OooO0O0:Llyiahf/vczjk/i16;

    invoke-virtual {v2, p2}, Llyiahf/vczjk/i16;->OooO0O0(Ljava/lang/Class;)V

    iget-object v1, v1, Llyiahf/vczjk/f26;->OooO00o:Llyiahf/vczjk/i16;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/i16;->OooO0O0(Ljava/lang/Class;)V

    goto :goto_0

    :cond_0
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/jc5;->OooO0oo:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/f26;

    const-string v3, "{ key="

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v3, v2, Llyiahf/vczjk/f26;->OooO00o:Llyiahf/vczjk/i16;

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v3, "; value="

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v3, v2, Llyiahf/vczjk/f26;->OooO0O0:Llyiahf/vczjk/i16;

    instance-of v4, v3, Llyiahf/vczjk/x11;

    if-eqz v4, :cond_0

    invoke-static {v3}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    move-result v2

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    goto :goto_1

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/f26;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :goto_1
    const-string v2, " }"

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "<"

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const-class v2, Llyiahf/vczjk/jc5;

    const-string v3, " (tag="

    invoke-static {v2, v1, v3}, Llyiahf/vczjk/ii5;->OooOOoo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)V

    iget-object v2, p0, Llyiahf/vczjk/i16;->OooO00o:Llyiahf/vczjk/ye9;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, ", values="

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, ")>"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
