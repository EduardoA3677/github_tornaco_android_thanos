.class public abstract Llyiahf/vczjk/o0O00000;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/n3a;


# instance fields
.field public OooO00o:I

.field public final OooO0O0:Llyiahf/vczjk/k45;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/w59;)V
    .locals 3

    const-string v0, "storageManager"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/o0oOOo;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/o0oOOo;-><init>(Ljava/lang/Object;I)V

    new-instance v1, Llyiahf/vczjk/oo000o;

    const/4 v2, 0x5

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    check-cast p1, Llyiahf/vczjk/q45;

    new-instance v2, Llyiahf/vczjk/k45;

    invoke-direct {v2, p1, v0, v1}, Llyiahf/vczjk/k45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/o0oOOo;Llyiahf/vczjk/oo000o;)V

    iput-object v2, p0, Llyiahf/vczjk/o0O00000;->OooO0O0:Llyiahf/vczjk/k45;

    return-void
.end method


# virtual methods
.method public final OooO()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o0O00000;->OooO0O0:Llyiahf/vczjk/k45;

    invoke-virtual {v0}, Llyiahf/vczjk/k45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/o0;

    iget-object v0, v0, Llyiahf/vczjk/o0;->OooO0O0:Ljava/util/List;

    return-object v0
.end method

.method public final bridge synthetic OooO0O0()Ljava/util/Collection;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/o0O00000;->OooO()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public abstract OooO0o()Ljava/util/Collection;
.end method

.method public abstract OooO0oO()Llyiahf/vczjk/uk4;
.end method

.method public abstract OooO0oo()Llyiahf/vczjk/sp3;
.end method

.method public abstract OooOO0(Llyiahf/vczjk/gz0;)Z
.end method

.method public OooOO0o(Ljava/util/List;)Ljava/util/List;
    .locals 0

    return-object p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    if-ne p0, p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/n3a;

    const/4 v1, 0x0

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    move-result v0

    invoke-virtual {p0}, Llyiahf/vczjk/o0O00000;->hashCode()I

    move-result v2

    if-eq v0, v2, :cond_2

    goto :goto_0

    :cond_2
    check-cast p1, Llyiahf/vczjk/n3a;

    invoke-interface {p1}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v2

    if-eq v0, v2, :cond_3

    goto :goto_0

    :cond_3
    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    invoke-interface {p1}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p1

    if-nez p1, :cond_4

    :goto_0
    return v1

    :cond_4
    invoke-static {v0}, Llyiahf/vczjk/uq2;->OooO0o(Llyiahf/vczjk/v02;)Z

    move-result v2

    if-nez v2, :cond_5

    invoke-static {v0}, Llyiahf/vczjk/n72;->OooOOOO(Llyiahf/vczjk/v02;)Z

    move-result v0

    if-nez v0, :cond_5

    invoke-static {p1}, Llyiahf/vczjk/uq2;->OooO0o(Llyiahf/vczjk/v02;)Z

    move-result v0

    if-nez v0, :cond_5

    invoke-static {p1}, Llyiahf/vczjk/n72;->OooOOOO(Llyiahf/vczjk/v02;)Z

    move-result v0

    if-nez v0, :cond_5

    invoke-virtual {p0, p1}, Llyiahf/vczjk/o0O00000;->OooOO0(Llyiahf/vczjk/gz0;)Z

    move-result p1

    return p1

    :cond_5
    return v1
.end method

.method public final hashCode()I
    .locals 2

    iget v0, p0, Llyiahf/vczjk/o0O00000;->OooO00o:I

    if-eqz v0, :cond_0

    return v0

    :cond_0
    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/uq2;->OooO0o(Llyiahf/vczjk/v02;)Z

    move-result v1

    if-nez v1, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/n72;->OooOOOO(Llyiahf/vczjk/v02;)Z

    move-result v1

    if-nez v1, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/n72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    move-result v0

    goto :goto_0

    :cond_1
    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    move-result v0

    :goto_0
    iput v0, p0, Llyiahf/vczjk/o0O00000;->OooO00o:I

    return v0
.end method
