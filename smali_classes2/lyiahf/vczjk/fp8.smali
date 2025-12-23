.class public final Llyiahf/vczjk/fp8;
.super Llyiahf/vczjk/dp8;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/n3a;

.field public final OooOOOO:Ljava/util/List;

.field public final OooOOOo:Z

.field public final OooOOo:Llyiahf/vczjk/oe3;

.field public final OooOOo0:Llyiahf/vczjk/jg5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/n3a;Ljava/util/List;ZLlyiahf/vczjk/jg5;Llyiahf/vczjk/oe3;)V
    .locals 1

    const-string v0, "constructor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "arguments"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "memberScope"

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fp8;->OooOOO:Llyiahf/vczjk/n3a;

    iput-object p2, p0, Llyiahf/vczjk/fp8;->OooOOOO:Ljava/util/List;

    iput-boolean p3, p0, Llyiahf/vczjk/fp8;->OooOOOo:Z

    iput-object p4, p0, Llyiahf/vczjk/fp8;->OooOOo0:Llyiahf/vczjk/jg5;

    iput-object p5, p0, Llyiahf/vczjk/fp8;->OooOOo:Llyiahf/vczjk/oe3;

    instance-of p2, p4, Llyiahf/vczjk/oq2;

    if-eqz p2, :cond_1

    instance-of p2, p4, Llyiahf/vczjk/nr9;

    if-eqz p2, :cond_0

    return-void

    :cond_0
    new-instance p2, Ljava/lang/IllegalStateException;

    new-instance p3, Ljava/lang/StringBuilder;

    const-string p5, "SimpleTypeImpl should not be created for error type: "

    invoke-direct {p3, p5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p3, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 p4, 0xa

    invoke-virtual {p3, p4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_1
    return-void
.end method


# virtual methods
.method public final OoooOO0()Llyiahf/vczjk/jg5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fp8;->OooOOo0:Llyiahf/vczjk/jg5;

    return-object v0
.end method

.method public final o000000()Llyiahf/vczjk/n3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fp8;->OooOOO:Llyiahf/vczjk/n3a;

    return-object v0
.end method

.method public final o000000o()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/fp8;->OooOOOo:Z

    return v0
.end method

.method public final o00000O0(Llyiahf/vczjk/al4;)Llyiahf/vczjk/uk4;
    .locals 1

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/fp8;->OooOOo:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dp8;

    if-nez p1, :cond_0

    return-object p0

    :cond_0
    return-object p1
.end method

.method public final o00000Oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/iaa;
    .locals 1

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/fp8;->OooOOo:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dp8;

    if-nez p1, :cond_0

    return-object p0

    :cond_0
    return-object p1
.end method

.method public final o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;
    .locals 1

    const-string v0, "newAttributes"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Llyiahf/vczjk/k10;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/hp8;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/hp8;-><init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/d3a;)V

    return-object v0
.end method

.method public final o0000Ooo(Z)Llyiahf/vczjk/dp8;
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/fp8;->OooOOOo:Z

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    if-eqz p1, :cond_1

    new-instance p1, Llyiahf/vczjk/u26;

    const/4 v0, 0x1

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/u26;-><init>(Llyiahf/vczjk/dp8;I)V

    return-object p1

    :cond_1
    new-instance p1, Llyiahf/vczjk/u26;

    const/4 v0, 0x0

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/u26;-><init>(Llyiahf/vczjk/dp8;I)V

    return-object p1
.end method

.method public final o00ooo()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fp8;->OooOOOO:Ljava/util/List;

    return-object v0
.end method

.method public final o0OOO0o()Llyiahf/vczjk/d3a;
    .locals 1

    sget-object v0, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/d3a;->OooOOOO:Llyiahf/vczjk/d3a;

    return-object v0
.end method
