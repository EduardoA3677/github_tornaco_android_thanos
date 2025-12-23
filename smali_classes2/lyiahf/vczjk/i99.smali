.class public final Llyiahf/vczjk/i99;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/jg5;


# instance fields
.field public final OooO0O0:Llyiahf/vczjk/jg5;

.field public final OooO0OO:Llyiahf/vczjk/i5a;

.field public OooO0Oo:Ljava/util/HashMap;

.field public final OooO0o0:Llyiahf/vczjk/sc9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jg5;Llyiahf/vczjk/i5a;)V
    .locals 1

    const-string v0, "workerScope"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "givenSubstitutor"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i99;->OooO0O0:Llyiahf/vczjk/jg5;

    new-instance p1, Llyiahf/vczjk/e19;

    const/4 v0, 0x1

    invoke-direct {p1, p2, v0}, Llyiahf/vczjk/e19;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    invoke-virtual {p2}, Llyiahf/vczjk/i5a;->OooO0o()Llyiahf/vczjk/g5a;

    move-result-object p1

    const-string p2, "getSubstitution(...)"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/os9;->Ooooo00(Llyiahf/vczjk/g5a;)Llyiahf/vczjk/g5a;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/i5a;

    invoke-direct {p2, p1}, Llyiahf/vczjk/i5a;-><init>(Llyiahf/vczjk/g5a;)V

    iput-object p2, p0, Llyiahf/vczjk/i99;->OooO0OO:Llyiahf/vczjk/i5a;

    new-instance p1, Llyiahf/vczjk/e19;

    const/4 p2, 0x2

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/e19;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/i99;->OooO0o0:Llyiahf/vczjk/sc9;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/v02;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/i99;->OooO0OO:Llyiahf/vczjk/i5a;

    iget-object v1, v0, Llyiahf/vczjk/i5a;->OooO00o:Llyiahf/vczjk/g5a;

    invoke-virtual {v1}, Llyiahf/vczjk/g5a;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_0

    return-object p1

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/i99;->OooO0Oo:Ljava/util/HashMap;

    if-nez v1, :cond_1

    new-instance v1, Ljava/util/HashMap;

    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/i99;->OooO0Oo:Ljava/util/HashMap;

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/i99;->OooO0Oo:Ljava/util/HashMap;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v1, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_4

    instance-of v2, p1, Llyiahf/vczjk/h99;

    if-eqz v2, :cond_3

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/h99;

    invoke-interface {v2, v0}, Llyiahf/vczjk/h99;->OooO0o0(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/x02;

    move-result-object v2

    if-eqz v2, :cond_2

    invoke-virtual {v1, p1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_2
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "We expect that no conflict should happen while substitution is guaranteed to generate invariant projection, but "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, " substitution fails"

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance v0, Ljava/lang/AssertionError;

    invoke-direct {v0, p1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Unknown descriptor in scope: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_4
    :goto_0
    check-cast v2, Llyiahf/vczjk/v02;

    return-object v2
.end method

.method public final OooO00o()Ljava/util/Set;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/i99;->OooO0O0:Llyiahf/vczjk/jg5;

    invoke-interface {v0}, Llyiahf/vczjk/jg5;->OooO00o()Ljava/util/Set;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "location"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/i99;->OooO0O0:Llyiahf/vczjk/jg5;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/mr7;->OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/i99;->OooO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/v02;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gz0;

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooO0OO()Ljava/util/Set;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/i99;->OooO0O0:Llyiahf/vczjk/jg5;

    invoke-interface {v0}, Llyiahf/vczjk/jg5;->OooO0OO()Ljava/util/Set;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/i99;->OooO0O0:Llyiahf/vczjk/jg5;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/jg5;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/i99;->OooO0oo(Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;
    .locals 0

    const-string p2, "kindFilter"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/i99;->OooO0o0:Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    return-object p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/i99;->OooO0O0:Llyiahf/vczjk/jg5;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/jg5;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/i99;->OooO0oo(Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0oO()Ljava/util/Set;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/i99;->OooO0O0:Llyiahf/vczjk/jg5;

    invoke-interface {v0}, Llyiahf/vczjk/jg5;->OooO0oO()Ljava/util/Set;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0oo(Ljava/util/Collection;)Ljava/util/Collection;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/i99;->OooO0OO:Llyiahf/vczjk/i5a;

    iget-object v0, v0, Llyiahf/vczjk/i5a;->OooO00o:Llyiahf/vczjk/g5a;

    invoke-virtual {v0}, Llyiahf/vczjk/g5a;->OooO0o0()Z

    move-result v0

    if-eqz v0, :cond_0

    return-object p1

    :cond_0
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    return-object p1

    :cond_1
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result v0

    new-instance v1, Ljava/util/LinkedHashSet;

    const/4 v2, 0x3

    if-ge v0, v2, :cond_2

    goto :goto_0

    :cond_2
    div-int/lit8 v2, v0, 0x3

    add-int/2addr v2, v0

    add-int/lit8 v2, v2, 0x1

    :goto_0
    invoke-direct {v1, v2}, Ljava/util/LinkedHashSet;-><init>(I)V

    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/v02;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/i99;->OooO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/v02;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_3
    return-object v1
.end method
