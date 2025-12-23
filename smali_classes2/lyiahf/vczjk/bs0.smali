.class public final Llyiahf/vczjk/bs0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/jg5;


# instance fields
.field public final OooO0O0:Ljava/lang/String;

.field public final OooO0OO:[Llyiahf/vczjk/jg5;


# direct methods
.method public constructor <init>(Ljava/lang/String;[Llyiahf/vczjk/jg5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bs0;->OooO0O0:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/bs0;->OooO0OO:[Llyiahf/vczjk/jg5;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/util/Set;
    .locals 5

    new-instance v0, Ljava/util/LinkedHashSet;

    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/bs0;->OooO0OO:[Llyiahf/vczjk/jg5;

    array-length v2, v1

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    aget-object v4, v1, v3

    invoke-interface {v4}, Llyiahf/vczjk/jg5;->OooO00o()Ljava/util/Set;

    move-result-object v4

    check-cast v4, Ljava/lang/Iterable;

    invoke-static {v4, v0}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    return-object v0
.end method

.method public final OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;
    .locals 6

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "location"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/bs0;->OooO0OO:[Llyiahf/vczjk/jg5;

    array-length v1, v0

    const/4 v2, 0x0

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v1, :cond_2

    aget-object v4, v0, v3

    invoke-interface {v4, p1, p2}, Llyiahf/vczjk/mr7;->OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;

    move-result-object v4

    if-eqz v4, :cond_1

    instance-of v5, v4, Llyiahf/vczjk/hz0;

    if-eqz v5, :cond_0

    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/yf5;

    invoke-interface {v5}, Llyiahf/vczjk/yf5;->Oooo0()Z

    move-result v5

    if-eqz v5, :cond_0

    if-nez v2, :cond_1

    move-object v2, v4

    goto :goto_1

    :cond_0
    return-object v4

    :cond_1
    :goto_1
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_2
    return-object v2
.end method

.method public final OooO0OO()Ljava/util/Set;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bs0;->OooO0OO:[Llyiahf/vczjk/jg5;

    invoke-static {v0}, Llyiahf/vczjk/sy;->OooooOo([Ljava/lang/Object;)Ljava/lang/Iterable;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/bua;->OooOo0(Ljava/lang/Iterable;)Ljava/util/HashSet;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;
    .locals 5

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/bs0;->OooO0OO:[Llyiahf/vczjk/jg5;

    array-length v1, v0

    if-eqz v1, :cond_3

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-eq v1, v2, :cond_2

    array-length v1, v0

    const/4 v2, 0x0

    :goto_0
    if-ge v3, v1, :cond_0

    aget-object v4, v0, v3

    invoke-interface {v4, p1, p2}, Llyiahf/vczjk/jg5;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/ls6;->OooO0o(Ljava/util/Collection;Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object v2

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    if-nez v2, :cond_1

    sget-object p1, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    return-object p1

    :cond_1
    return-object v2

    :cond_2
    aget-object v0, v0, v3

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/jg5;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object p1

    return-object p1

    :cond_3
    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1
.end method

.method public final OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;
    .locals 5

    const-string v0, "kindFilter"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/bs0;->OooO0OO:[Llyiahf/vczjk/jg5;

    array-length v1, v0

    if-eqz v1, :cond_3

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-eq v1, v2, :cond_2

    array-length v1, v0

    const/4 v2, 0x0

    :goto_0
    if-ge v3, v1, :cond_0

    aget-object v4, v0, v3

    invoke-interface {v4, p1, p2}, Llyiahf/vczjk/mr7;->OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/ls6;->OooO0o(Ljava/util/Collection;Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object v2

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    if-nez v2, :cond_1

    sget-object p1, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    return-object p1

    :cond_1
    return-object v2

    :cond_2
    aget-object v0, v0, v3

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/mr7;->OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;

    move-result-object p1

    return-object p1

    :cond_3
    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;
    .locals 5

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/bs0;->OooO0OO:[Llyiahf/vczjk/jg5;

    array-length v1, v0

    if-eqz v1, :cond_3

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-eq v1, v2, :cond_2

    array-length v1, v0

    const/4 v2, 0x0

    :goto_0
    if-ge v3, v1, :cond_0

    aget-object v4, v0, v3

    invoke-interface {v4, p1, p2}, Llyiahf/vczjk/jg5;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/ls6;->OooO0o(Ljava/util/Collection;Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object v2

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    if-nez v2, :cond_1

    sget-object p1, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    return-object p1

    :cond_1
    return-object v2

    :cond_2
    aget-object v0, v0, v3

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/jg5;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object p1

    return-object p1

    :cond_3
    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1
.end method

.method public final OooO0oO()Ljava/util/Set;
    .locals 5

    new-instance v0, Ljava/util/LinkedHashSet;

    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/bs0;->OooO0OO:[Llyiahf/vczjk/jg5;

    array-length v2, v1

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    aget-object v4, v1, v3

    invoke-interface {v4}, Llyiahf/vczjk/jg5;->OooO0oO()Ljava/util/Set;

    move-result-object v4

    check-cast v4, Ljava/lang/Iterable;

    invoke-static {v4, v0}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bs0;->OooO0O0:Ljava/lang/String;

    return-object v0
.end method
