.class public final Llyiahf/vczjk/de4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/jg5;


# static fields
.field public static final synthetic OooO0o:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooO0O0:Llyiahf/vczjk/ld9;

.field public final OooO0OO:Llyiahf/vczjk/tr4;

.field public final OooO0Oo:Llyiahf/vczjk/zr4;

.field public final OooO0o0:Llyiahf/vczjk/o45;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/de4;

    const-string v2, "kotlinScopes"

    const-string v3, "getKotlinScopes()[Lorg/jetbrains/kotlin/resolve/scopes/MemberScope;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const/4 v1, 0x1

    new-array v1, v1, [Llyiahf/vczjk/th4;

    aput-object v0, v1, v4

    sput-object v1, Llyiahf/vczjk/de4;->OooO0o:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/mm7;Llyiahf/vczjk/tr4;)V
    .locals 1

    const-string v0, "packageFragment"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/de4;->OooO0O0:Llyiahf/vczjk/ld9;

    iput-object p3, p0, Llyiahf/vczjk/de4;->OooO0OO:Llyiahf/vczjk/tr4;

    new-instance v0, Llyiahf/vczjk/zr4;

    invoke-direct {v0, p1, p2, p3}, Llyiahf/vczjk/zr4;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/mm7;Llyiahf/vczjk/tr4;)V

    iput-object v0, p0, Llyiahf/vczjk/de4;->OooO0Oo:Llyiahf/vczjk/zr4;

    iget-object p1, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s64;

    iget-object p1, p1, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    new-instance p2, Llyiahf/vczjk/o0oOOo;

    const/16 p3, 0x14

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/o0oOOo;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p3, Llyiahf/vczjk/o45;

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p3, p0, Llyiahf/vczjk/de4;->OooO0o0:Llyiahf/vczjk/o45;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)V
    .locals 2

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "location"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/de4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v0, v0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v1, p0, Llyiahf/vczjk/de4;->OooO0OO:Llyiahf/vczjk/tr4;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooOOO:Llyiahf/vczjk/sp3;

    invoke-static {v0, p2, v1, p1}, Llyiahf/vczjk/ls6;->OooOOOo(Llyiahf/vczjk/sp3;Llyiahf/vczjk/x65;Llyiahf/vczjk/hh6;Llyiahf/vczjk/qt5;)V

    return-void
.end method

.method public final OooO00o()Ljava/util/Set;
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/de4;->OooO0oo()[Llyiahf/vczjk/jg5;

    move-result-object v0

    new-instance v1, Ljava/util/LinkedHashSet;

    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    array-length v2, v0

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    aget-object v4, v0, v3

    invoke-interface {v4}, Llyiahf/vczjk/jg5;->OooO00o()Ljava/util/Set;

    move-result-object v4

    check-cast v4, Ljava/lang/Iterable;

    invoke-static {v4, v1}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/de4;->OooO0Oo:Llyiahf/vczjk/zr4;

    invoke-virtual {v0}, Llyiahf/vczjk/ds4;->OooO00o()Ljava/util/Set;

    move-result-object v0

    check-cast v0, Ljava/util/Collection;

    invoke-interface {v1, v0}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    return-object v1
.end method

.method public final OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;
    .locals 6

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "location"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/de4;->OooO(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)V

    iget-object v0, p0, Llyiahf/vczjk/de4;->OooO0Oo:Llyiahf/vczjk/zr4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x0

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/zr4;->OooOo0O(Llyiahf/vczjk/qt5;Llyiahf/vczjk/cm7;)Llyiahf/vczjk/by0;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/de4;->OooO0oo()[Llyiahf/vczjk/jg5;

    move-result-object v0

    array-length v2, v0

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_3

    aget-object v4, v0, v3

    invoke-interface {v4, p1, p2}, Llyiahf/vczjk/mr7;->OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;

    move-result-object v4

    if-eqz v4, :cond_2

    instance-of v5, v4, Llyiahf/vczjk/hz0;

    if-eqz v5, :cond_1

    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/yf5;

    invoke-interface {v5}, Llyiahf/vczjk/yf5;->Oooo0()Z

    move-result v5

    if-eqz v5, :cond_1

    if-nez v1, :cond_2

    move-object v1, v4

    goto :goto_1

    :cond_1
    return-object v4

    :cond_2
    :goto_1
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_3
    return-object v1
.end method

.method public final OooO0OO()Ljava/util/Set;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/de4;->OooO0oo()[Llyiahf/vczjk/jg5;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/sy;->OooooOo([Ljava/lang/Object;)Ljava/lang/Iterable;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/bua;->OooOo0(Ljava/lang/Iterable;)Ljava/util/HashSet;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/de4;->OooO0Oo:Llyiahf/vczjk/zr4;

    invoke-virtual {v1}, Llyiahf/vczjk/ds4;->OooO0OO()Ljava/util/Set;

    move-result-object v1

    check-cast v1, Ljava/util/Collection;

    invoke-interface {v0, v1}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;
    .locals 5

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/de4;->OooO(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)V

    invoke-virtual {p0}, Llyiahf/vczjk/de4;->OooO0oo()[Llyiahf/vczjk/jg5;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/de4;->OooO0Oo:Llyiahf/vczjk/zr4;

    invoke-virtual {v1, p1, p2}, Llyiahf/vczjk/ds4;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object v1

    array-length v2, v0

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    aget-object v4, v0, v3

    invoke-interface {v4, p1, p2}, Llyiahf/vczjk/jg5;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object v4

    invoke-static {v1, v4}, Llyiahf/vczjk/ls6;->OooO0o(Ljava/util/Collection;Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object v1

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    if-nez v1, :cond_1

    sget-object p1, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    return-object p1

    :cond_1
    return-object v1
.end method

.method public final OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;
    .locals 5

    const-string v0, "kindFilter"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/de4;->OooO0oo()[Llyiahf/vczjk/jg5;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/de4;->OooO0Oo:Llyiahf/vczjk/zr4;

    invoke-virtual {v1, p1, p2}, Llyiahf/vczjk/zr4;->OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;

    move-result-object v1

    array-length v2, v0

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    aget-object v4, v0, v3

    invoke-interface {v4, p1, p2}, Llyiahf/vczjk/mr7;->OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;

    move-result-object v4

    invoke-static {v1, v4}, Llyiahf/vczjk/ls6;->OooO0o(Ljava/util/Collection;Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object v1

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    if-nez v1, :cond_1

    sget-object p1, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    return-object p1

    :cond_1
    return-object v1
.end method

.method public final OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;
    .locals 5

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/de4;->OooO(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)V

    invoke-virtual {p0}, Llyiahf/vczjk/de4;->OooO0oo()[Llyiahf/vczjk/jg5;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/de4;->OooO0Oo:Llyiahf/vczjk/zr4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    array-length v2, v0

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    aget-object v4, v0, v3

    invoke-interface {v4, p1, p2}, Llyiahf/vczjk/jg5;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object v4

    invoke-static {v1, v4}, Llyiahf/vczjk/ls6;->OooO0o(Ljava/util/Collection;Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object v1

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    if-nez v1, :cond_1

    sget-object p1, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    return-object p1

    :cond_1
    return-object v1
.end method

.method public final OooO0oO()Ljava/util/Set;
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/de4;->OooO0oo()[Llyiahf/vczjk/jg5;

    move-result-object v0

    new-instance v1, Ljava/util/LinkedHashSet;

    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    array-length v2, v0

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    aget-object v4, v0, v3

    invoke-interface {v4}, Llyiahf/vczjk/jg5;->OooO0oO()Ljava/util/Set;

    move-result-object v4

    check-cast v4, Ljava/lang/Iterable;

    invoke-static {v4, v1}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/de4;->OooO0Oo:Llyiahf/vczjk/zr4;

    invoke-virtual {v0}, Llyiahf/vczjk/ds4;->OooO0oO()Ljava/util/Set;

    move-result-object v0

    check-cast v0, Ljava/util/Collection;

    invoke-interface {v1, v0}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    return-object v1
.end method

.method public final OooO0oo()[Llyiahf/vczjk/jg5;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/de4;->OooO0o0:Llyiahf/vczjk/o45;

    sget-object v1, Llyiahf/vczjk/de4;->OooO0o:[Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    invoke-static {v0, v1}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/jg5;

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "scope for "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/de4;->OooO0OO:Llyiahf/vczjk/tr4;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
