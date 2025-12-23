.class public abstract Llyiahf/vczjk/aaa;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/util/Set;

.field public static final OooO0O0:Ljava/util/HashMap;

.field public static final OooO0OO:Ljava/util/HashMap;

.field public static final OooO0Oo:Ljava/util/LinkedHashSet;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    invoke-static {}, Llyiahf/vczjk/z9a;->values()[Llyiahf/vczjk/z9a;

    move-result-object v0

    new-instance v1, Ljava/util/ArrayList;

    array-length v2, v0

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    array-length v2, v0

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v2, :cond_0

    aget-object v5, v0, v4

    invoke-virtual {v5}, Llyiahf/vczjk/z9a;->OooO0OO()Llyiahf/vczjk/qt5;

    move-result-object v5

    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_0
    invoke-static {v1}, Llyiahf/vczjk/d21;->o0000OOo(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/aaa;->OooO00o:Ljava/util/Set;

    invoke-static {}, Llyiahf/vczjk/y9a;->values()[Llyiahf/vczjk/y9a;

    move-result-object v0

    new-instance v1, Ljava/util/ArrayList;

    array-length v2, v0

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    array-length v2, v0

    move v4, v3

    :goto_1
    if-ge v4, v2, :cond_1

    aget-object v5, v0, v4

    invoke-virtual {v5}, Llyiahf/vczjk/y9a;->OooO00o()Llyiahf/vczjk/qt5;

    move-result-object v5

    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v4, v4, 0x1

    goto :goto_1

    :cond_1
    invoke-static {v1}, Llyiahf/vczjk/d21;->o0000OOo(Ljava/lang/Iterable;)Ljava/util/Set;

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    sput-object v0, Llyiahf/vczjk/aaa;->OooO0O0:Ljava/util/HashMap;

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    sput-object v0, Llyiahf/vczjk/aaa;->OooO0OO:Ljava/util/HashMap;

    sget-object v0, Llyiahf/vczjk/y9a;->OooOOO0:Llyiahf/vczjk/y9a;

    const-string v1, "ubyteArrayOf"

    invoke-static {v1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/xn6;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/y9a;->OooOOO:Llyiahf/vczjk/y9a;

    const-string v1, "ushortArrayOf"

    invoke-static {v1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v1

    new-instance v4, Llyiahf/vczjk/xn6;

    invoke-direct {v4, v0, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/y9a;->OooOOOO:Llyiahf/vczjk/y9a;

    const-string v1, "uintArrayOf"

    invoke-static {v1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v1

    new-instance v5, Llyiahf/vczjk/xn6;

    invoke-direct {v5, v0, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/y9a;->OooOOOo:Llyiahf/vczjk/y9a;

    const-string v1, "ulongArrayOf"

    invoke-static {v1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/xn6;

    invoke-direct {v6, v0, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    filled-new-array {v2, v4, v5, v6}, [Llyiahf/vczjk/xn6;

    move-result-object v0

    new-instance v1, Ljava/util/HashMap;

    const/4 v2, 0x4

    invoke-static {v2}, Llyiahf/vczjk/lc5;->o00oO0o(I)I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/HashMap;-><init>(I)V

    invoke-static {v1, v0}, Llyiahf/vczjk/lc5;->o0ooOoO(Ljava/util/HashMap;[Llyiahf/vczjk/xn6;)V

    invoke-static {}, Llyiahf/vczjk/z9a;->values()[Llyiahf/vczjk/z9a;

    move-result-object v0

    new-instance v1, Ljava/util/LinkedHashSet;

    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    array-length v2, v0

    move v4, v3

    :goto_2
    if-ge v4, v2, :cond_2

    aget-object v5, v0, v4

    invoke-virtual {v5}, Llyiahf/vczjk/z9a;->OooO00o()Llyiahf/vczjk/hy0;

    move-result-object v5

    invoke-virtual {v5}, Llyiahf/vczjk/hy0;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v5

    invoke-interface {v1, v5}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    add-int/lit8 v4, v4, 0x1

    goto :goto_2

    :cond_2
    sput-object v1, Llyiahf/vczjk/aaa;->OooO0Oo:Ljava/util/LinkedHashSet;

    invoke-static {}, Llyiahf/vczjk/z9a;->values()[Llyiahf/vczjk/z9a;

    move-result-object v0

    array-length v1, v0

    :goto_3
    if-ge v3, v1, :cond_3

    aget-object v2, v0, v3

    sget-object v4, Llyiahf/vczjk/aaa;->OooO0O0:Ljava/util/HashMap;

    invoke-virtual {v2}, Llyiahf/vczjk/z9a;->OooO00o()Llyiahf/vczjk/hy0;

    move-result-object v5

    invoke-virtual {v2}, Llyiahf/vczjk/z9a;->OooO0O0()Llyiahf/vczjk/hy0;

    move-result-object v6

    invoke-virtual {v4, v5, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v4, Llyiahf/vczjk/aaa;->OooO0OO:Ljava/util/HashMap;

    invoke-virtual {v2}, Llyiahf/vczjk/z9a;->OooO0O0()Llyiahf/vczjk/hy0;

    move-result-object v5

    invoke-virtual {v2}, Llyiahf/vczjk/z9a;->OooO00o()Llyiahf/vczjk/hy0;

    move-result-object v2

    invoke-virtual {v4, v5, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v3, v3, 0x1

    goto :goto_3

    :cond_3
    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/uk4;)Z
    .locals 2

    invoke-static {p0}, Llyiahf/vczjk/l5a;->OooOO0o(Llyiahf/vczjk/uk4;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p0

    if-nez p0, :cond_1

    goto :goto_0

    :cond_1
    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/hh6;

    if-eqz v1, :cond_2

    check-cast v0, Llyiahf/vczjk/hh6;

    check-cast v0, Llyiahf/vczjk/ih6;

    iget-object v0, v0, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    sget-object v1, Llyiahf/vczjk/x09;->OooOO0o:Llyiahf/vczjk/hc3;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    sget-object v0, Llyiahf/vczjk/aaa;->OooO00o:Ljava/util/Set;

    invoke-interface {p0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p0

    invoke-interface {v0, p0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_2

    const/4 p0, 0x1

    return p0

    :cond_2
    :goto_0
    const/4 p0, 0x0

    return p0
.end method
