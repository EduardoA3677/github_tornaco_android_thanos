.class public abstract Llyiahf/vczjk/o0O0O00;
.super Llyiahf/vczjk/o0O00000;
.source "SourceFile"


# direct methods
.method public constructor <init>(Llyiahf/vczjk/q45;)V
    .locals 0

    if-eqz p1, :cond_0

    invoke-direct {p0, p1}, Llyiahf/vczjk/o0O00000;-><init>(Llyiahf/vczjk/w59;)V

    return-void

    :cond_0
    const/4 p1, 0x0

    invoke-static {p1}, Llyiahf/vczjk/o0O0O00;->OooOOO0(I)V

    const/4 p1, 0x0

    throw p1
.end method

.method public static synthetic OooOOO0(I)V
    .locals 9

    const/4 v0, 0x4

    const/4 v1, 0x3

    const/4 v2, 0x1

    if-eq p0, v2, :cond_0

    if-eq p0, v1, :cond_0

    if-eq p0, v0, :cond_0

    const-string v3, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    goto :goto_0

    :cond_0
    const-string v3, "@NotNull method %s.%s must not return null"

    :goto_0
    const/4 v4, 0x2

    if-eq p0, v2, :cond_1

    if-eq p0, v1, :cond_1

    if-eq p0, v0, :cond_1

    move v5, v1

    goto :goto_1

    :cond_1
    move v5, v4

    :goto_1
    new-array v5, v5, [Ljava/lang/Object;

    const-string v6, "kotlin/reflect/jvm/internal/impl/types/AbstractClassTypeConstructor"

    const/4 v7, 0x0

    if-eq p0, v2, :cond_3

    if-eq p0, v4, :cond_2

    if-eq p0, v1, :cond_3

    if-eq p0, v0, :cond_3

    const-string v8, "storageManager"

    aput-object v8, v5, v7

    goto :goto_2

    :cond_2
    const-string v8, "classifier"

    aput-object v8, v5, v7

    goto :goto_2

    :cond_3
    aput-object v6, v5, v7

    :goto_2
    if-eq p0, v2, :cond_5

    if-eq p0, v1, :cond_4

    if-eq p0, v0, :cond_4

    aput-object v6, v5, v2

    goto :goto_3

    :cond_4
    const-string v6, "getAdditionalNeighboursInSupertypeGraph"

    aput-object v6, v5, v2

    goto :goto_3

    :cond_5
    const-string v6, "getBuiltIns"

    aput-object v6, v5, v2

    :goto_3
    if-eq p0, v2, :cond_7

    if-eq p0, v4, :cond_6

    if-eq p0, v1, :cond_7

    if-eq p0, v0, :cond_7

    const-string v6, "<init>"

    aput-object v6, v5, v4

    goto :goto_4

    :cond_6
    const-string v6, "isSameClassifier"

    aput-object v6, v5, v4

    :cond_7
    :goto_4
    invoke-static {v3, v5}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v3

    if-eq p0, v2, :cond_8

    if-eq p0, v1, :cond_8

    if-eq p0, v0, :cond_8

    new-instance p0, Ljava/lang/IllegalArgumentException;

    invoke-direct {p0, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    goto :goto_5

    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    :goto_5
    throw p0
.end method


# virtual methods
.method public bridge synthetic OooO00o()Llyiahf/vczjk/gz0;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/o0O0O00;->OooOOO()Llyiahf/vczjk/by0;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0oO()Llyiahf/vczjk/uk4;
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/o0O0O00;->OooOOO()Llyiahf/vczjk/by0;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    sget-object v2, Llyiahf/vczjk/hk4;->OooO0o0:Llyiahf/vczjk/qt5;

    sget-object v2, Llyiahf/vczjk/w09;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-static {v0, v2}, Llyiahf/vczjk/hk4;->OooO0O0(Llyiahf/vczjk/by0;Llyiahf/vczjk/ic3;)Z

    move-result v2

    if-nez v2, :cond_1

    sget-object v2, Llyiahf/vczjk/w09;->OooO0O0:Llyiahf/vczjk/ic3;

    invoke-static {v0, v2}, Llyiahf/vczjk/hk4;->OooO0O0(Llyiahf/vczjk/by0;Llyiahf/vczjk/ic3;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/o0O0O00;->OooOO0O()Llyiahf/vczjk/hk4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/hk4;->OooO0o0()Llyiahf/vczjk/dp8;

    move-result-object v0

    return-object v0

    :cond_1
    :goto_0
    return-object v1

    :cond_2
    const/16 v0, 0x6b

    invoke-static {v0}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v1
.end method

.method public final OooOO0(Llyiahf/vczjk/gz0;)Z
    .locals 5

    instance-of v0, p1, Llyiahf/vczjk/by0;

    const/4 v1, 0x0

    if-eqz v0, :cond_8

    invoke-virtual {p0}, Llyiahf/vczjk/o0O0O00;->OooOOO()Llyiahf/vczjk/by0;

    move-result-object v0

    const-string v2, "first"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-interface {p1}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v3

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    const/4 v3, 0x1

    if-nez v2, :cond_1

    :cond_0
    :goto_0
    move p1, v1

    goto :goto_2

    :cond_1
    invoke-interface {v0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    invoke-interface {p1}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p1

    :goto_1
    if-eqz v0, :cond_4

    if-eqz p1, :cond_4

    instance-of v2, v0, Llyiahf/vczjk/cm5;

    if-eqz v2, :cond_2

    instance-of p1, p1, Llyiahf/vczjk/cm5;

    goto :goto_2

    :cond_2
    instance-of v2, p1, Llyiahf/vczjk/cm5;

    if-eqz v2, :cond_3

    goto :goto_0

    :cond_3
    instance-of v2, v0, Llyiahf/vczjk/hh6;

    if-eqz v2, :cond_5

    instance-of v2, p1, Llyiahf/vczjk/hh6;

    if-eqz v2, :cond_0

    check-cast v0, Llyiahf/vczjk/hh6;

    check-cast v0, Llyiahf/vczjk/ih6;

    check-cast p1, Llyiahf/vczjk/hh6;

    check-cast p1, Llyiahf/vczjk/ih6;

    iget-object v0, v0, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    iget-object p1, p1, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    :cond_4
    move p1, v3

    goto :goto_2

    :cond_5
    instance-of v2, p1, Llyiahf/vczjk/hh6;

    if-eqz v2, :cond_6

    goto :goto_0

    :cond_6
    invoke-interface {v0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-interface {p1}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_7

    goto :goto_0

    :cond_7
    invoke-interface {v0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    invoke-interface {p1}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p1

    goto :goto_1

    :goto_2
    if-eqz p1, :cond_8

    return v3

    :cond_8
    return v1
.end method

.method public final OooOO0O()Llyiahf/vczjk/hk4;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/o0O0O00;->OooOOO()Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/p72;->OooO0o0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hk4;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const/4 v0, 0x1

    invoke-static {v0}, Llyiahf/vczjk/o0O0O00;->OooOOO0(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public abstract OooOOO()Llyiahf/vczjk/by0;
.end method
