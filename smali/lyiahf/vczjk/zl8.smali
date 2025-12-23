.class public final Llyiahf/vczjk/zl8;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Z

.field public final OooO0O0:Llyiahf/vczjk/oe3;

.field public final OooO0OO:Z

.field public OooO0Oo:Llyiahf/vczjk/wl;

.field public OooO0o:Llyiahf/vczjk/p13;

.field public final OooO0o0:Llyiahf/vczjk/c9;

.field public OooO0oO:Llyiahf/vczjk/p13;


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/am8;Llyiahf/vczjk/oe3;Z)V
    .locals 6

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/zl8;->OooO00o:Z

    iput-object p5, p0, Llyiahf/vczjk/zl8;->OooO0O0:Llyiahf/vczjk/oe3;

    iput-boolean p6, p0, Llyiahf/vczjk/zl8;->OooO0OO:Z

    if-eqz p1, :cond_1

    sget-object p1, Llyiahf/vczjk/am8;->OooOOOO:Llyiahf/vczjk/am8;

    if-eq p4, p1, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "The initial value must not be set to PartiallyExpanded if skipPartiallyExpanded is set to true."

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :goto_0
    if-eqz p6, :cond_3

    sget-object p1, Llyiahf/vczjk/am8;->OooOOO0:Llyiahf/vczjk/am8;

    if-eq p4, p1, :cond_2

    goto :goto_1

    :cond_2
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "The initial value must not be set to Hidden if skipHiddenState is set to true."

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    :goto_1
    sget-object p1, Llyiahf/vczjk/wl8;->OooO0O0:Llyiahf/vczjk/h1a;

    iput-object p1, p0, Llyiahf/vczjk/zl8;->OooO0Oo:Llyiahf/vczjk/wl;

    new-instance v0, Llyiahf/vczjk/c9;

    new-instance v2, Llyiahf/vczjk/hp;

    const/16 p1, 0xa

    invoke-direct {v2, p1, p2}, Llyiahf/vczjk/hp;-><init>(ILlyiahf/vczjk/le3;)V

    new-instance v4, Llyiahf/vczjk/ku7;

    const/4 p1, 0x7

    invoke-direct {v4, p0, p1}, Llyiahf/vczjk/ku7;-><init>(Ljava/lang/Object;I)V

    move-object v3, p3

    move-object v1, p4

    move-object v5, p5

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/c9;-><init>(Ljava/lang/Enum;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;)V

    iput-object v0, p0, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    invoke-static {}, Llyiahf/vczjk/ng0;->OoooOOo()Llyiahf/vczjk/ev8;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/zl8;->OooO0o:Llyiahf/vczjk/p13;

    invoke-static {}, Llyiahf/vczjk/ng0;->OoooOOo()Llyiahf/vczjk/ev8;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/zl8;->OooO0oO:Llyiahf/vczjk/p13;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/zl8;Llyiahf/vczjk/am8;Llyiahf/vczjk/p13;Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    iget-object v0, v0, Llyiahf/vczjk/c9;->OooOO0O:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v0

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/yl8;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v0, p2, v2}, Llyiahf/vczjk/yl8;-><init>(Llyiahf/vczjk/zl8;FLlyiahf/vczjk/p13;Llyiahf/vczjk/yo1;)V

    iget-object p0, p0, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    sget-object p2, Llyiahf/vczjk/at5;->OooOOO0:Llyiahf/vczjk/at5;

    invoke-virtual {p0, p1, p2, v1, p3}, Llyiahf/vczjk/c9;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/at5;Llyiahf/vczjk/df3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p0, p1, :cond_0

    return-object p0

    :cond_0
    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/am8;->OooOOO:Llyiahf/vczjk/am8;

    iget-object v1, p0, Llyiahf/vczjk/zl8;->OooO0O0:Llyiahf/vczjk/oe3;

    invoke-interface {v1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/zl8;->OooO0o:Llyiahf/vczjk/p13;

    invoke-static {p0, v0, v1, p1}, Llyiahf/vczjk/zl8;->OooO00o(Llyiahf/vczjk/zl8;Llyiahf/vczjk/am8;Llyiahf/vczjk/p13;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v0, :cond_0

    return-object p1

    :cond_0
    return-object v2
.end method

.method public final OooO0OO()Llyiahf/vczjk/am8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    iget-object v0, v0, Llyiahf/vczjk/c9;->OooO0oO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/am8;

    return-object v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/zl8;->OooO0OO:Z

    if-nez v0, :cond_1

    sget-object v0, Llyiahf/vczjk/am8;->OooOOO0:Llyiahf/vczjk/am8;

    iget-object v1, p0, Llyiahf/vczjk/zl8;->OooO0O0:Llyiahf/vczjk/oe3;

    invoke-interface {v1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/zl8;->OooO0oO:Llyiahf/vczjk/p13;

    invoke-static {p0, v0, v1, p1}, Llyiahf/vczjk/zl8;->OooO00o(Llyiahf/vczjk/zl8;Llyiahf/vczjk/am8;Llyiahf/vczjk/p13;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v0, :cond_0

    return-object p1

    :cond_0
    return-object v2

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Attempted to animate to hidden when skipHiddenState was enabled. Set skipHiddenState to false to use this function."

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0o(Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/zl8;->OooO00o:Z

    if-nez v0, :cond_1

    sget-object v0, Llyiahf/vczjk/am8;->OooOOOO:Llyiahf/vczjk/am8;

    iget-object v1, p0, Llyiahf/vczjk/zl8;->OooO0O0:Llyiahf/vczjk/oe3;

    invoke-interface {v1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/zl8;->OooO0oO:Llyiahf/vczjk/p13;

    invoke-static {p0, v0, v1, p1}, Llyiahf/vczjk/zl8;->OooO00o(Llyiahf/vczjk/zl8;Llyiahf/vczjk/am8;Llyiahf/vczjk/p13;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v0, :cond_0

    return-object p1

    :cond_0
    return-object v2

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Attempted to animate to partial expanded when skipPartiallyExpanded was enabled. Set skipPartiallyExpanded to false to use this function."

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0o0()Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    iget-object v0, v0, Llyiahf/vczjk/c9;->OooO0oO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/am8;->OooOOO0:Llyiahf/vczjk/am8;

    if-eq v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0oO(Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    invoke-virtual {v0}, Llyiahf/vczjk/c9;->OooO0Oo()Llyiahf/vczjk/kb5;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/am8;->OooOOOO:Llyiahf/vczjk/am8;

    iget-object v0, v0, Llyiahf/vczjk/kb5;->OooO00o:Ljava/lang/Object;

    invoke-interface {v0, v1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    sget-object v1, Llyiahf/vczjk/am8;->OooOOO:Llyiahf/vczjk/am8;

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/zl8;->OooO0O0:Llyiahf/vczjk/oe3;

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/zl8;->OooO0o:Llyiahf/vczjk/p13;

    invoke-static {p0, v1, v0, p1}, Llyiahf/vczjk/zl8;->OooO00o(Llyiahf/vczjk/zl8;Llyiahf/vczjk/am8;Llyiahf/vczjk/p13;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v0, :cond_1

    return-object p1

    :cond_1
    return-object v2
.end method
