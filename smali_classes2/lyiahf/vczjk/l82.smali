.class public final Llyiahf/vczjk/l82;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0O0:Ljava/util/Set;

.field public static final OooO0OO:Ljava/util/Set;

.field public static final OooO0Oo:Llyiahf/vczjk/yi5;

.field public static final OooO0o0:Llyiahf/vczjk/yi5;


# instance fields
.field public OooO00o:Llyiahf/vczjk/s72;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    sget-object v0, Llyiahf/vczjk/ik4;->OooOOOo:Llyiahf/vczjk/ik4;

    invoke-static {v0}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/l82;->OooO0O0:Ljava/util/Set;

    sget-object v0, Llyiahf/vczjk/ik4;->OooOOo0:Llyiahf/vczjk/ik4;

    sget-object v1, Llyiahf/vczjk/ik4;->OooOo00:Llyiahf/vczjk/ik4;

    filled-new-array {v0, v1}, [Llyiahf/vczjk/ik4;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/sy;->o0000O0O([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/l82;->OooO0OO:Ljava/util/Set;

    new-instance v0, Llyiahf/vczjk/yi5;

    const/4 v1, 0x1

    const/4 v2, 0x2

    filled-new-array {v1, v1, v2}, [I

    move-result-object v2

    const/4 v3, 0x0

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/yi5;-><init>([IZ)V

    new-instance v0, Llyiahf/vczjk/yi5;

    const/16 v2, 0xb

    filled-new-array {v1, v1, v2}, [I

    move-result-object v2

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/yi5;-><init>([IZ)V

    sput-object v0, Llyiahf/vczjk/l82;->OooO0Oo:Llyiahf/vczjk/yi5;

    new-instance v0, Llyiahf/vczjk/yi5;

    const/16 v2, 0xd

    filled-new-array {v1, v1, v2}, [I

    move-result-object v1

    invoke-direct {v0, v1, v3}, Llyiahf/vczjk/yi5;-><init>([IZ)V

    sput-object v0, Llyiahf/vczjk/l82;->OooO0o0:Llyiahf/vczjk/yi5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/hh6;Llyiahf/vczjk/tm7;)Llyiahf/vczjk/s82;
    .locals 10

    const-string v3, "Could not read data from "

    const-string v0, "descriptor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "kotlinClass"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p2, Llyiahf/vczjk/tm7;->OooO0O0:Llyiahf/vczjk/fq3;

    iget-object v4, v0, Llyiahf/vczjk/fq3;->OooO0o0:Ljava/lang/Object;

    check-cast v4, [Ljava/lang/String;

    if-nez v4, :cond_0

    iget-object v4, v0, Llyiahf/vczjk/fq3;->OooO0o:Ljava/lang/Object;

    check-cast v4, [Ljava/lang/String;

    :cond_0
    const/4 v5, 0x0

    if-eqz v4, :cond_1

    iget-object v6, v0, Llyiahf/vczjk/fq3;->OooO0OO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/ik4;

    sget-object v7, Llyiahf/vczjk/l82;->OooO0OO:Ljava/util/Set;

    invoke-interface {v7, v6}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_1

    goto :goto_0

    :cond_1
    move-object v4, v5

    :goto_0
    if-nez v4, :cond_2

    goto :goto_3

    :cond_2
    iget-object v6, v0, Llyiahf/vczjk/fq3;->OooO0Oo:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/yi5;

    iget-object v0, v0, Llyiahf/vczjk/fq3;->OooO0oO:Ljava/lang/Object;

    check-cast v0, [Ljava/lang/String;

    if-nez v0, :cond_3

    goto :goto_3

    :cond_3
    :try_start_0
    invoke-static {v4, v0}, Llyiahf/vczjk/ve4;->OooO0oo([Ljava/lang/String;[Ljava/lang/String;)Llyiahf/vczjk/xn6;

    move-result-object v0
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_2

    :catchall_0
    move-exception v0

    goto :goto_1

    :catch_0
    move-exception v0

    :try_start_1
    new-instance v4, Ljava/lang/IllegalStateException;

    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2}, Llyiahf/vczjk/tm7;->OooO00o()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v4, v3, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :goto_1
    invoke-virtual {p0}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v3

    iget-object v3, v3, Llyiahf/vczjk/s72;->OooO0OO:Llyiahf/vczjk/pp3;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p0}, Llyiahf/vczjk/l82;->OooO0o0()Llyiahf/vczjk/yi5;

    move-result-object v3

    invoke-virtual {v6, v3}, Llyiahf/vczjk/yi5;->OooO0O0(Llyiahf/vczjk/yi5;)Z

    move-result v3

    if-nez v3, :cond_5

    move-object v0, v5

    :goto_2
    if-nez v0, :cond_4

    :goto_3
    return-object v5

    :cond_4
    invoke-virtual {v0}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/be4;

    invoke-virtual {v0}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/tc7;

    move-object v5, v6

    new-instance v6, Llyiahf/vczjk/ce4;

    invoke-virtual {p0, p2}, Llyiahf/vczjk/l82;->OooO0Oo(Llyiahf/vczjk/tm7;)Llyiahf/vczjk/nw3;

    invoke-virtual {p0, p2}, Llyiahf/vczjk/l82;->OooO0o(Llyiahf/vczjk/tm7;)Z

    invoke-virtual {p0, p2}, Llyiahf/vczjk/l82;->OooO0O0(Llyiahf/vczjk/tm7;)Llyiahf/vczjk/i82;

    move-result-object v0

    invoke-direct {v6, p2, v3, v4, v0}, Llyiahf/vczjk/ce4;-><init>(Llyiahf/vczjk/tm7;Llyiahf/vczjk/tc7;Llyiahf/vczjk/be4;Llyiahf/vczjk/i82;)V

    new-instance v1, Llyiahf/vczjk/s82;

    invoke-virtual {p0}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v7

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v8, "scope for "

    invoke-direct {v0, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v8, " in "

    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/dk0;->OooOOo:Llyiahf/vczjk/dk0;

    move-object v2, p1

    invoke-direct/range {v1 .. v9}, Llyiahf/vczjk/s82;-><init>(Llyiahf/vczjk/hh6;Llyiahf/vczjk/tc7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/zb0;Llyiahf/vczjk/ce4;Llyiahf/vczjk/s72;Ljava/lang/String;Llyiahf/vczjk/le3;)V

    return-object v1

    :cond_5
    throw v0
.end method

.method public final OooO0O0(Llyiahf/vczjk/tm7;)Llyiahf/vczjk/i82;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooO0OO:Llyiahf/vczjk/pp3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p1, p1, Llyiahf/vczjk/tm7;->OooO0O0:Llyiahf/vczjk/fq3;

    iget p1, p1, Llyiahf/vczjk/fq3;->OooO0O0:I

    and-int/lit8 v0, p1, 0x10

    if-eqz v0, :cond_1

    and-int/lit8 p1, p1, 0x20

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/i82;->OooOOO:Llyiahf/vczjk/i82;

    return-object p1

    :cond_1
    :goto_0
    sget-object p1, Llyiahf/vczjk/i82;->OooOOO0:Llyiahf/vczjk/i82;

    return-object p1
.end method

.method public final OooO0OO()Llyiahf/vczjk/s72;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/l82;->OooO00o:Llyiahf/vczjk/s72;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const-string v0, "components"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/tm7;)Llyiahf/vczjk/nw3;
    .locals 8

    invoke-virtual {p0}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooO0OO:Llyiahf/vczjk/pp3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p1, Llyiahf/vczjk/tm7;->OooO0O0:Llyiahf/vczjk/fq3;

    iget-object v0, v0, Llyiahf/vczjk/fq3;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yi5;

    invoke-virtual {p0}, Llyiahf/vczjk/l82;->OooO0o0()Llyiahf/vczjk/yi5;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/yi5;->OooO0O0(Llyiahf/vczjk/yi5;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    new-instance v0, Llyiahf/vczjk/nw3;

    iget-object v1, p1, Llyiahf/vczjk/tm7;->OooO0O0:Llyiahf/vczjk/fq3;

    iget-object v1, v1, Llyiahf/vczjk/fq3;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/yi5;

    sget-object v2, Llyiahf/vczjk/yi5;->OooO0oO:Llyiahf/vczjk/yi5;

    invoke-virtual {p0}, Llyiahf/vczjk/l82;->OooO0o0()Llyiahf/vczjk/yi5;

    move-result-object v3

    invoke-virtual {p0}, Llyiahf/vczjk/l82;->OooO0o0()Llyiahf/vczjk/yi5;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-boolean v5, v1, Llyiahf/vczjk/yi5;->OooO0o:Z

    if-eqz v5, :cond_1

    move-object v5, v2

    goto :goto_0

    :cond_1
    sget-object v5, Llyiahf/vczjk/yi5;->OooO0oo:Llyiahf/vczjk/yi5;

    :goto_0
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v6, v4, Llyiahf/vczjk/zb0;->OooO0O0:I

    iget v7, v5, Llyiahf/vczjk/zb0;->OooO0O0:I

    if-le v7, v6, :cond_2

    goto :goto_1

    :cond_2
    if-ge v7, v6, :cond_3

    goto :goto_2

    :cond_3
    iget v6, v5, Llyiahf/vczjk/zb0;->OooO0OO:I

    iget v7, v4, Llyiahf/vczjk/zb0;->OooO0OO:I

    if-le v6, v7, :cond_4

    :goto_1
    move-object v4, v5

    :cond_4
    :goto_2
    invoke-virtual {p1}, Llyiahf/vczjk/tm7;->OooO00o()Ljava/lang/String;

    move-result-object v5

    iget-object p1, p1, Llyiahf/vczjk/tm7;->OooO00o:Ljava/lang/Class;

    invoke-static {p1}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v6

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/nw3;-><init>(Ljava/lang/Object;Llyiahf/vczjk/yi5;Llyiahf/vczjk/yi5;Llyiahf/vczjk/yi5;Ljava/lang/String;Llyiahf/vczjk/hy0;)V

    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/tm7;)Z
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooO0OO:Llyiahf/vczjk/pp3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p0}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooO0OO:Llyiahf/vczjk/pp3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p1, p1, Llyiahf/vczjk/tm7;->OooO0O0:Llyiahf/vczjk/fq3;

    iget v0, p1, Llyiahf/vczjk/fq3;->OooO0O0:I

    and-int/lit8 v0, v0, 0x2

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-eqz v0, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    if-eqz v0, :cond_1

    iget-object p1, p1, Llyiahf/vczjk/fq3;->OooO0Oo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/yi5;

    sget-object v0, Llyiahf/vczjk/l82;->OooO0Oo:Llyiahf/vczjk/yi5;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zb0;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    return v2

    :cond_1
    return v1
.end method

.method public final OooO0o0()Llyiahf/vczjk/yi5;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooO0OO:Llyiahf/vczjk/pp3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/yi5;->OooO0oO:Llyiahf/vczjk/yi5;

    return-object v0
.end method

.method public final OooO0oO(Llyiahf/vczjk/tm7;)Llyiahf/vczjk/vx0;
    .locals 6

    const-string v0, "Could not read data from "

    iget-object v1, p1, Llyiahf/vczjk/tm7;->OooO0O0:Llyiahf/vczjk/fq3;

    iget-object v2, v1, Llyiahf/vczjk/fq3;->OooO0o0:Ljava/lang/Object;

    check-cast v2, [Ljava/lang/String;

    if-nez v2, :cond_0

    iget-object v2, v1, Llyiahf/vczjk/fq3;->OooO0o:Ljava/lang/Object;

    check-cast v2, [Ljava/lang/String;

    :cond_0
    const/4 v3, 0x0

    if-eqz v2, :cond_1

    iget-object v4, v1, Llyiahf/vczjk/fq3;->OooO0OO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/ik4;

    sget-object v5, Llyiahf/vczjk/l82;->OooO0O0:Ljava/util/Set;

    invoke-interface {v5, v4}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1

    goto :goto_0

    :cond_1
    move-object v2, v3

    :goto_0
    if-nez v2, :cond_2

    goto :goto_3

    :cond_2
    iget-object v4, v1, Llyiahf/vczjk/fq3;->OooO0Oo:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/yi5;

    iget-object v1, v1, Llyiahf/vczjk/fq3;->OooO0oO:Ljava/lang/Object;

    check-cast v1, [Ljava/lang/String;

    if-nez v1, :cond_3

    goto :goto_3

    :cond_3
    :try_start_0
    invoke-static {v2, v1}, Llyiahf/vczjk/ve4;->OooO0o([Ljava/lang/String;[Ljava/lang/String;)Llyiahf/vczjk/xn6;

    move-result-object v0
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_2

    :catchall_0
    move-exception v0

    goto :goto_1

    :catch_0
    move-exception v1

    :try_start_1
    new-instance v2, Ljava/lang/IllegalStateException;

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1}, Llyiahf/vczjk/tm7;->OooO00o()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v2, v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :goto_1
    invoke-virtual {p0}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/s72;->OooO0OO:Llyiahf/vczjk/pp3;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p0}, Llyiahf/vczjk/l82;->OooO0o0()Llyiahf/vczjk/yi5;

    move-result-object v1

    invoke-virtual {v4, v1}, Llyiahf/vczjk/yi5;->OooO0O0(Llyiahf/vczjk/yi5;)Z

    move-result v1

    if-nez v1, :cond_5

    move-object v0, v3

    :goto_2
    if-nez v0, :cond_4

    :goto_3
    return-object v3

    :cond_4
    invoke-virtual {v0}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/be4;

    invoke-virtual {v0}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/zb7;

    new-instance v2, Llyiahf/vczjk/pk4;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/l82;->OooO0Oo(Llyiahf/vczjk/tm7;)Llyiahf/vczjk/nw3;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/l82;->OooO0o(Llyiahf/vczjk/tm7;)Z

    invoke-virtual {p0, p1}, Llyiahf/vczjk/l82;->OooO0O0(Llyiahf/vczjk/tm7;)Llyiahf/vczjk/i82;

    move-result-object v3

    invoke-direct {v2, p1, v3}, Llyiahf/vczjk/pk4;-><init>(Llyiahf/vczjk/tm7;Llyiahf/vczjk/i82;)V

    new-instance p1, Llyiahf/vczjk/vx0;

    invoke-direct {p1, v1, v0, v4, v2}, Llyiahf/vczjk/vx0;-><init>(Llyiahf/vczjk/rt5;Llyiahf/vczjk/zb7;Llyiahf/vczjk/zb0;Llyiahf/vczjk/sx8;)V

    return-object p1

    :cond_5
    throw v0
.end method
