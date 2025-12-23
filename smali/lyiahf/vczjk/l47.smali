.class public final Llyiahf/vczjk/l47;
.super Llyiahf/vczjk/n47;
.source "SourceFile"


# static fields
.field public static final OooOOo0:Llyiahf/vczjk/l47;

.field private static final serialVersionUID:J = 0x1L


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/l47;

    const-class v1, [J

    invoke-direct {v0, v1}, Llyiahf/vczjk/n47;-><init>(Ljava/lang/Class;)V

    sput-object v0, Llyiahf/vczjk/l47;->OooOOo0:Llyiahf/vczjk/l47;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 7

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/n47;->OoooOo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [J

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o00oO0o()Llyiahf/vczjk/ex9;

    move-result-object v0

    iget-object v1, v0, Llyiahf/vczjk/ex9;->OooOOo0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/wx;

    if-nez v1, :cond_1

    new-instance v1, Llyiahf/vczjk/wx;

    const/4 v2, 0x5

    invoke-direct {v1, v2}, Llyiahf/vczjk/wx;-><init>(I)V

    iput-object v1, v0, Llyiahf/vczjk/ex9;->OooOOo0:Ljava/lang/Object;

    :cond_1
    iget-object v0, v0, Llyiahf/vczjk/ex9;->OooOOo0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/wx;

    invoke-virtual {v0}, Llyiahf/vczjk/wx;->OooO0Oo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [J

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    :try_start_0
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-eq v4, v5, :cond_6

    sget-object v5, Llyiahf/vczjk/gc4;->OooOo0:Llyiahf/vczjk/gc4;

    if-ne v4, v5, :cond_2

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000Ooo()J

    move-result-wide v4

    goto :goto_1

    :catch_0
    move-exception p1

    goto :goto_2

    :cond_2
    sget-object v5, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v4, v5, :cond_4

    iget-object v4, p0, Llyiahf/vczjk/n47;->_nuller:Llyiahf/vczjk/u46;

    if-eqz v4, :cond_3

    invoke-interface {v4, p1}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    goto :goto_0

    :cond_3
    invoke-virtual {p0, p1}, Llyiahf/vczjk/m49;->Oooo0o0(Llyiahf/vczjk/v72;)V

    const-wide/16 v4, 0x0

    goto :goto_1

    :cond_4
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->Oooo00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)J

    move-result-wide v4

    :goto_1
    array-length v6, v1

    if-lt v3, v6, :cond_5

    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/wx;->OooO0O0(ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, [J
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    move v3, v2

    move-object v1, v6

    :cond_5
    add-int/lit8 v6, v3, 0x1

    :try_start_1
    aput-wide v4, v1, v3
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    move v3, v6

    goto :goto_0

    :catch_1
    move-exception p1

    move v3, v6

    goto :goto_2

    :cond_6
    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/wx;->OooO0OO(ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [J

    return-object p1

    :goto_2
    iget p2, v0, Llyiahf/vczjk/wx;->OooO0Oo:I

    add-int/2addr p2, v3

    invoke-static {p1, v1, p2}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1
.end method

.method public final OoooOOO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, [J

    check-cast p2, [J

    array-length v0, p1

    array-length v1, p2

    add-int v2, v0, v1

    invoke-static {p1, v2}, Ljava/util/Arrays;->copyOf([JI)[J

    move-result-object p1

    const/4 v2, 0x0

    invoke-static {p2, v2, p1, v0, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    return-object p1
.end method

.method public final OoooOOo()Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    new-array v0, v0, [J

    return-object v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->Oooo00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)J

    move-result-wide p1

    const/4 v0, 0x1

    new-array v0, v0, [J

    const/4 v1, 0x0

    aput-wide p1, v0, v1

    return-object v0
.end method

.method public final OoooOoo(Llyiahf/vczjk/u46;Ljava/lang/Boolean;)Llyiahf/vczjk/n47;
    .locals 1

    new-instance v0, Llyiahf/vczjk/l47;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/n47;-><init>(Llyiahf/vczjk/n47;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    return-object v0
.end method
