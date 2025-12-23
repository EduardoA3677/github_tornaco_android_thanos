.class public final Llyiahf/vczjk/k47;
.super Llyiahf/vczjk/n47;
.source "SourceFile"


# static fields
.field public static final OooOOo0:Llyiahf/vczjk/k47;

.field private static final serialVersionUID:J = 0x1L


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/k47;

    const-class v1, [I

    invoke-direct {v0, v1}, Llyiahf/vczjk/n47;-><init>(Ljava/lang/Class;)V

    sput-object v0, Llyiahf/vczjk/k47;->OooOOo0:Llyiahf/vczjk/k47;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 6

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/n47;->OoooOo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [I

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o00oO0o()Llyiahf/vczjk/ex9;

    move-result-object v0

    iget-object v1, v0, Llyiahf/vczjk/ex9;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/wx;

    if-nez v1, :cond_1

    new-instance v1, Llyiahf/vczjk/wx;

    const/4 v2, 0x4

    invoke-direct {v1, v2}, Llyiahf/vczjk/wx;-><init>(I)V

    iput-object v1, v0, Llyiahf/vczjk/ex9;->OooOOOo:Ljava/lang/Object;

    :cond_1
    iget-object v0, v0, Llyiahf/vczjk/ex9;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/wx;

    invoke-virtual {v0}, Llyiahf/vczjk/wx;->OooO0Oo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [I

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

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00000o0()I

    move-result v4

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

    move v4, v2

    goto :goto_1

    :cond_4
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->Oooo00O(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)I

    move-result v4

    :goto_1
    array-length v5, v1

    if-lt v3, v5, :cond_5

    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/wx;->OooO0O0(ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, [I
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    move v3, v2

    move-object v1, v5

    :cond_5
    add-int/lit8 v5, v3, 0x1

    :try_start_1
    aput v4, v1, v3
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    move v3, v5

    goto :goto_0

    :catch_1
    move-exception p1

    move v3, v5

    goto :goto_2

    :cond_6
    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/wx;->OooO0OO(ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [I

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

    check-cast p1, [I

    check-cast p2, [I

    array-length v0, p1

    array-length v1, p2

    add-int v2, v0, v1

    invoke-static {p1, v2}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object p1

    const/4 v2, 0x0

    invoke-static {p2, v2, p1, v0, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    return-object p1
.end method

.method public final OoooOOo()Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    new-array v0, v0, [I

    return-object v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->Oooo00O(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)I

    move-result p1

    filled-new-array {p1}, [I

    move-result-object p1

    return-object p1
.end method

.method public final OoooOoo(Llyiahf/vczjk/u46;Ljava/lang/Boolean;)Llyiahf/vczjk/n47;
    .locals 1

    new-instance v0, Llyiahf/vczjk/k47;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/n47;-><init>(Llyiahf/vczjk/n47;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    return-object v0
.end method
