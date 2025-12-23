.class public Llyiahf/vczjk/o2a;
.super Llyiahf/vczjk/r1a;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/qb4;)Ljava/lang/Object;
    .locals 6

    new-instance v0, Ljava/util/BitSet;

    invoke-direct {v0}, Ljava/util/BitSet;-><init>()V

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooO0Oo()V

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o0000()I

    move-result v1

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    const/4 v4, 0x2

    if-eq v1, v4, :cond_5

    invoke-static {v1}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v4

    const/4 v5, 0x5

    if-eq v4, v5, :cond_1

    const/4 v5, 0x6

    if-eq v4, v5, :cond_1

    const/4 v5, 0x7

    if-ne v4, v5, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->Oooooo0()Z

    move-result v1

    goto :goto_1

    :cond_0
    new-instance v0, Llyiahf/vczjk/fc4;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Invalid bitset value type: "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/u81;->OooOoo0(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "; at path "

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/qb4;->Oooo0oO(Z)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o00oO0o()I

    move-result v1

    if-nez v1, :cond_2

    move v1, v2

    goto :goto_1

    :cond_2
    const/4 v4, 0x1

    if-ne v1, v4, :cond_4

    move v1, v4

    :goto_1
    if-eqz v1, :cond_3

    invoke-virtual {v0, v3}, Ljava/util/BitSet;->set(I)V

    :cond_3
    add-int/lit8 v3, v3, 0x1

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o0000()I

    move-result v1

    goto :goto_0

    :cond_4
    new-instance v0, Llyiahf/vczjk/fc4;

    const-string v2, "Invalid bitset value "

    const-string v3, ", expected 0 or 1; at path "

    invoke-static {v1, v2, v3}, Llyiahf/vczjk/ii5;->OooOOO(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {p1, v4}, Llyiahf/vczjk/qb4;->Oooo0oO(Z)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooOoO()V

    return-object v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/zc4;Ljava/lang/Object;)V
    .locals 4

    check-cast p2, Ljava/util/BitSet;

    invoke-virtual {p1}, Llyiahf/vczjk/zc4;->OooO0oO()V

    invoke-virtual {p2}, Ljava/util/BitSet;->length()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    invoke-virtual {p2, v1}, Ljava/util/BitSet;->get(I)Z

    move-result v2

    int-to-long v2, v2

    invoke-virtual {p1, v2, v3}, Llyiahf/vczjk/zc4;->o0ooOO0(J)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/zc4;->OooOoO()V

    return-void
.end method
