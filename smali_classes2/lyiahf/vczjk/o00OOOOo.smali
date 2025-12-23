.class public abstract Llyiahf/vczjk/o00OOOOo;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooOOO:I

.field public OooOOO0:I

.field public OooOOOO:Ljava/io/Serializable;

.field public OooOOOo:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/String;ILjava/util/Map;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, -0x1

    iput v0, p0, Llyiahf/vczjk/o00OOOOo;->OooOOO:I

    iput-object p1, p0, Llyiahf/vczjk/o00OOOOo;->OooOOOO:Ljava/io/Serializable;

    iput p2, p0, Llyiahf/vczjk/o00OOOOo;->OooOOO0:I

    iput-object p3, p0, Llyiahf/vczjk/o00OOOOo;->OooOOOo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public OooO(Llyiahf/vczjk/o00Oo00;)V
    .locals 6

    monitor-enter p0

    :try_start_0
    iget v0, p0, Llyiahf/vczjk/o00OOOOo;->OooOOO0:I

    const/4 v1, -0x1

    add-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/o00OOOOo;->OooOOO0:I

    iget-object v2, p0, Llyiahf/vczjk/o00OOOOo;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/c99;

    const/4 v3, 0x0

    if-nez v0, :cond_0

    iput v3, p0, Llyiahf/vczjk/o00OOOOo;->OooOOO:I

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_0
    :goto_0
    const-string v0, "null cannot be cast to non-null type kotlinx.coroutines.flow.internal.AbstractSharedFlowSlot<kotlin.Any>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1, p0}, Llyiahf/vczjk/o00Oo00;->OooO0O0(Llyiahf/vczjk/o00OOOOo;)[Llyiahf/vczjk/yo1;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    array-length v0, p1

    :goto_1
    if-ge v3, v0, :cond_2

    aget-object v4, p1, v3

    if-eqz v4, :cond_1

    sget-object v5, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-interface {v4, v5}, Llyiahf/vczjk/yo1;->resumeWith(Ljava/lang/Object;)V

    :cond_1
    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_2
    if-eqz v2, :cond_3

    invoke-virtual {v2, v1}, Llyiahf/vczjk/c99;->OooOoOO(I)V

    :cond_3
    return-void

    :goto_2
    monitor-exit p0

    throw p1
.end method

.method public OooO0OO()Llyiahf/vczjk/o00Oo00;
    .locals 4

    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/o00OOOOo;->OooOOOO:Ljava/io/Serializable;

    check-cast v0, [Llyiahf/vczjk/o00Oo00;

    if-nez v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/o00OOOOo;->OooO0o()[Llyiahf/vczjk/o00Oo00;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/o00OOOOo;->OooOOOO:Ljava/io/Serializable;

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_0
    iget v1, p0, Llyiahf/vczjk/o00OOOOo;->OooOOO0:I

    array-length v2, v0

    if-lt v1, v2, :cond_1

    array-length v1, v0

    mul-int/lit8 v1, v1, 0x2

    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    const-string v1, "copyOf(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v1, v0

    check-cast v1, [Llyiahf/vczjk/o00Oo00;

    iput-object v1, p0, Llyiahf/vczjk/o00OOOOo;->OooOOOO:Ljava/io/Serializable;

    check-cast v0, [Llyiahf/vczjk/o00Oo00;

    :cond_1
    :goto_0
    iget v1, p0, Llyiahf/vczjk/o00OOOOo;->OooOOO:I

    :cond_2
    aget-object v2, v0, v1

    if-nez v2, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/o00OOOOo;->OooO0o0()Llyiahf/vczjk/o00Oo00;

    move-result-object v2

    aput-object v2, v0, v1

    :cond_3
    add-int/lit8 v1, v1, 0x1

    array-length v3, v0

    if-lt v1, v3, :cond_4

    const/4 v1, 0x0

    :cond_4
    invoke-virtual {v2, p0}, Llyiahf/vczjk/o00Oo00;->OooO00o(Llyiahf/vczjk/o00OOOOo;)Z

    move-result v3

    if-eqz v3, :cond_2

    iput v1, p0, Llyiahf/vczjk/o00OOOOo;->OooOOO:I

    iget v0, p0, Llyiahf/vczjk/o00OOOOo;->OooOOO0:I

    const/4 v1, 0x1

    add-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/o00OOOOo;->OooOOO0:I

    iget-object v0, p0, Llyiahf/vczjk/o00OOOOo;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/c99;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    if-eqz v0, :cond_5

    invoke-virtual {v0, v1}, Llyiahf/vczjk/c99;->OooOoOO(I)V

    :cond_5
    return-object v2

    :goto_1
    monitor-exit p0

    throw v0
.end method

.method public OooO0Oo()Ljava/util/Map;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o00OOOOo;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Ljava/util/Map;

    return-object v0
.end method

.method public abstract OooO0o()[Llyiahf/vczjk/o00Oo00;
.end method

.method public abstract OooO0o0()Llyiahf/vczjk/o00Oo00;
.end method

.method public abstract OooOO0()Llyiahf/vczjk/xp3;
.end method

.method public OooOO0O()Llyiahf/vczjk/c99;
    .locals 5

    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/o00OOOOo;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/c99;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/c99;

    iget v1, p0, Llyiahf/vczjk/o00OOOOo;->OooOOO0:I

    sget-object v2, Llyiahf/vczjk/aj0;->OooOOO:Llyiahf/vczjk/aj0;

    const/4 v3, 0x1

    const v4, 0x7fffffff

    invoke-direct {v0, v3, v4, v2}, Llyiahf/vczjk/jl8;-><init>(IILlyiahf/vczjk/aj0;)V

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/jl8;->OooO0oo(Ljava/lang/Object;)Z

    iput-object v0, p0, Llyiahf/vczjk/o00OOOOo;->OooOOOo:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit p0

    return-object v0

    :goto_1
    monitor-exit p0

    throw v0
.end method

.method public abstract OooOO0o()Z
.end method

.method public OooOOO0()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/o00OOOOo;->OooOOO:I

    const/4 v1, -0x1

    if-le v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method
