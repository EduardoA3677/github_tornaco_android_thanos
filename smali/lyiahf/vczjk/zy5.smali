.class public final Llyiahf/vczjk/zy5;
.super Llyiahf/vczjk/ps5;
.source "SourceFile"


# instance fields
.field public final OooOOOO:Llyiahf/vczjk/ps5;

.field public OooOOOo:Z


# direct methods
.method public constructor <init>(JLlyiahf/vczjk/rv8;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ps5;)V
    .locals 0

    invoke-direct/range {p0 .. p5}, Llyiahf/vczjk/ps5;-><init>(JLlyiahf/vczjk/rv8;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    move-object p1, p0

    iput-object p6, p1, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    invoke-virtual {p6}, Llyiahf/vczjk/ps5;->OooOO0O()V

    return-void
.end method


# virtual methods
.method public final OooO0OO()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/nv8;->OooO0OO:Z

    if-nez v0, :cond_0

    invoke-super {p0}, Llyiahf/vczjk/ps5;->OooO0OO()V

    iget-boolean v0, p0, Llyiahf/vczjk/zy5;->OooOOOo:Z

    if-nez v0, :cond_0

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/zy5;->OooOOOo:Z

    iget-object v0, p0, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    invoke-virtual {v0}, Llyiahf/vczjk/ps5;->OooOO0o()V

    :cond_0
    return-void
.end method

.method public final OooOo0o()Llyiahf/vczjk/xr6;
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    iget-boolean v1, v0, Llyiahf/vczjk/ps5;->OooOOO0:Z

    if-nez v1, :cond_0

    iget-boolean v1, v0, Llyiahf/vczjk/nv8;->OooO0OO:Z

    if-eqz v1, :cond_1

    :cond_0
    move-object v2, p0

    goto/16 :goto_7

    :cond_1
    iget-object v5, p0, Llyiahf/vczjk/ps5;->OooO0oo:Llyiahf/vczjk/ks5;

    iget-wide v8, p0, Llyiahf/vczjk/nv8;->OooO0O0:J

    const/4 v1, 0x0

    if-eqz v5, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/nv8;->OooO0oO()J

    move-result-wide v2

    iget-object v0, p0, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    invoke-virtual {v0}, Llyiahf/vczjk/nv8;->OooO0Oo()Llyiahf/vczjk/rv8;

    move-result-object v0

    invoke-static {v2, v3, p0, v0}, Llyiahf/vczjk/vv8;->OooO0OO(JLlyiahf/vczjk/ps5;Llyiahf/vczjk/rv8;)Ljava/util/HashMap;

    move-result-object v0

    move-object v6, v0

    goto :goto_0

    :cond_2
    move-object v6, v1

    :goto_0
    sget-object v10, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v10

    :try_start_0
    invoke-static {p0}, Llyiahf/vczjk/vv8;->OooO0Oo(Llyiahf/vczjk/nv8;)V

    if-eqz v5, :cond_3

    iget v0, v5, Llyiahf/vczjk/a88;->OooO0Oo:I

    if-nez v0, :cond_4

    :cond_3
    move-object v2, p0

    goto :goto_1

    :cond_4
    iget-object v0, p0, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    invoke-virtual {v0}, Llyiahf/vczjk/nv8;->OooO0oO()J

    move-result-wide v3

    iget-object v0, p0, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    invoke-virtual {v0}, Llyiahf/vczjk/nv8;->OooO0Oo()Llyiahf/vczjk/rv8;

    move-result-object v7
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    move-object v2, p0

    :try_start_1
    invoke-virtual/range {v2 .. v7}, Llyiahf/vczjk/ps5;->OooOoO(JLlyiahf/vczjk/ks5;Ljava/util/HashMap;Llyiahf/vczjk/rv8;)Llyiahf/vczjk/xr6;

    move-result-object v0

    sget-object v3, Llyiahf/vczjk/pv8;->OooO0o0:Llyiahf/vczjk/pv8;

    invoke-virtual {v0, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-nez v3, :cond_5

    monitor-exit v10

    return-object v0

    :cond_5
    :try_start_2
    iget-object v0, v2, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    invoke-virtual {v0}, Llyiahf/vczjk/ps5;->OooOo()Llyiahf/vczjk/ks5;

    move-result-object v0

    if-eqz v0, :cond_6

    invoke-virtual {v0, v5}, Llyiahf/vczjk/ks5;->OooOO0O(Llyiahf/vczjk/a88;)V

    goto :goto_2

    :cond_6
    iget-object v0, v2, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    invoke-virtual {v0, v5}, Llyiahf/vczjk/ps5;->OooOoo0(Llyiahf/vczjk/ks5;)V

    iput-object v1, v2, Llyiahf/vczjk/ps5;->OooO0oo:Llyiahf/vczjk/ks5;

    goto :goto_2

    :catchall_0
    move-exception v0

    goto/16 :goto_6

    :catchall_1
    move-exception v0

    move-object v2, p0

    goto/16 :goto_6

    :goto_1
    invoke-virtual {p0}, Llyiahf/vczjk/nv8;->OooO00o()V

    :goto_2
    iget-object v0, v2, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    invoke-virtual {v0}, Llyiahf/vczjk/nv8;->OooO0oO()J

    move-result-wide v0

    cmp-long v0, v0, v8

    if-gez v0, :cond_7

    iget-object v0, v2, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    invoke-virtual {v0}, Llyiahf/vczjk/ps5;->OooOo0O()V

    :cond_7
    iget-object v0, v2, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    invoke-virtual {v0}, Llyiahf/vczjk/nv8;->OooO0Oo()Llyiahf/vczjk/rv8;

    move-result-object v1

    invoke-virtual {v1, v8, v9}, Llyiahf/vczjk/rv8;->OooO0O0(J)Llyiahf/vczjk/rv8;

    move-result-object v1

    iget-object v3, v2, Llyiahf/vczjk/ps5;->OooOO0:Llyiahf/vczjk/rv8;

    invoke-virtual {v1, v3}, Llyiahf/vczjk/rv8;->OooO00o(Llyiahf/vczjk/rv8;)Llyiahf/vczjk/rv8;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/nv8;->OooOOo(Llyiahf/vczjk/rv8;)V

    iget-object v0, v2, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    invoke-virtual {v0, v8, v9}, Llyiahf/vczjk/ps5;->OooOoOO(J)V

    iget-object v0, v2, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    iget v1, v2, Llyiahf/vczjk/nv8;->OooO0Oo:I

    const/4 v3, -0x1

    iput v3, v2, Llyiahf/vczjk/nv8;->OooO0Oo:I

    if-ltz v1, :cond_8

    iget-object v3, v0, Llyiahf/vczjk/ps5;->OooOO0O:[I

    const-string v4, "<this>"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    array-length v4, v3

    add-int/lit8 v5, v4, 0x1

    invoke-static {v3, v5}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object v3

    aput v1, v3, v4

    iput-object v3, v0, Llyiahf/vczjk/ps5;->OooOO0O:[I

    goto :goto_3

    :cond_8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :goto_3
    iget-object v0, v2, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    iget-object v1, v2, Llyiahf/vczjk/ps5;->OooOO0:Llyiahf/vczjk/rv8;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    monitor-enter v10
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    :try_start_3
    iget-object v3, v0, Llyiahf/vczjk/ps5;->OooOO0:Llyiahf/vczjk/rv8;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/rv8;->OooO0oo(Llyiahf/vczjk/rv8;)Llyiahf/vczjk/rv8;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/ps5;->OooOO0:Llyiahf/vczjk/rv8;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    :try_start_4
    monitor-exit v10

    iget-object v0, v2, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    iget-object v1, v2, Llyiahf/vczjk/ps5;->OooOO0O:[I

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    array-length v3, v1

    if-nez v3, :cond_9

    goto :goto_5

    :cond_9
    iget-object v3, v0, Llyiahf/vczjk/ps5;->OooOO0O:[I

    array-length v4, v3

    if-nez v4, :cond_a

    goto :goto_4

    :cond_a
    array-length v4, v3

    array-length v5, v1

    add-int v6, v4, v5

    invoke-static {v3, v6}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object v3

    const/4 v6, 0x0

    invoke-static {v1, v6, v3, v4, v5}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    move-object v1, v3

    :goto_4
    iput-object v1, v0, Llyiahf/vczjk/ps5;->OooOO0O:[I
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    :goto_5
    monitor-exit v10

    const/4 v0, 0x1

    iput-boolean v0, v2, Llyiahf/vczjk/ps5;->OooOOO0:Z

    iget-boolean v1, v2, Llyiahf/vczjk/zy5;->OooOOOo:Z

    if-nez v1, :cond_b

    iput-boolean v0, v2, Llyiahf/vczjk/zy5;->OooOOOo:Z

    iget-object v0, v2, Llyiahf/vczjk/zy5;->OooOOOO:Llyiahf/vczjk/ps5;

    invoke-virtual {v0}, Llyiahf/vczjk/ps5;->OooOO0o()V

    :cond_b
    sget-object v0, Llyiahf/vczjk/pv8;->OooO0o0:Llyiahf/vczjk/pv8;

    return-object v0

    :catchall_2
    move-exception v0

    :try_start_5
    monitor-exit v10

    throw v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    :goto_6
    monitor-exit v10

    throw v0

    :goto_7
    new-instance v0, Llyiahf/vczjk/ov8;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    return-object v0
.end method
