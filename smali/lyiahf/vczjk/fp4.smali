.class public final Llyiahf/vczjk/fp4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ce1;


# instance fields
.field public OooOOO:Llyiahf/vczjk/lg1;

.field public final OooOOO0:Llyiahf/vczjk/ro4;

.field public OooOOOO:Llyiahf/vczjk/g89;

.field public OooOOOo:I

.field public final OooOOo:Llyiahf/vczjk/js5;

.field public OooOOo0:I

.field public final OooOOoo:Llyiahf/vczjk/js5;

.field public final OooOo:Llyiahf/vczjk/js5;

.field public final OooOo0:Llyiahf/vczjk/wo4;

.field public final OooOo00:Llyiahf/vczjk/zo4;

.field public final OooOo0O:Llyiahf/vczjk/js5;

.field public final OooOo0o:Llyiahf/vczjk/f89;

.field public OooOoO:I

.field public final OooOoO0:Llyiahf/vczjk/ws5;

.field public OooOoOO:I

.field public final OooOoo0:Ljava/lang/String;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ro4;Llyiahf/vczjk/g89;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    iput-object p2, p0, Llyiahf/vczjk/fp4;->OooOOOO:Llyiahf/vczjk/g89;

    sget-object p1, Llyiahf/vczjk/y78;->OooO00o:[J

    new-instance p1, Llyiahf/vczjk/js5;

    invoke-direct {p1}, Llyiahf/vczjk/js5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fp4;->OooOOo:Llyiahf/vczjk/js5;

    new-instance p1, Llyiahf/vczjk/js5;

    invoke-direct {p1}, Llyiahf/vczjk/js5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fp4;->OooOOoo:Llyiahf/vczjk/js5;

    new-instance p1, Llyiahf/vczjk/zo4;

    invoke-direct {p1, p0}, Llyiahf/vczjk/zo4;-><init>(Llyiahf/vczjk/fp4;)V

    iput-object p1, p0, Llyiahf/vczjk/fp4;->OooOo00:Llyiahf/vczjk/zo4;

    new-instance p1, Llyiahf/vczjk/wo4;

    invoke-direct {p1, p0}, Llyiahf/vczjk/wo4;-><init>(Llyiahf/vczjk/fp4;)V

    iput-object p1, p0, Llyiahf/vczjk/fp4;->OooOo0:Llyiahf/vczjk/wo4;

    new-instance p1, Llyiahf/vczjk/js5;

    invoke-direct {p1}, Llyiahf/vczjk/js5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fp4;->OooOo0O:Llyiahf/vczjk/js5;

    new-instance p1, Llyiahf/vczjk/f89;

    invoke-direct {p1}, Llyiahf/vczjk/f89;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fp4;->OooOo0o:Llyiahf/vczjk/f89;

    new-instance p1, Llyiahf/vczjk/js5;

    invoke-direct {p1}, Llyiahf/vczjk/js5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fp4;->OooOo:Llyiahf/vczjk/js5;

    new-instance p1, Llyiahf/vczjk/ws5;

    const/16 p2, 0x10

    new-array p2, p2, [Ljava/lang/Object;

    invoke-direct {p1, p2}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/fp4;->OooOoO0:Llyiahf/vczjk/ws5;

    const-string p1, "Asking for intrinsic measurements of SubcomposeLayout layouts is not supported. This includes components that are built on top of SubcomposeLayout, such as lazy lists, BoxWithConstraints, TabRow, etc. To mitigate this:\n- if intrinsic measurements are used to achieve \'match parent\' sizing, consider replacing the parent of the component with a custom layout which controls the order in which children are measured, making intrinsic measurement not needed\n- adding a size modifier to the component, in order to fast return the queried intrinsic measurement."

    iput-object p1, p0, Llyiahf/vczjk/fp4;->OooOoo0:Ljava/lang/String;

    return-void
.end method

.method public static OooO0oo(Llyiahf/vczjk/sg1;Llyiahf/vczjk/ro4;ZLlyiahf/vczjk/lg1;Llyiahf/vczjk/a91;)Llyiahf/vczjk/sg1;
    .locals 1

    if-eqz p0, :cond_0

    iget-boolean v0, p0, Llyiahf/vczjk/sg1;->Oooo000:Z

    if-eqz v0, :cond_1

    :cond_0
    sget-object p0, Llyiahf/vczjk/osa;->OooO00o:Landroid/view/ViewGroup$LayoutParams;

    new-instance p0, Llyiahf/vczjk/ed5;

    invoke-direct {p0, p1}, Llyiahf/vczjk/ed5;-><init>(Llyiahf/vczjk/ro4;)V

    new-instance p1, Llyiahf/vczjk/sg1;

    invoke-direct {p1, p3, p0}, Llyiahf/vczjk/sg1;-><init>(Llyiahf/vczjk/lg1;Llyiahf/vczjk/ed5;)V

    move-object p0, p1

    :cond_1
    if-nez p2, :cond_2

    invoke-virtual {p0, p4}, Llyiahf/vczjk/sg1;->OooOO0(Llyiahf/vczjk/a91;)V

    return-object p0

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/sg1;->OooOooo:Llyiahf/vczjk/zf1;

    const/16 p2, 0x64

    iput p2, p1, Llyiahf/vczjk/zf1;->OooOoO0:I

    const/4 p3, 0x1

    iput-boolean p3, p1, Llyiahf/vczjk/zf1;->OooOo:Z

    invoke-virtual {p0, p4}, Llyiahf/vczjk/sg1;->OooOO0(Llyiahf/vczjk/a91;)V

    iget-boolean p3, p1, Llyiahf/vczjk/zf1;->OooOooo:Z

    if-nez p3, :cond_3

    iget p3, p1, Llyiahf/vczjk/zf1;->OooOoO0:I

    if-ne p3, p2, :cond_3

    goto :goto_0

    :cond_3
    const-string p2, "Cannot disable reuse from root if it was caused by other groups"

    invoke-static {p2}, Llyiahf/vczjk/v07;->OooO00o(Ljava/lang/String;)V

    :goto_0
    const/4 p2, -0x1

    iput p2, p1, Llyiahf/vczjk/zf1;->OooOoO0:I

    const/4 p2, 0x0

    iput-boolean p2, p1, Llyiahf/vczjk/zf1;->OooOo:Z

    return-object p0
.end method


# virtual methods
.method public final OooO()V
    .locals 1

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/fp4;->OooO0o0(Z)V

    return-void
.end method

.method public final OooO00o()V
    .locals 17

    move-object/from16 v0, p0

    iget-object v1, v0, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    const/4 v2, 0x1

    iput-boolean v2, v1, Llyiahf/vczjk/ro4;->OooOoo:Z

    iget-object v2, v0, Llyiahf/vczjk/fp4;->OooOOo:Llyiahf/vczjk/js5;

    iget-object v3, v2, Llyiahf/vczjk/js5;->OooO0OO:[Ljava/lang/Object;

    iget-object v4, v2, Llyiahf/vczjk/js5;->OooO00o:[J

    array-length v5, v4

    add-int/lit8 v5, v5, -0x2

    const/4 v6, 0x0

    if-ltz v5, :cond_3

    move v7, v6

    :goto_0
    aget-wide v8, v4, v7

    not-long v10, v8

    const/4 v12, 0x7

    shl-long/2addr v10, v12

    and-long/2addr v10, v8

    const-wide v12, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    and-long/2addr v10, v12

    cmp-long v10, v10, v12

    if-eqz v10, :cond_2

    sub-int v10, v7, v5

    not-int v10, v10

    ushr-int/lit8 v10, v10, 0x1f

    const/16 v11, 0x8

    rsub-int/lit8 v10, v10, 0x8

    move v12, v6

    :goto_1
    if-ge v12, v10, :cond_1

    const-wide/16 v13, 0xff

    and-long/2addr v13, v8

    const-wide/16 v15, 0x80

    cmp-long v13, v13, v15

    if-gez v13, :cond_0

    shl-int/lit8 v13, v7, 0x3

    add-int/2addr v13, v12

    aget-object v13, v3, v13

    check-cast v13, Llyiahf/vczjk/xo4;

    iget-object v13, v13, Llyiahf/vczjk/xo4;->OooO0OO:Llyiahf/vczjk/sg1;

    if-eqz v13, :cond_0

    invoke-virtual {v13}, Llyiahf/vczjk/sg1;->OooOO0o()V

    :cond_0
    shr-long/2addr v8, v11

    add-int/lit8 v12, v12, 0x1

    goto :goto_1

    :cond_1
    if-ne v10, v11, :cond_3

    :cond_2
    if-eq v7, v5, :cond_3

    add-int/lit8 v7, v7, 0x1

    goto :goto_0

    :cond_3
    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OoooO00()V

    iput-boolean v6, v1, Llyiahf/vczjk/ro4;->OooOoo:Z

    invoke-virtual {v2}, Llyiahf/vczjk/js5;->OooO00o()V

    iget-object v1, v0, Llyiahf/vczjk/fp4;->OooOOoo:Llyiahf/vczjk/js5;

    invoke-virtual {v1}, Llyiahf/vczjk/js5;->OooO00o()V

    iput v6, v0, Llyiahf/vczjk/fp4;->OooOoOO:I

    iput v6, v0, Llyiahf/vczjk/fp4;->OooOoO:I

    iget-object v1, v0, Llyiahf/vczjk/fp4;->OooOo0O:Llyiahf/vczjk/js5;

    invoke-virtual {v1}, Llyiahf/vczjk/js5;->OooO00o()V

    invoke-virtual {v0}, Llyiahf/vczjk/fp4;->OooO0Oo()V

    return-void
.end method

.method public final OooO0O0()V
    .locals 1

    const/4 v0, 0x1

    invoke-virtual {p0, v0}, Llyiahf/vczjk/fp4;->OooO0o0(Z)V

    return-void
.end method

.method public final OooO0OO(I)V
    .locals 13

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/fp4;->OooOoO:I

    iget-object v1, p0, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOOo0()Ljava/util/List;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/ts5;

    iget-object v3, v2, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    iget v3, v3, Llyiahf/vczjk/ws5;->OooOOOO:I

    iget v4, p0, Llyiahf/vczjk/fp4;->OooOoOO:I

    sub-int/2addr v3, v4

    const/4 v4, 0x1

    sub-int/2addr v3, v4

    if-gt p1, v3, :cond_7

    iget-object v5, p0, Llyiahf/vczjk/fp4;->OooOo0o:Llyiahf/vczjk/f89;

    invoke-virtual {v5}, Llyiahf/vczjk/f89;->clear()V

    if-gt p1, v3, :cond_0

    move v5, p1

    :goto_0
    invoke-virtual {v2, v5}, Llyiahf/vczjk/ts5;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/ro4;

    iget-object v7, p0, Llyiahf/vczjk/fp4;->OooOOo:Llyiahf/vczjk/js5;

    invoke-virtual {v7, v6}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    invoke-static {v6}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v6, Llyiahf/vczjk/xo4;

    iget-object v6, v6, Llyiahf/vczjk/xo4;->OooO00o:Ljava/lang/Object;

    iget-object v7, p0, Llyiahf/vczjk/fp4;->OooOo0o:Llyiahf/vczjk/f89;

    iget-object v7, v7, Llyiahf/vczjk/f89;->OooOOO0:Llyiahf/vczjk/bs5;

    invoke-virtual {v7, v6}, Llyiahf/vczjk/bs5;->OooO0O0(Ljava/lang/Object;)Z

    if-eq v5, v3, :cond_0

    add-int/lit8 v5, v5, 0x1

    goto :goto_0

    :cond_0
    iget-object v2, p0, Llyiahf/vczjk/fp4;->OooOOOO:Llyiahf/vczjk/g89;

    iget-object v5, p0, Llyiahf/vczjk/fp4;->OooOo0o:Llyiahf/vczjk/f89;

    invoke-interface {v2, v5}, Llyiahf/vczjk/g89;->o0ooOoO(Llyiahf/vczjk/f89;)V

    invoke-static {}, Llyiahf/vczjk/wr6;->OooOOO0()Llyiahf/vczjk/nv8;

    move-result-object v2

    if-eqz v2, :cond_1

    invoke-virtual {v2}, Llyiahf/vczjk/nv8;->OooO0o0()Llyiahf/vczjk/oe3;

    move-result-object v5

    goto :goto_1

    :cond_1
    const/4 v5, 0x0

    :goto_1
    invoke-static {v2}, Llyiahf/vczjk/wr6;->OooOOOo(Llyiahf/vczjk/nv8;)Llyiahf/vczjk/nv8;

    move-result-object v6

    move v7, v0

    :goto_2
    if-lt v3, p1, :cond_6

    :try_start_0
    move-object v8, v1

    check-cast v8, Llyiahf/vczjk/ts5;

    invoke-virtual {v8, v3}, Llyiahf/vczjk/ts5;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/ro4;

    iget-object v9, p0, Llyiahf/vczjk/fp4;->OooOOo:Llyiahf/vczjk/js5;

    invoke-virtual {v9, v8}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    invoke-static {v9}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v9, Llyiahf/vczjk/xo4;

    iget-object v10, v9, Llyiahf/vczjk/xo4;->OooO00o:Ljava/lang/Object;

    iget-object v11, p0, Llyiahf/vczjk/fp4;->OooOo0o:Llyiahf/vczjk/f89;

    iget-object v11, v11, Llyiahf/vczjk/f89;->OooOOO0:Llyiahf/vczjk/bs5;

    invoke-virtual {v11, v10}, Llyiahf/vczjk/lf6;->OooO00o(Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_3

    iget v11, p0, Llyiahf/vczjk/fp4;->OooOoO:I

    add-int/2addr v11, v4

    iput v11, p0, Llyiahf/vczjk/fp4;->OooOoO:I

    iget-object v11, v9, Llyiahf/vczjk/xo4;->OooO0o:Llyiahf/vczjk/qs5;

    check-cast v11, Llyiahf/vczjk/fw8;

    invoke-virtual {v11}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Ljava/lang/Boolean;

    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v11

    if-eqz v11, :cond_5

    iget-object v7, v8, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v8, v7, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    sget-object v11, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    iput-object v11, v8, Llyiahf/vczjk/kf5;->OooOo:Llyiahf/vczjk/no4;

    iget-object v7, v7, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-eqz v7, :cond_2

    iput-object v11, v7, Llyiahf/vczjk/w65;->OooOo0O:Llyiahf/vczjk/no4;

    :cond_2
    iget-object v7, v9, Llyiahf/vczjk/xo4;->OooO0o:Llyiahf/vczjk/qs5;

    sget-object v8, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    check-cast v7, Llyiahf/vczjk/fw8;

    invoke-virtual {v7, v8}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    move v7, v4

    goto :goto_3

    :catchall_0
    move-exception p1

    goto :goto_4

    :cond_3
    iget-object v11, p0, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    iput-boolean v4, v11, Llyiahf/vczjk/ro4;->OooOoo:Z

    iget-object v12, p0, Llyiahf/vczjk/fp4;->OooOOo:Llyiahf/vczjk/js5;

    invoke-virtual {v12, v8}, Llyiahf/vczjk/js5;->OooOO0(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v8, v9, Llyiahf/vczjk/xo4;->OooO0OO:Llyiahf/vczjk/sg1;

    if-eqz v8, :cond_4

    invoke-virtual {v8}, Llyiahf/vczjk/sg1;->OooOO0o()V

    :cond_4
    iget-object v8, p0, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v8, v3, v4}, Llyiahf/vczjk/ro4;->OoooO0(II)V

    iput-boolean v0, v11, Llyiahf/vczjk/ro4;->OooOoo:Z

    :cond_5
    :goto_3
    iget-object v8, p0, Llyiahf/vczjk/fp4;->OooOOoo:Llyiahf/vczjk/js5;

    invoke-virtual {v8, v10}, Llyiahf/vczjk/js5;->OooOO0(Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    add-int/lit8 v3, v3, -0x1

    goto :goto_2

    :goto_4
    invoke-static {v2, v6, v5}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    throw p1

    :cond_6
    invoke-static {v2, v6, v5}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    goto :goto_5

    :cond_7
    move v7, v0

    :goto_5
    if-eqz v7, :cond_9

    sget-object p1, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter p1

    :try_start_1
    sget-object v1, Llyiahf/vczjk/vv8;->OooO:Llyiahf/vczjk/li3;

    iget-object v1, v1, Llyiahf/vczjk/ps5;->OooO0oo:Llyiahf/vczjk/ks5;

    if-eqz v1, :cond_8

    invoke-virtual {v1}, Llyiahf/vczjk/a88;->OooO0OO()Z

    move-result v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-ne v1, v4, :cond_8

    move v0, v4

    goto :goto_6

    :catchall_1
    move-exception v0

    goto :goto_7

    :cond_8
    :goto_6
    monitor-exit p1

    if-eqz v0, :cond_9

    invoke-static {}, Llyiahf/vczjk/vv8;->OooO00o()V

    goto :goto_8

    :goto_7
    monitor-exit p1

    throw v0

    :cond_9
    :goto_8
    invoke-virtual {p0}, Llyiahf/vczjk/fp4;->OooO0Oo()V

    return-void
.end method

.method public final OooO0Oo()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOo0()Ljava/util/List;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ts5;

    iget-object v0, v0, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    iget-object v1, p0, Llyiahf/vczjk/fp4;->OooOOo:Llyiahf/vczjk/js5;

    iget v2, v1, Llyiahf/vczjk/js5;->OooO0o0:I

    if-ne v2, v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Inconsistency between the count of nodes tracked by the state ("

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget v1, v1, Llyiahf/vczjk/js5;->OooO0o0:I

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ") and the children count on the SubcomposeLayout ("

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, "). Are you trying to use the state of the disposed SubcomposeLayout?"

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/pz3;->OooO00o(Ljava/lang/String;)V

    :goto_0
    iget v1, p0, Llyiahf/vczjk/fp4;->OooOoO:I

    sub-int v1, v0, v1

    iget v2, p0, Llyiahf/vczjk/fp4;->OooOoOO:I

    sub-int/2addr v1, v2

    if-ltz v1, :cond_1

    goto :goto_1

    :cond_1
    const-string v1, "Incorrect state. Total children "

    const-string v2, ". Reusable children "

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/ii5;->OooOOO(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/fp4;->OooOoO:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ". Precomposed children "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Llyiahf/vczjk/fp4;->OooOoOO:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO00o(Ljava/lang/String;)V

    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/fp4;->OooOo0O:Llyiahf/vczjk/js5;

    iget v1, v0, Llyiahf/vczjk/js5;->OooO0o0:I

    iget v2, p0, Llyiahf/vczjk/fp4;->OooOoOO:I

    if-ne v1, v2, :cond_2

    return-void

    :cond_2
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Incorrect state. Precomposed children "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget v2, p0, Llyiahf/vczjk/fp4;->OooOoOO:I

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v2, ". Map size "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v0, v0, Llyiahf/vczjk/js5;->OooO0o0:I

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO00o(Ljava/lang/String;)V

    return-void
.end method

.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/z79;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->Oooo00o()Z

    move-result v1

    if-nez v1, :cond_0

    new-instance p1, Llyiahf/vczjk/cp4;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    return-object p1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/fp4;->OooO0Oo()V

    iget-object v1, p0, Llyiahf/vczjk/fp4;->OooOOoo:Llyiahf/vczjk/js5;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/js5;->OooO0OO(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/fp4;->OooOo:Llyiahf/vczjk/js5;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/js5;->OooOO0(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/fp4;->OooOo0O:Llyiahf/vczjk/js5;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_2

    invoke-virtual {p0, p1}, Llyiahf/vczjk/fp4;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/ro4;

    move-result-object v2

    const/4 v3, 0x0

    const/4 v4, 0x1

    if-eqz v2, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOo0()Ljava/util/List;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ts5;

    iget-object v5, v5, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/ws5;->OooO(Ljava/lang/Object;)I

    move-result v5

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOo0()Ljava/util/List;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/ts5;

    iget-object v6, v6, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    iget v6, v6, Llyiahf/vczjk/ws5;->OooOOOO:I

    iput-boolean v4, v0, Llyiahf/vczjk/ro4;->OooOoo:Z

    invoke-virtual {v0, v5, v6, v4}, Llyiahf/vczjk/ro4;->Oooo0o0(III)V

    iput-boolean v3, v0, Llyiahf/vczjk/ro4;->OooOoo:Z

    iget v0, p0, Llyiahf/vczjk/fp4;->OooOoOO:I

    add-int/2addr v0, v4

    iput v0, p0, Llyiahf/vczjk/fp4;->OooOoOO:I

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOo0()Ljava/util/List;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ts5;

    iget-object v2, v2, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    iget v2, v2, Llyiahf/vczjk/ws5;->OooOOOO:I

    new-instance v5, Llyiahf/vczjk/ro4;

    const/4 v6, 0x2

    invoke-direct {v5, v6}, Llyiahf/vczjk/ro4;-><init>(I)V

    iput-boolean v4, v0, Llyiahf/vczjk/ro4;->OooOoo:Z

    invoke-virtual {v0, v2, v5}, Llyiahf/vczjk/ro4;->OooOoo0(ILlyiahf/vczjk/ro4;)V

    iput-boolean v3, v0, Llyiahf/vczjk/ro4;->OooOoo:Z

    iget v0, p0, Llyiahf/vczjk/fp4;->OooOoOO:I

    add-int/2addr v0, v4

    iput v0, p0, Llyiahf/vczjk/fp4;->OooOoOO:I

    move-object v2, v5

    :goto_0
    invoke-virtual {v1, p1, v2}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_2
    check-cast v2, Llyiahf/vczjk/ro4;

    invoke-virtual {p0, v2, p1, p2}, Llyiahf/vczjk/fp4;->OooO0oO(Llyiahf/vczjk/ro4;Ljava/lang/Object;Llyiahf/vczjk/ze3;)V

    :cond_3
    new-instance p2, Llyiahf/vczjk/dp4;

    invoke-direct {p2, p0, p1}, Llyiahf/vczjk/dp4;-><init>(Llyiahf/vczjk/fp4;Ljava/lang/Object;)V

    return-object p2
.end method

.method public final OooO0o0(Z)V
    .locals 10

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/fp4;->OooOoOO:I

    iget-object v1, p0, Llyiahf/vczjk/fp4;->OooOo0O:Llyiahf/vczjk/js5;

    invoke-virtual {v1}, Llyiahf/vczjk/js5;->OooO00o()V

    iget-object v1, p0, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOOo0()Ljava/util/List;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/ts5;

    iget-object v2, v2, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    iget v2, v2, Llyiahf/vczjk/ws5;->OooOOOO:I

    iget v3, p0, Llyiahf/vczjk/fp4;->OooOoO:I

    if-eq v3, v2, :cond_6

    iput v2, p0, Llyiahf/vczjk/fp4;->OooOoO:I

    invoke-static {}, Llyiahf/vczjk/wr6;->OooOOO0()Llyiahf/vczjk/nv8;

    move-result-object v3

    if-eqz v3, :cond_0

    invoke-virtual {v3}, Llyiahf/vczjk/nv8;->OooO0o0()Llyiahf/vczjk/oe3;

    move-result-object v4

    goto :goto_0

    :cond_0
    const/4 v4, 0x0

    :goto_0
    invoke-static {v3}, Llyiahf/vczjk/wr6;->OooOOOo(Llyiahf/vczjk/nv8;)Llyiahf/vczjk/nv8;

    move-result-object v5

    :goto_1
    if-ge v0, v2, :cond_5

    :try_start_0
    move-object v6, v1

    check-cast v6, Llyiahf/vczjk/ts5;

    invoke-virtual {v6, v0}, Llyiahf/vczjk/ts5;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/ro4;

    iget-object v7, p0, Llyiahf/vczjk/fp4;->OooOOo:Llyiahf/vczjk/js5;

    invoke-virtual {v7, v6}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/xo4;

    if-eqz v7, :cond_4

    iget-object v8, v7, Llyiahf/vczjk/xo4;->OooO0o:Llyiahf/vczjk/qs5;

    check-cast v8, Llyiahf/vczjk/fw8;

    invoke-virtual {v8}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/Boolean;

    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v8

    if-eqz v8, :cond_4

    iget-object v6, v6, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v8, v6, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    sget-object v9, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    iput-object v9, v8, Llyiahf/vczjk/kf5;->OooOo:Llyiahf/vczjk/no4;

    iget-object v6, v6, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-eqz v6, :cond_1

    iput-object v9, v6, Llyiahf/vczjk/w65;->OooOo0O:Llyiahf/vczjk/no4;

    :cond_1
    if-eqz p1, :cond_3

    iget-object v6, v7, Llyiahf/vczjk/xo4;->OooO0OO:Llyiahf/vczjk/sg1;

    if-eqz v6, :cond_2

    invoke-virtual {v6}, Llyiahf/vczjk/sg1;->OooOO0O()V

    :cond_2
    sget-object v6, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v6}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v6

    iput-object v6, v7, Llyiahf/vczjk/xo4;->OooO0o:Llyiahf/vczjk/qs5;

    goto :goto_2

    :catchall_0
    move-exception p1

    goto :goto_3

    :cond_3
    iget-object v6, v7, Llyiahf/vczjk/xo4;->OooO0o:Llyiahf/vczjk/qs5;

    sget-object v8, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    check-cast v6, Llyiahf/vczjk/fw8;

    invoke-virtual {v6, v8}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :goto_2
    sget-object v6, Llyiahf/vczjk/e16;->OooO0oO:Llyiahf/vczjk/op3;

    iput-object v6, v7, Llyiahf/vczjk/xo4;->OooO00o:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_4
    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    :goto_3
    invoke-static {v3, v5, v4}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    throw p1

    :cond_5
    invoke-static {v3, v5, v4}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    iget-object p1, p0, Llyiahf/vczjk/fp4;->OooOOoo:Llyiahf/vczjk/js5;

    invoke-virtual {p1}, Llyiahf/vczjk/js5;->OooO00o()V

    :cond_6
    invoke-virtual {p0}, Llyiahf/vczjk/fp4;->OooO0Oo()V

    return-void
.end method

.method public final OooO0oO(Llyiahf/vczjk/ro4;Ljava/lang/Object;Llyiahf/vczjk/ze3;)V
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/fp4;->OooOOo:Llyiahf/vczjk/js5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    const/4 v2, 0x0

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/xo4;

    sget-object v3, Llyiahf/vczjk/dd1;->OooO00o:Llyiahf/vczjk/a91;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    iput-object p2, v1, Llyiahf/vczjk/xo4;->OooO00o:Ljava/lang/Object;

    iput-object v3, v1, Llyiahf/vczjk/xo4;->OooO0O0:Llyiahf/vczjk/ze3;

    iput-object v2, v1, Llyiahf/vczjk/xo4;->OooO0OO:Llyiahf/vczjk/sg1;

    sget-object p2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {p2}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p2

    iput-object p2, v1, Llyiahf/vczjk/xo4;->OooO0o:Llyiahf/vczjk/qs5;

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_0
    check-cast v1, Llyiahf/vczjk/xo4;

    iget-object p2, v1, Llyiahf/vczjk/xo4;->OooO0OO:Llyiahf/vczjk/sg1;

    const/4 v0, 0x0

    const/4 v3, 0x1

    if-eqz p2, :cond_2

    iget-object v4, p2, Llyiahf/vczjk/sg1;->OooOOOo:Ljava/lang/Object;

    monitor-enter v4

    :try_start_0
    iget-object p2, p2, Llyiahf/vczjk/sg1;->OooOoO:Llyiahf/vczjk/js5;

    iget p2, p2, Llyiahf/vczjk/js5;->OooO0o0:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-lez p2, :cond_1

    move p2, v3

    goto :goto_0

    :cond_1
    move p2, v0

    :goto_0
    monitor-exit v4

    goto :goto_1

    :catchall_0
    move-exception p1

    monitor-exit v4

    throw p1

    :cond_2
    move p2, v3

    :goto_1
    iget-object v4, v1, Llyiahf/vczjk/xo4;->OooO0O0:Llyiahf/vczjk/ze3;

    if-ne v4, p3, :cond_4

    if-nez p2, :cond_4

    iget-boolean p2, v1, Llyiahf/vczjk/xo4;->OooO0Oo:Z

    if-eqz p2, :cond_3

    goto :goto_2

    :cond_3
    return-void

    :cond_4
    :goto_2
    iput-object p3, v1, Llyiahf/vczjk/xo4;->OooO0O0:Llyiahf/vczjk/ze3;

    invoke-static {}, Llyiahf/vczjk/wr6;->OooOOO0()Llyiahf/vczjk/nv8;

    move-result-object p2

    if-eqz p2, :cond_5

    invoke-virtual {p2}, Llyiahf/vczjk/nv8;->OooO0o0()Llyiahf/vczjk/oe3;

    move-result-object v2

    :cond_5
    invoke-static {p2}, Llyiahf/vczjk/wr6;->OooOOOo(Llyiahf/vczjk/nv8;)Llyiahf/vczjk/nv8;

    move-result-object p3

    :try_start_1
    iget-object v4, p0, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    iput-boolean v3, v4, Llyiahf/vczjk/ro4;->OooOoo:Z

    iget-object v5, v1, Llyiahf/vczjk/xo4;->OooO0O0:Llyiahf/vczjk/ze3;

    iget-object v6, v1, Llyiahf/vczjk/xo4;->OooO0OO:Llyiahf/vczjk/sg1;

    iget-object v7, p0, Llyiahf/vczjk/fp4;->OooOOO:Llyiahf/vczjk/lg1;

    if-eqz v7, :cond_6

    iget-boolean v8, v1, Llyiahf/vczjk/xo4;->OooO0o0:Z

    new-instance v9, Llyiahf/vczjk/ep4;

    invoke-direct {v9, v1, v5}, Llyiahf/vczjk/ep4;-><init>(Llyiahf/vczjk/xo4;Llyiahf/vczjk/ze3;)V

    new-instance v5, Llyiahf/vczjk/a91;

    const v10, -0x68551fe9

    invoke-direct {v5, v10, v9, v3}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-static {v6, p1, v8, v7, v5}, Llyiahf/vczjk/fp4;->OooO0oo(Llyiahf/vczjk/sg1;Llyiahf/vczjk/ro4;ZLlyiahf/vczjk/lg1;Llyiahf/vczjk/a91;)Llyiahf/vczjk/sg1;

    move-result-object p1

    iput-object p1, v1, Llyiahf/vczjk/xo4;->OooO0OO:Llyiahf/vczjk/sg1;

    iput-boolean v0, v1, Llyiahf/vczjk/xo4;->OooO0o0:Z

    iput-boolean v0, v4, Llyiahf/vczjk/ro4;->OooOoo:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    invoke-static {p2, p3, v2}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    iput-boolean v0, v1, Llyiahf/vczjk/xo4;->OooO0Oo:Z

    return-void

    :catchall_1
    move-exception p1

    goto :goto_3

    :cond_6
    :try_start_2
    const-string p1, "parent composition reference not set"

    invoke-static {p1}, Llyiahf/vczjk/pz3;->OooO0OO(Ljava/lang/String;)Ljava/lang/Void;

    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :goto_3
    invoke-static {p2, p3, v2}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    throw p1
.end method

.method public final OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/ro4;
    .locals 11

    iget v0, p0, Llyiahf/vczjk/fp4;->OooOoO:I

    if-nez v0, :cond_0

    goto/16 :goto_5

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOo0()Ljava/util/List;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ts5;

    iget-object v2, v1, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    iget v2, v2, Llyiahf/vczjk/ws5;->OooOOOO:I

    iget v3, p0, Llyiahf/vczjk/fp4;->OooOoOO:I

    sub-int/2addr v2, v3

    iget v3, p0, Llyiahf/vczjk/fp4;->OooOoO:I

    sub-int v3, v2, v3

    const/4 v4, 0x1

    sub-int/2addr v2, v4

    move v5, v2

    :goto_0
    iget-object v6, p0, Llyiahf/vczjk/fp4;->OooOOo:Llyiahf/vczjk/js5;

    const/4 v7, -0x1

    if-lt v5, v3, :cond_2

    invoke-virtual {v1, v5}, Llyiahf/vczjk/ts5;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/ro4;

    invoke-virtual {v6, v8}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v8, Llyiahf/vczjk/xo4;

    iget-object v8, v8, Llyiahf/vczjk/xo4;->OooO00o:Ljava/lang/Object;

    invoke-static {v8, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_1

    move v8, v5

    goto :goto_1

    :cond_1
    add-int/lit8 v5, v5, -0x1

    goto :goto_0

    :cond_2
    move v8, v7

    :goto_1
    if-ne v8, v7, :cond_6

    :goto_2
    if-lt v2, v3, :cond_5

    invoke-virtual {v1, v2}, Llyiahf/vczjk/ts5;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ro4;

    invoke-virtual {v6, v5}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v5, Llyiahf/vczjk/xo4;

    iget-object v9, v5, Llyiahf/vczjk/xo4;->OooO00o:Ljava/lang/Object;

    sget-object v10, Llyiahf/vczjk/e16;->OooO0oO:Llyiahf/vczjk/op3;

    if-eq v9, v10, :cond_4

    iget-object v10, p0, Llyiahf/vczjk/fp4;->OooOOOO:Llyiahf/vczjk/g89;

    invoke-interface {v10, p1, v9}, Llyiahf/vczjk/g89;->Oooo0OO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_3

    goto :goto_3

    :cond_3
    add-int/lit8 v2, v2, -0x1

    goto :goto_2

    :cond_4
    :goto_3
    iput-object p1, v5, Llyiahf/vczjk/xo4;->OooO00o:Ljava/lang/Object;

    move v5, v2

    move v8, v5

    goto :goto_4

    :cond_5
    move v5, v2

    :cond_6
    :goto_4
    if-ne v8, v7, :cond_7

    :goto_5
    const/4 p1, 0x0

    return-object p1

    :cond_7
    if-eq v5, v3, :cond_8

    iput-boolean v4, v0, Llyiahf/vczjk/ro4;->OooOoo:Z

    invoke-virtual {v0, v5, v3, v4}, Llyiahf/vczjk/ro4;->Oooo0o0(III)V

    const/4 p1, 0x0

    iput-boolean p1, v0, Llyiahf/vczjk/ro4;->OooOoo:Z

    :cond_8
    iget p1, p0, Llyiahf/vczjk/fp4;->OooOoO:I

    add-int/2addr p1, v7

    iput p1, p0, Llyiahf/vczjk/fp4;->OooOoO:I

    invoke-virtual {v1, v3}, Llyiahf/vczjk/ts5;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ro4;

    invoke-virtual {v6, p1}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v0, Llyiahf/vczjk/xo4;

    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {v1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/xo4;->OooO0o:Llyiahf/vczjk/qs5;

    iput-boolean v4, v0, Llyiahf/vczjk/xo4;->OooO0o0:Z

    iput-boolean v4, v0, Llyiahf/vczjk/xo4;->OooO0Oo:Z

    return-object p1
.end method
