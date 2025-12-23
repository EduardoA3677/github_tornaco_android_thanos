.class public final Llyiahf/vczjk/bo3;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/xn4;

.field public OooO0O0:Z

.field public OooO0OO:Z

.field public OooO0Oo:Z

.field public final OooO0o:Llyiahf/vczjk/as5;

.field public OooO0o0:Z

.field public final OooO0oO:Llyiahf/vczjk/d26;

.field public final OooO0oo:Llyiahf/vczjk/vr5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xn4;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bo3;->OooO00o:Llyiahf/vczjk/xn4;

    new-instance p1, Llyiahf/vczjk/as5;

    invoke-direct {p1}, Llyiahf/vczjk/as5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bo3;->OooO0o:Llyiahf/vczjk/as5;

    new-instance p1, Llyiahf/vczjk/d26;

    invoke-direct {p1}, Llyiahf/vczjk/d26;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bo3;->OooO0oO:Llyiahf/vczjk/d26;

    new-instance p1, Llyiahf/vczjk/vr5;

    const/16 v0, 0xa

    invoke-direct {p1, v0}, Llyiahf/vczjk/vr5;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/bo3;->OooO0oo:Llyiahf/vczjk/vr5;

    return-void
.end method


# virtual methods
.method public final OooO00o(JLjava/util/List;Z)V
    .locals 17

    move-object/from16 v0, p0

    move-wide/from16 v1, p1

    iget-object v3, v0, Llyiahf/vczjk/bo3;->OooO0oO:Llyiahf/vczjk/d26;

    iget-object v4, v0, Llyiahf/vczjk/bo3;->OooO0oo:Llyiahf/vczjk/vr5;

    invoke-virtual {v4}, Llyiahf/vczjk/vr5;->OooO00o()V

    invoke-interface/range {p3 .. p3}, Ljava/util/Collection;->size()I

    move-result v5

    const/4 v6, 0x1

    move-object v10, v3

    move v9, v6

    const/4 v8, 0x0

    :goto_0
    if-ge v8, v5, :cond_7

    move-object/from16 v11, p3

    invoke-interface {v11, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/jl5;

    iget-boolean v13, v12, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v13, :cond_6

    new-instance v13, Llyiahf/vczjk/ao3;

    invoke-direct {v13, v0, v12}, Llyiahf/vczjk/ao3;-><init>(Llyiahf/vczjk/bo3;Llyiahf/vczjk/jl5;)V

    iput-object v13, v12, Llyiahf/vczjk/jl5;->OooOoO0:Llyiahf/vczjk/ao3;

    if-eqz v9, :cond_4

    iget-object v13, v10, Llyiahf/vczjk/d26;->OooO00o:Llyiahf/vczjk/ws5;

    iget-object v14, v13, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v13, v13, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v15, 0x0

    :goto_1
    if-ge v15, v13, :cond_1

    aget-object v16, v14, v15

    move-object/from16 v7, v16

    check-cast v7, Llyiahf/vczjk/j16;

    iget-object v7, v7, Llyiahf/vczjk/j16;->OooO0OO:Llyiahf/vczjk/jl5;

    invoke-static {v7, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_0

    goto :goto_2

    :cond_0
    add-int/lit8 v15, v15, 0x1

    goto :goto_1

    :cond_1
    const/16 v16, 0x0

    :goto_2
    move-object/from16 v7, v16

    check-cast v7, Llyiahf/vczjk/j16;

    if-eqz v7, :cond_3

    iput-boolean v6, v7, Llyiahf/vczjk/j16;->OooO:Z

    iget-object v10, v7, Llyiahf/vczjk/j16;->OooO0Oo:Llyiahf/vczjk/w3;

    invoke-virtual {v10, v1, v2}, Llyiahf/vczjk/w3;->OooO00o(J)V

    invoke-virtual {v4, v1, v2}, Llyiahf/vczjk/vr5;->OooO0Oo(J)Ljava/lang/Object;

    move-result-object v10

    if-nez v10, :cond_2

    new-instance v10, Llyiahf/vczjk/as5;

    invoke-direct {v10}, Llyiahf/vczjk/as5;-><init>()V

    invoke-virtual {v4, v1, v2, v10}, Llyiahf/vczjk/vr5;->OooO0oO(JLjava/lang/Object;)V

    :cond_2
    check-cast v10, Llyiahf/vczjk/as5;

    invoke-virtual {v10, v7}, Llyiahf/vczjk/as5;->OooO0oO(Ljava/lang/Object;)V

    :goto_3
    move-object v10, v7

    goto :goto_4

    :cond_3
    const/4 v9, 0x0

    :cond_4
    new-instance v7, Llyiahf/vczjk/j16;

    invoke-direct {v7, v12}, Llyiahf/vczjk/j16;-><init>(Llyiahf/vczjk/jl5;)V

    iget-object v12, v7, Llyiahf/vczjk/j16;->OooO0Oo:Llyiahf/vczjk/w3;

    invoke-virtual {v12, v1, v2}, Llyiahf/vczjk/w3;->OooO00o(J)V

    invoke-virtual {v4, v1, v2}, Llyiahf/vczjk/vr5;->OooO0Oo(J)Ljava/lang/Object;

    move-result-object v12

    if-nez v12, :cond_5

    new-instance v12, Llyiahf/vczjk/as5;

    invoke-direct {v12}, Llyiahf/vczjk/as5;-><init>()V

    invoke-virtual {v4, v1, v2, v12}, Llyiahf/vczjk/vr5;->OooO0oO(JLjava/lang/Object;)V

    :cond_5
    check-cast v12, Llyiahf/vczjk/as5;

    invoke-virtual {v12, v7}, Llyiahf/vczjk/as5;->OooO0oO(Ljava/lang/Object;)V

    iget-object v10, v10, Llyiahf/vczjk/d26;->OooO00o:Llyiahf/vczjk/ws5;

    invoke-virtual {v10, v7}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_6
    :goto_4
    add-int/lit8 v8, v8, 0x1

    goto :goto_0

    :cond_7
    if-eqz p4, :cond_c

    iget-object v1, v4, Llyiahf/vczjk/vr5;->OooO0O0:[J

    iget-object v2, v4, Llyiahf/vczjk/vr5;->OooO0OO:[Ljava/lang/Object;

    iget-object v4, v4, Llyiahf/vczjk/vr5;->OooO00o:[J

    array-length v5, v4

    add-int/lit8 v5, v5, -0x2

    if-ltz v5, :cond_c

    const/4 v6, 0x0

    :goto_5
    aget-wide v7, v4, v6

    not-long v9, v7

    const/4 v11, 0x7

    shl-long/2addr v9, v11

    and-long/2addr v9, v7

    const-wide v11, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    and-long/2addr v9, v11

    cmp-long v9, v9, v11

    if-eqz v9, :cond_b

    sub-int v9, v6, v5

    not-int v9, v9

    ushr-int/lit8 v9, v9, 0x1f

    const/16 v10, 0x8

    rsub-int/lit8 v9, v9, 0x8

    const/4 v11, 0x0

    :goto_6
    if-ge v11, v9, :cond_a

    const-wide/16 v12, 0xff

    and-long/2addr v12, v7

    const-wide/16 v14, 0x80

    cmp-long v12, v12, v14

    if-gez v12, :cond_8

    shl-int/lit8 v12, v6, 0x3

    add-int/2addr v12, v11

    aget-wide v13, v1, v12

    aget-object v12, v2, v12

    check-cast v12, Llyiahf/vczjk/as5;

    iget-object v15, v3, Llyiahf/vczjk/d26;->OooO00o:Llyiahf/vczjk/ws5;

    move/from16 p1, v10

    iget-object v10, v15, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v15, v15, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v0, 0x0

    :goto_7
    if-ge v0, v15, :cond_9

    aget-object v16, v10, v0

    move/from16 p2, v0

    move-object/from16 v0, v16

    check-cast v0, Llyiahf/vczjk/j16;

    invoke-virtual {v0, v13, v14, v12}, Llyiahf/vczjk/j16;->OooO0o(JLlyiahf/vczjk/as5;)V

    add-int/lit8 v0, p2, 0x1

    goto :goto_7

    :cond_8
    move/from16 p1, v10

    :cond_9
    shr-long v7, v7, p1

    add-int/lit8 v11, v11, 0x1

    move-object/from16 v0, p0

    move/from16 v10, p1

    goto :goto_6

    :cond_a
    move v0, v10

    if-ne v9, v0, :cond_c

    :cond_b
    if-eq v6, v5, :cond_c

    add-int/lit8 v6, v6, 0x1

    move-object/from16 v0, p0

    goto :goto_5

    :cond_c
    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/hl1;Z)Z
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/bo3;->OooO0oO:Llyiahf/vczjk/d26;

    iget-object v1, p1, Llyiahf/vczjk/hl1;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/i65;

    iget-object v2, p0, Llyiahf/vczjk/bo3;->OooO00o:Llyiahf/vczjk/xn4;

    invoke-virtual {v0, v1, v2, p1, p2}, Llyiahf/vczjk/d26;->OooO00o(Llyiahf/vczjk/i65;Llyiahf/vczjk/xn4;Llyiahf/vczjk/hl1;Z)Z

    move-result v1

    const/4 v2, 0x0

    if-nez v1, :cond_0

    return v2

    :cond_0
    const/4 v1, 0x1

    iput-boolean v1, p0, Llyiahf/vczjk/bo3;->OooO0O0:Z

    iget-object v3, v0, Llyiahf/vczjk/d26;->OooO00o:Llyiahf/vczjk/ws5;

    iget-object v4, v3, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v5, v3, Llyiahf/vczjk/ws5;->OooOOOO:I

    move v6, v2

    move v7, v6

    :goto_0
    if-ge v6, v5, :cond_3

    aget-object v8, v4, v6

    check-cast v8, Llyiahf/vczjk/j16;

    invoke-virtual {v8, p1, p2}, Llyiahf/vczjk/j16;->OooO0o0(Llyiahf/vczjk/hl1;Z)Z

    move-result v8

    if-nez v8, :cond_2

    if-eqz v7, :cond_1

    goto :goto_1

    :cond_1
    move v7, v2

    goto :goto_2

    :cond_2
    :goto_1
    move v7, v1

    :goto_2
    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    :cond_3
    iget-object p2, v3, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v3, v3, Llyiahf/vczjk/ws5;->OooOOOO:I

    move v4, v2

    move v5, v4

    :goto_3
    if-ge v4, v3, :cond_6

    aget-object v6, p2, v4

    check-cast v6, Llyiahf/vczjk/j16;

    invoke-virtual {v6, p1}, Llyiahf/vczjk/j16;->OooO0Oo(Llyiahf/vczjk/hl1;)Z

    move-result v6

    if-nez v6, :cond_5

    if-eqz v5, :cond_4

    goto :goto_4

    :cond_4
    move v5, v2

    goto :goto_5

    :cond_5
    :goto_4
    move v5, v1

    :goto_5
    add-int/lit8 v4, v4, 0x1

    goto :goto_3

    :cond_6
    invoke-virtual {v0, p1}, Llyiahf/vczjk/d26;->OooO0O0(Llyiahf/vczjk/hl1;)V

    if-nez v5, :cond_8

    if-eqz v7, :cond_7

    goto :goto_6

    :cond_7
    move v1, v2

    :cond_8
    :goto_6
    iput-boolean v2, p0, Llyiahf/vczjk/bo3;->OooO0O0:Z

    iget-boolean p1, p0, Llyiahf/vczjk/bo3;->OooO0o0:Z

    if-eqz p1, :cond_a

    iput-boolean v2, p0, Llyiahf/vczjk/bo3;->OooO0o0:Z

    iget-object p1, p0, Llyiahf/vczjk/bo3;->OooO0o:Llyiahf/vczjk/as5;

    iget p2, p1, Llyiahf/vczjk/c76;->OooO0O0:I

    move v3, v2

    :goto_7
    if-ge v3, p2, :cond_9

    invoke-virtual {p1, v3}, Llyiahf/vczjk/c76;->OooO0O0(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/jl5;

    invoke-virtual {p0, v4}, Llyiahf/vczjk/bo3;->OooO0Oo(Llyiahf/vczjk/jl5;)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_7

    :cond_9
    invoke-virtual {p1}, Llyiahf/vczjk/as5;->OooO()V

    :cond_a
    iget-boolean p1, p0, Llyiahf/vczjk/bo3;->OooO0OO:Z

    if-eqz p1, :cond_b

    iput-boolean v2, p0, Llyiahf/vczjk/bo3;->OooO0OO:Z

    invoke-virtual {p0}, Llyiahf/vczjk/bo3;->OooO0OO()V

    :cond_b
    iget-boolean p1, p0, Llyiahf/vczjk/bo3;->OooO0Oo:Z

    if-eqz p1, :cond_c

    iput-boolean v2, p0, Llyiahf/vczjk/bo3;->OooO0Oo:Z

    iget-object p1, v0, Llyiahf/vczjk/d26;->OooO00o:Llyiahf/vczjk/ws5;

    invoke-virtual {p1}, Llyiahf/vczjk/ws5;->OooO0oO()V

    :cond_c
    return v1
.end method

.method public final OooO0OO()V
    .locals 6

    iget-boolean v0, p0, Llyiahf/vczjk/bo3;->OooO0O0:Z

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    iput-boolean v1, p0, Llyiahf/vczjk/bo3;->OooO0OO:Z

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/bo3;->OooO0oO:Llyiahf/vczjk/d26;

    iget-object v2, v0, Llyiahf/vczjk/d26;->OooO00o:Llyiahf/vczjk/ws5;

    iget-object v3, v2, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v2, v2, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v4, 0x0

    :goto_0
    if-ge v4, v2, :cond_1

    aget-object v5, v3, v4

    check-cast v5, Llyiahf/vczjk/j16;

    invoke-virtual {v5}, Llyiahf/vczjk/j16;->OooO0OO()V

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_1
    iget-boolean v2, p0, Llyiahf/vczjk/bo3;->OooO0Oo:Z

    if-eqz v2, :cond_2

    iput-boolean v1, p0, Llyiahf/vczjk/bo3;->OooO0Oo:Z

    return-void

    :cond_2
    iget-object v0, v0, Llyiahf/vczjk/d26;->OooO00o:Llyiahf/vczjk/ws5;

    invoke-virtual {v0}, Llyiahf/vczjk/ws5;->OooO0oO()V

    return-void
.end method

.method public final OooO0Oo(Llyiahf/vczjk/jl5;)V
    .locals 6

    iget-boolean v0, p0, Llyiahf/vczjk/bo3;->OooO0O0:Z

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    iput-boolean v1, p0, Llyiahf/vczjk/bo3;->OooO0o0:Z

    iget-object v0, p0, Llyiahf/vczjk/bo3;->OooO0o:Llyiahf/vczjk/as5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/as5;->OooO0oO(Ljava/lang/Object;)V

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/bo3;->OooO0oO:Llyiahf/vczjk/d26;

    iget-object v2, v0, Llyiahf/vczjk/d26;->OooO0O0:Llyiahf/vczjk/as5;

    invoke-virtual {v2}, Llyiahf/vczjk/as5;->OooO()V

    invoke-virtual {v2, v0}, Llyiahf/vczjk/as5;->OooO0oO(Ljava/lang/Object;)V

    :cond_1
    invoke-virtual {v2}, Llyiahf/vczjk/c76;->OooO0o0()Z

    move-result v0

    if-eqz v0, :cond_3

    iget v0, v2, Llyiahf/vczjk/c76;->OooO0O0:I

    sub-int/2addr v0, v1

    invoke-virtual {v2, v0}, Llyiahf/vczjk/as5;->OooOO0O(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/d26;

    const/4 v3, 0x0

    :goto_0
    iget-object v4, v0, Llyiahf/vczjk/d26;->OooO00o:Llyiahf/vczjk/ws5;

    iget v5, v4, Llyiahf/vczjk/ws5;->OooOOOO:I

    if-ge v3, v5, :cond_1

    iget-object v4, v4, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v4, v4, v3

    check-cast v4, Llyiahf/vczjk/j16;

    iget-object v5, v4, Llyiahf/vczjk/j16;->OooO0OO:Llyiahf/vczjk/jl5;

    invoke-static {v5, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    iget-object v5, v0, Llyiahf/vczjk/d26;->OooO00o:Llyiahf/vczjk/ws5;

    invoke-virtual {v5, v4}, Llyiahf/vczjk/ws5;->OooOO0(Ljava/lang/Object;)Z

    invoke-virtual {v4}, Llyiahf/vczjk/j16;->OooO0OO()V

    goto :goto_0

    :cond_2
    invoke-virtual {v2, v4}, Llyiahf/vczjk/as5;->OooO0oO(Ljava/lang/Object;)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_3
    return-void
.end method
