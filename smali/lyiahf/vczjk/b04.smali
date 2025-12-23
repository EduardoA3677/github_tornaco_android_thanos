.class public final Llyiahf/vczjk/b04;
.super Llyiahf/vczjk/v16;
.source "SourceFile"


# static fields
.field public static final Ooooo00:Llyiahf/vczjk/ie;


# instance fields
.field public final OoooOoO:Llyiahf/vczjk/cf9;

.field public OoooOoo:Llyiahf/vczjk/a04;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    invoke-static {}, Llyiahf/vczjk/c6a;->OooOOoo()Llyiahf/vczjk/ie;

    move-result-object v0

    sget v1, Llyiahf/vczjk/n21;->OooOO0O:I

    sget-wide v1, Llyiahf/vczjk/n21;->OooO0oO:J

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/ie;->OooOOOo(J)V

    const/high16 v1, 0x3f800000    # 1.0f

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ie;->OooOo0O(F)V

    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ie;->OooOo0o(I)V

    sput-object v0, Llyiahf/vczjk/b04;->Ooooo00:Llyiahf/vczjk/ie;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ro4;)V
    .locals 2

    invoke-direct {p0, p1}, Llyiahf/vczjk/v16;-><init>(Llyiahf/vczjk/ro4;)V

    new-instance v0, Llyiahf/vczjk/cf9;

    invoke-direct {v0}, Llyiahf/vczjk/jl5;-><init>()V

    const/4 v1, 0x0

    iput v1, v0, Llyiahf/vczjk/jl5;->OooOOOo:I

    iput-object v0, p0, Llyiahf/vczjk/b04;->OoooOoO:Llyiahf/vczjk/cf9;

    iput-object p0, v0, Llyiahf/vczjk/jl5;->OooOo00:Llyiahf/vczjk/v16;

    iget-object p1, p1, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    if-eqz p1, :cond_0

    new-instance p1, Llyiahf/vczjk/a04;

    invoke-direct {p1, p0}, Llyiahf/vczjk/q65;-><init>(Llyiahf/vczjk/v16;)V

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/b04;->OoooOoo:Llyiahf/vczjk/a04;

    return-void
.end method


# virtual methods
.method public final OooO0OO(I)I
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0()Llyiahf/vczjk/era;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/era;->Oooo0OO()Llyiahf/vczjk/lf5;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ro4;

    iget-object v2, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v2, v2, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/v16;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOO()Ljava/util/List;

    move-result-object v0

    invoke-interface {v1, v2, v0, p1}, Llyiahf/vczjk/lf5;->OooO(Llyiahf/vczjk/o34;Ljava/util/List;I)I

    move-result p1

    return p1
.end method

.method public final OooOo0(I)I
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0()Llyiahf/vczjk/era;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/era;->Oooo0OO()Llyiahf/vczjk/lf5;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ro4;

    iget-object v2, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v2, v2, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/v16;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOO()Ljava/util/List;

    move-result-object v0

    invoke-interface {v1, v2, v0, p1}, Llyiahf/vczjk/lf5;->OooO0Oo(Llyiahf/vczjk/o34;Ljava/util/List;I)I

    move-result p1

    return p1
.end method

.method public final OooOo0o(I)I
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0()Llyiahf/vczjk/era;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/era;->Oooo0OO()Llyiahf/vczjk/lf5;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ro4;

    iget-object v2, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v2, v2, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/v16;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOO()Ljava/util/List;

    move-result-object v0

    invoke-interface {v1, v2, v0, p1}, Llyiahf/vczjk/lf5;->OooO0o(Llyiahf/vczjk/o34;Ljava/util/List;I)I

    move-result p1

    return p1
.end method

.method public final OooOoOO(J)Llyiahf/vczjk/ow6;
    .locals 6

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ow6;->oo000o(J)V

    iget-object v0, p0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v1

    iget-object v2, v1, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v1, v1, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v1, :cond_0

    aget-object v4, v2, v3

    check-cast v4, Llyiahf/vczjk/ro4;

    iget-object v4, v4, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v4, v4, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    sget-object v5, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    iput-object v5, v4, Llyiahf/vczjk/kf5;->OooOo:Llyiahf/vczjk/no4;

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/ro4;->Oooo0:Llyiahf/vczjk/lf5;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOO()Ljava/util/List;

    move-result-object v0

    invoke-interface {v1, p0, v0, p1, p2}, Llyiahf/vczjk/lf5;->OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/v16;->o000(Llyiahf/vczjk/mf5;)V

    invoke-virtual {p0}, Llyiahf/vczjk/v16;->o0000o()V

    return-object p0
.end method

.method public final OooooO0(I)I
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0()Llyiahf/vczjk/era;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/era;->Oooo0OO()Llyiahf/vczjk/lf5;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ro4;

    iget-object v2, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v2, v2, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/v16;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOO()Ljava/util/List;

    move-result-object v0

    invoke-interface {v1, v2, v0, p1}, Llyiahf/vczjk/lf5;->OooOO0(Llyiahf/vczjk/o34;Ljava/util/List;I)I

    move-result p1

    return p1
.end method

.method public final o0000()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b04;->OoooOoo:Llyiahf/vczjk/a04;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/a04;

    invoke-direct {v0, p0}, Llyiahf/vczjk/q65;-><init>(Llyiahf/vczjk/v16;)V

    iput-object v0, p0, Llyiahf/vczjk/b04;->OoooOoo:Llyiahf/vczjk/a04;

    :cond_0
    return-void
.end method

.method public final o0000O0()Llyiahf/vczjk/q65;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b04;->OoooOoo:Llyiahf/vczjk/a04;

    return-object v0
.end method

.method public final o0000Oo0(Llyiahf/vczjk/o16;JLlyiahf/vczjk/eo3;IZ)V
    .locals 17

    move-object/from16 v0, p0

    move-wide/from16 v3, p2

    move-object/from16 v5, p4

    iget-object v1, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    move-object/from16 v2, p1

    invoke-interface {v2, v1}, Llyiahf/vczjk/o16;->OooOO0(Llyiahf/vczjk/ro4;)Z

    move-result v6

    const/4 v8, 0x1

    const/4 v9, 0x0

    if-eqz v6, :cond_1

    invoke-virtual {v0, v3, v4}, Llyiahf/vczjk/v16;->o000Oo0(J)Z

    move-result v6

    if-eqz v6, :cond_0

    move/from16 v6, p5

    move/from16 v7, p6

    move v10, v8

    goto :goto_0

    :cond_0
    move/from16 v6, p5

    if-ne v6, v8, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->o0000O0O()J

    move-result-wide v10

    invoke-virtual {v0, v3, v4, v10, v11}, Llyiahf/vczjk/v16;->o0000Ooo(JJ)F

    move-result v7

    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v7

    const v10, 0x7fffffff

    and-int/2addr v7, v10

    const/high16 v10, 0x7f800000    # Float.POSITIVE_INFINITY

    if-ge v7, v10, :cond_2

    move v10, v8

    move v7, v9

    goto :goto_0

    :cond_1
    move/from16 v6, p5

    :cond_2
    move/from16 v7, p6

    move v10, v9

    :goto_0
    if-eqz v10, :cond_f

    iget v10, v5, Llyiahf/vczjk/eo3;->OooOOOO:I

    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOoO0()Llyiahf/vczjk/ws5;

    move-result-object v1

    iget-object v11, v1, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v1, v1, Llyiahf/vczjk/ws5;->OooOOOO:I

    sub-int/2addr v1, v8

    move v12, v1

    :goto_1
    if-ltz v12, :cond_e

    aget-object v1, v11, v12

    check-cast v1, Llyiahf/vczjk/ro4;

    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->Oooo0()Z

    move-result v13

    if-eqz v13, :cond_d

    move-object/from16 v16, v2

    move-object v2, v1

    move-object/from16 v1, v16

    invoke-interface/range {v1 .. v7}, Llyiahf/vczjk/o16;->OooO0o(Llyiahf/vczjk/ro4;JLlyiahf/vczjk/eo3;IZ)V

    invoke-virtual {v5}, Llyiahf/vczjk/eo3;->OooO00o()J

    move-result-wide v3

    invoke-static {v3, v4}, Llyiahf/vczjk/ng0;->OooOoO(J)F

    move-result v1

    const/4 v6, 0x0

    cmpg-float v1, v1, v6

    if-gez v1, :cond_d

    invoke-static {v3, v4}, Llyiahf/vczjk/ng0;->Oooo0O0(J)Z

    move-result v1

    if-eqz v1, :cond_d

    invoke-static {v3, v4}, Llyiahf/vczjk/ng0;->Oooo0(J)Z

    move-result v1

    if-nez v1, :cond_d

    iget-object v1, v2, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v1, v1, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v16;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 v2, 0x10

    invoke-static {v2}, Llyiahf/vczjk/z16;->OooO0oO(I)Z

    move-result v3

    invoke-virtual {v1, v3}, Llyiahf/vczjk/v16;->o0000OO0(Z)Llyiahf/vczjk/jl5;

    move-result-object v1

    if-nez v1, :cond_3

    goto/16 :goto_7

    :cond_3
    iget-boolean v3, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v3, :cond_e

    iget-object v3, v1, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v3, v3, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v3, :cond_4

    const-string v3, "visitLocalDescendants called on an unattached node"

    invoke-static {v3}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_4
    iget-object v1, v1, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget v3, v1, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/2addr v3, v2

    if-eqz v3, :cond_e

    :goto_2
    if-eqz v1, :cond_e

    iget v3, v1, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v3, v2

    if-eqz v3, :cond_c

    const/4 v3, 0x0

    move-object v4, v1

    move-object v6, v3

    :goto_3
    if-eqz v4, :cond_c

    instance-of v13, v4, Llyiahf/vczjk/ny6;

    if-eqz v13, :cond_5

    check-cast v4, Llyiahf/vczjk/ny6;

    invoke-interface {v4}, Llyiahf/vczjk/ny6;->oo000o()Z

    move-result v4

    if-eqz v4, :cond_b

    iget-object v1, v5, Llyiahf/vczjk/eo3;->OooOOO0:Llyiahf/vczjk/as5;

    iget v1, v1, Llyiahf/vczjk/c76;->OooO0O0:I

    sub-int/2addr v1, v8

    iput v1, v5, Llyiahf/vczjk/eo3;->OooOOOO:I

    goto :goto_6

    :cond_5
    iget v13, v4, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v13, v2

    if-eqz v13, :cond_b

    instance-of v13, v4, Llyiahf/vczjk/m52;

    if-eqz v13, :cond_b

    move-object v13, v4

    check-cast v13, Llyiahf/vczjk/m52;

    iget-object v13, v13, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    move v14, v9

    :goto_4
    if-eqz v13, :cond_a

    iget v15, v13, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v15, v2

    if-eqz v15, :cond_9

    add-int/lit8 v14, v14, 0x1

    if-ne v14, v8, :cond_6

    move-object v4, v13

    goto :goto_5

    :cond_6
    if-nez v6, :cond_7

    new-instance v6, Llyiahf/vczjk/ws5;

    new-array v15, v2, [Llyiahf/vczjk/jl5;

    invoke-direct {v6, v15}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_7
    if-eqz v4, :cond_8

    invoke-virtual {v6, v4}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v4, v3

    :cond_8
    invoke-virtual {v6, v13}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_9
    :goto_5
    iget-object v13, v13, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_4

    :cond_a
    if-ne v14, v8, :cond_b

    goto :goto_3

    :cond_b
    invoke-static {v6}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v4

    goto :goto_3

    :cond_c
    iget-object v1, v1, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_2

    :cond_d
    :goto_6
    add-int/lit8 v12, v12, -0x1

    move-object/from16 v2, p1

    move-wide/from16 v3, p2

    move/from16 v6, p5

    goto/16 :goto_1

    :cond_e
    :goto_7
    iput v10, v5, Llyiahf/vczjk/eo3;->OooOOOO:I

    :cond_f
    return-void
.end method

.method public final o0000oOo(Llyiahf/vczjk/eq0;Llyiahf/vczjk/kj3;)V
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-static {v0}, Llyiahf/vczjk/uo4;->OooO00o(Llyiahf/vczjk/ro4;)Llyiahf/vczjk/tg6;

    move-result-object v1

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOoO0()Llyiahf/vczjk/ws5;

    move-result-object v0

    iget-object v2, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v0, :cond_1

    aget-object v4, v2, v3

    check-cast v4, Llyiahf/vczjk/ro4;

    invoke-virtual {v4}, Llyiahf/vczjk/ro4;->Oooo0()Z

    move-result v5

    if-eqz v5, :cond_0

    invoke-virtual {v4, p1, p2}, Llyiahf/vczjk/ro4;->OooOO0(Llyiahf/vczjk/eq0;Llyiahf/vczjk/kj3;)V

    :cond_0
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    check-cast v1, Llyiahf/vczjk/xa;

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->getShowLayoutBounds()Z

    move-result p2

    if-eqz p2, :cond_2

    iget-wide v0, p0, Llyiahf/vczjk/ow6;->OooOOOO:J

    const/16 p2, 0x20

    shr-long v2, v0, p2

    long-to-int p2, v2

    int-to-float p2, p2

    const/high16 v2, 0x3f000000    # 0.5f

    sub-float v6, p2, v2

    const-wide v3, 0xffffffffL

    and-long/2addr v0, v3

    long-to-int p2, v0

    int-to-float p2, p2

    sub-float v7, p2, v2

    const/high16 v4, 0x3f000000    # 0.5f

    const/high16 v5, 0x3f000000    # 0.5f

    sget-object v8, Llyiahf/vczjk/b04;->Ooooo00:Llyiahf/vczjk/ie;

    move-object v3, p1

    invoke-interface/range {v3 .. v8}, Llyiahf/vczjk/eq0;->OooO0o(FFFFLlyiahf/vczjk/ie;)V

    :cond_2
    return-void
.end method

.method public final o000OO()Llyiahf/vczjk/jl5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b04;->OoooOoO:Llyiahf/vczjk/cf9;

    return-object v0
.end method

.method public final o0OoOo0(JFLlyiahf/vczjk/oe3;)V
    .locals 6

    const/4 v5, 0x0

    move-object v0, p0

    move-wide v1, p1

    move v3, p3

    move-object v4, p4

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/v16;->o0000oo0(JFLlyiahf/vczjk/oe3;Llyiahf/vczjk/kj3;)V

    iget-boolean p1, v0, Llyiahf/vczjk/o65;->OooOOoo:Z

    if-eqz p1, :cond_0

    return-void

    :cond_0
    iget-object p1, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    iget-object p1, p1, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object p1, p1, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    invoke-virtual {p1}, Llyiahf/vczjk/kf5;->oo0o0Oo()V

    return-void
.end method

.method public final o0ooOoO(Llyiahf/vczjk/p4;)I
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/b04;->OoooOoo:Llyiahf/vczjk/a04;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a04;->o0ooOoO(Llyiahf/vczjk/p4;)I

    move-result p1

    return p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget-boolean v1, v0, Llyiahf/vczjk/kf5;->OooOoO0:Z

    const/4 v2, 0x1

    iget-object v3, v0, Llyiahf/vczjk/kf5;->Oooo0OO:Llyiahf/vczjk/so4;

    if-nez v1, :cond_2

    iget-object v1, v0, Llyiahf/vczjk/kf5;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object v1, v1, Llyiahf/vczjk/vo4;->OooO0Oo:Llyiahf/vczjk/lo4;

    sget-object v4, Llyiahf/vczjk/lo4;->OooOOO0:Llyiahf/vczjk/lo4;

    if-ne v1, v4, :cond_1

    iput-boolean v2, v3, Llyiahf/vczjk/v4;->OooO0o:Z

    iget-boolean v1, v3, Llyiahf/vczjk/v4;->OooO0O0:Z

    if-eqz v1, :cond_2

    iput-boolean v2, v0, Llyiahf/vczjk/kf5;->Oooo0:Z

    iput-boolean v2, v0, Llyiahf/vczjk/kf5;->Oooo0O0:Z

    goto :goto_0

    :cond_1
    iput-boolean v2, v3, Llyiahf/vczjk/v4;->OooO0oO:Z

    :cond_2
    :goto_0
    invoke-virtual {v0}, Llyiahf/vczjk/kf5;->OooO0oO()Llyiahf/vczjk/b04;

    move-result-object v1

    iput-boolean v2, v1, Llyiahf/vczjk/o65;->OooOo00:Z

    invoke-virtual {v0}, Llyiahf/vczjk/kf5;->Oooo0O0()V

    invoke-virtual {v0}, Llyiahf/vczjk/kf5;->OooO0oO()Llyiahf/vczjk/b04;

    move-result-object v0

    const/4 v1, 0x0

    iput-boolean v1, v0, Llyiahf/vczjk/o65;->OooOo00:Z

    iget-object v0, v3, Llyiahf/vczjk/v4;->OooO:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Integer;

    if-eqz p1, :cond_3

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    return p1

    :cond_3
    const/high16 p1, -0x80000000

    return p1
.end method

.method public final ooOO(JFLlyiahf/vczjk/kj3;)V
    .locals 6

    const/4 v4, 0x0

    move-object v0, p0

    move-wide v1, p1

    move v3, p3

    move-object v5, p4

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/v16;->o0000oo0(JFLlyiahf/vczjk/oe3;Llyiahf/vczjk/kj3;)V

    iget-boolean p1, v0, Llyiahf/vczjk/o65;->OooOOoo:Z

    if-eqz p1, :cond_0

    return-void

    :cond_0
    iget-object p1, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    iget-object p1, p1, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object p1, p1, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    invoke-virtual {p1}, Llyiahf/vczjk/kf5;->oo0o0Oo()V

    return-void
.end method
