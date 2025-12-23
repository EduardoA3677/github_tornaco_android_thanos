.class public final Llyiahf/vczjk/ok1;
.super Llyiahf/vczjk/nk1;
.source "SourceFile"


# instance fields
.field public o00000:Z

.field public o000000:[Llyiahf/vczjk/zr0;

.field public o000000O:[Llyiahf/vczjk/zr0;

.field public o000000o:I

.field public o00000O:Ljava/lang/ref/WeakReference;

.field public o00000O0:Z

.field public o00000OO:Ljava/lang/ref/WeakReference;

.field public o00000Oo:Ljava/lang/ref/WeakReference;

.field public o00000o0:Ljava/lang/ref/WeakReference;

.field public final o00000oO:Llyiahf/vczjk/p90;

.field public final o0000Ooo:Ljava/util/HashSet;

.field public o000OOo:I

.field public final o00oO0O:Llyiahf/vczjk/uqa;

.field public o00oO0o:Ljava/util/ArrayList;

.field public o0O0O00:I

.field public o0OO00O:I

.field public o0OOO0o:Z

.field public final o0Oo0oo:Llyiahf/vczjk/yz4;

.field public final o0ooOO0:Llyiahf/vczjk/o62;

.field public o0ooOOo:I

.field public o0ooOoO:Llyiahf/vczjk/q90;

.field public oo0o0Oo:I


# direct methods
.method public constructor <init>()V
    .locals 4

    invoke-direct {p0}, Llyiahf/vczjk/nk1;-><init>()V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    new-instance v0, Llyiahf/vczjk/uqa;

    invoke-direct {v0, p0}, Llyiahf/vczjk/uqa;-><init>(Llyiahf/vczjk/ok1;)V

    iput-object v0, p0, Llyiahf/vczjk/ok1;->o00oO0O:Llyiahf/vczjk/uqa;

    new-instance v0, Llyiahf/vczjk/o62;

    invoke-direct {v0}, Llyiahf/vczjk/o62;-><init>()V

    const/4 v1, 0x1

    iput-boolean v1, v0, Llyiahf/vczjk/o62;->OooO0O0:Z

    iput-boolean v1, v0, Llyiahf/vczjk/o62;->OooO0OO:Z

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iput-object v1, v0, Llyiahf/vczjk/o62;->OooO0o:Ljava/io/Serializable;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/o62;->OooO0oo:Ljava/lang/Object;

    new-instance v2, Llyiahf/vczjk/p90;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    iput-object v2, v0, Llyiahf/vczjk/o62;->OooO:Ljava/lang/Object;

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    iput-object v2, v0, Llyiahf/vczjk/o62;->OooO0oO:Ljava/io/Serializable;

    iput-object p0, v0, Llyiahf/vczjk/o62;->OooO0Oo:Ljava/lang/Object;

    iput-object p0, v0, Llyiahf/vczjk/o62;->OooO0o0:Ljava/lang/Object;

    iput-object v0, p0, Llyiahf/vczjk/ok1;->o0ooOO0:Llyiahf/vczjk/o62;

    iput-object v1, p0, Llyiahf/vczjk/ok1;->o0ooOoO:Llyiahf/vczjk/q90;

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/ok1;->o0OOO0o:Z

    new-instance v2, Llyiahf/vczjk/yz4;

    invoke-direct {v2}, Llyiahf/vczjk/yz4;-><init>()V

    iput-object v2, p0, Llyiahf/vczjk/ok1;->o0Oo0oo:Llyiahf/vczjk/yz4;

    iput v0, p0, Llyiahf/vczjk/ok1;->o0O0O00:I

    iput v0, p0, Llyiahf/vczjk/ok1;->o000OOo:I

    const/4 v2, 0x4

    new-array v3, v2, [Llyiahf/vczjk/zr0;

    iput-object v3, p0, Llyiahf/vczjk/ok1;->o000000:[Llyiahf/vczjk/zr0;

    new-array v2, v2, [Llyiahf/vczjk/zr0;

    iput-object v2, p0, Llyiahf/vczjk/ok1;->o000000O:[Llyiahf/vczjk/zr0;

    const/16 v2, 0x101

    iput v2, p0, Llyiahf/vczjk/ok1;->o000000o:I

    iput-boolean v0, p0, Llyiahf/vczjk/ok1;->o00000:Z

    iput-boolean v0, p0, Llyiahf/vczjk/ok1;->o00000O0:Z

    iput-object v1, p0, Llyiahf/vczjk/ok1;->o00000O:Ljava/lang/ref/WeakReference;

    iput-object v1, p0, Llyiahf/vczjk/ok1;->o00000OO:Ljava/lang/ref/WeakReference;

    iput-object v1, p0, Llyiahf/vczjk/ok1;->o00000Oo:Ljava/lang/ref/WeakReference;

    iput-object v1, p0, Llyiahf/vczjk/ok1;->o00000o0:Ljava/lang/ref/WeakReference;

    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/ok1;->o0000Ooo:Ljava/util/HashSet;

    new-instance v0, Llyiahf/vczjk/p90;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/ok1;->o00000oO:Llyiahf/vczjk/p90;

    return-void
.end method

.method public static OoooO0(Llyiahf/vczjk/nk1;Llyiahf/vczjk/q90;Llyiahf/vczjk/p90;)V
    .locals 10

    if-nez p1, :cond_0

    return-void

    :cond_0
    iget v0, p0, Llyiahf/vczjk/nk1;->Oooooo:I

    const/16 v1, 0x8

    const/4 v2, 0x0

    if-eq v0, v1, :cond_13

    instance-of v0, p0, Llyiahf/vczjk/uk3;

    if-nez v0, :cond_13

    instance-of v0, p0, Llyiahf/vczjk/w50;

    if-eqz v0, :cond_1

    goto/16 :goto_8

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    aget-object v1, v0, v2

    iput-object v1, p2, Llyiahf/vczjk/p90;->OooO00o:Llyiahf/vczjk/mk1;

    const/4 v1, 0x1

    aget-object v0, v0, v1

    iput-object v0, p2, Llyiahf/vczjk/p90;->OooO0O0:Llyiahf/vczjk/mk1;

    invoke-virtual {p0}, Llyiahf/vczjk/nk1;->OooOOOO()I

    move-result v0

    iput v0, p2, Llyiahf/vczjk/p90;->OooO0OO:I

    invoke-virtual {p0}, Llyiahf/vczjk/nk1;->OooOO0o()I

    move-result v0

    iput v0, p2, Llyiahf/vczjk/p90;->OooO0Oo:I

    iput-boolean v2, p2, Llyiahf/vczjk/p90;->OooO:Z

    iput v2, p2, Llyiahf/vczjk/p90;->OooOO0:I

    iget-object v0, p2, Llyiahf/vczjk/p90;->OooO00o:Llyiahf/vczjk/mk1;

    sget-object v3, Llyiahf/vczjk/mk1;->OooOOOO:Llyiahf/vczjk/mk1;

    if-ne v0, v3, :cond_2

    move v0, v1

    goto :goto_0

    :cond_2
    move v0, v2

    :goto_0
    iget-object v4, p2, Llyiahf/vczjk/p90;->OooO0O0:Llyiahf/vczjk/mk1;

    if-ne v4, v3, :cond_3

    move v3, v1

    goto :goto_1

    :cond_3
    move v3, v2

    :goto_1
    const/4 v4, 0x0

    if-eqz v0, :cond_4

    iget v5, p0, Llyiahf/vczjk/nk1;->OoooOOo:F

    cmpl-float v5, v5, v4

    if-lez v5, :cond_4

    move v5, v1

    goto :goto_2

    :cond_4
    move v5, v2

    :goto_2
    if-eqz v3, :cond_5

    iget v6, p0, Llyiahf/vczjk/nk1;->OoooOOo:F

    cmpl-float v4, v6, v4

    if-lez v4, :cond_5

    move v4, v1

    goto :goto_3

    :cond_5
    move v4, v2

    :goto_3
    sget-object v6, Llyiahf/vczjk/mk1;->OooOOO:Llyiahf/vczjk/mk1;

    sget-object v7, Llyiahf/vczjk/mk1;->OooOOO0:Llyiahf/vczjk/mk1;

    if-eqz v0, :cond_7

    invoke-virtual {p0, v2}, Llyiahf/vczjk/nk1;->OooOOo(I)Z

    move-result v8

    if-eqz v8, :cond_7

    iget v8, p0, Llyiahf/vczjk/nk1;->OooOOo0:I

    if-nez v8, :cond_7

    if-nez v5, :cond_7

    iput-object v6, p2, Llyiahf/vczjk/p90;->OooO00o:Llyiahf/vczjk/mk1;

    if-eqz v3, :cond_6

    iget v0, p0, Llyiahf/vczjk/nk1;->OooOOo:I

    if-nez v0, :cond_6

    iput-object v7, p2, Llyiahf/vczjk/p90;->OooO00o:Llyiahf/vczjk/mk1;

    :cond_6
    move v0, v2

    :cond_7
    if-eqz v3, :cond_9

    invoke-virtual {p0, v1}, Llyiahf/vczjk/nk1;->OooOOo(I)Z

    move-result v8

    if-eqz v8, :cond_9

    iget v8, p0, Llyiahf/vczjk/nk1;->OooOOo:I

    if-nez v8, :cond_9

    if-nez v4, :cond_9

    iput-object v6, p2, Llyiahf/vczjk/p90;->OooO0O0:Llyiahf/vczjk/mk1;

    if-eqz v0, :cond_8

    iget v3, p0, Llyiahf/vczjk/nk1;->OooOOo0:I

    if-nez v3, :cond_8

    iput-object v7, p2, Llyiahf/vczjk/p90;->OooO0O0:Llyiahf/vczjk/mk1;

    :cond_8
    move v3, v2

    :cond_9
    invoke-virtual {p0}, Llyiahf/vczjk/nk1;->OooOoO0()Z

    move-result v8

    if-eqz v8, :cond_a

    iput-object v7, p2, Llyiahf/vczjk/p90;->OooO00o:Llyiahf/vczjk/mk1;

    move v0, v2

    :cond_a
    invoke-virtual {p0}, Llyiahf/vczjk/nk1;->OooOoO()Z

    move-result v8

    if-eqz v8, :cond_b

    iput-object v7, p2, Llyiahf/vczjk/p90;->OooO0O0:Llyiahf/vczjk/mk1;

    move v3, v2

    :cond_b
    iget-object v8, p0, Llyiahf/vczjk/nk1;->OooOOoo:[I

    const/4 v9, 0x4

    if-eqz v5, :cond_e

    aget v5, v8, v2

    if-ne v5, v9, :cond_c

    iput-object v7, p2, Llyiahf/vczjk/p90;->OooO00o:Llyiahf/vczjk/mk1;

    goto :goto_5

    :cond_c
    if-nez v3, :cond_e

    iget-object v3, p2, Llyiahf/vczjk/p90;->OooO0O0:Llyiahf/vczjk/mk1;

    if-ne v3, v7, :cond_d

    iget v3, p2, Llyiahf/vczjk/p90;->OooO0Oo:I

    goto :goto_4

    :cond_d
    iput-object v6, p2, Llyiahf/vczjk/p90;->OooO00o:Llyiahf/vczjk/mk1;

    move-object v3, p1

    check-cast v3, Landroidx/constraintlayout/widget/OooO0O0;

    invoke-virtual {v3, p0, p2}, Landroidx/constraintlayout/widget/OooO0O0;->OooO0O0(Llyiahf/vczjk/nk1;Llyiahf/vczjk/p90;)V

    iget v3, p2, Llyiahf/vczjk/p90;->OooO0o:I

    :goto_4
    iput-object v7, p2, Llyiahf/vczjk/p90;->OooO00o:Llyiahf/vczjk/mk1;

    iget v5, p0, Llyiahf/vczjk/nk1;->OoooOOo:F

    int-to-float v3, v3

    mul-float/2addr v5, v3

    float-to-int v3, v5

    iput v3, p2, Llyiahf/vczjk/p90;->OooO0OO:I

    :cond_e
    :goto_5
    if-eqz v4, :cond_12

    aget v1, v8, v1

    if-ne v1, v9, :cond_f

    iput-object v7, p2, Llyiahf/vczjk/p90;->OooO0O0:Llyiahf/vczjk/mk1;

    goto :goto_7

    :cond_f
    if-nez v0, :cond_12

    iget-object v0, p2, Llyiahf/vczjk/p90;->OooO00o:Llyiahf/vczjk/mk1;

    if-ne v0, v7, :cond_10

    iget v0, p2, Llyiahf/vczjk/p90;->OooO0OO:I

    goto :goto_6

    :cond_10
    iput-object v6, p2, Llyiahf/vczjk/p90;->OooO0O0:Llyiahf/vczjk/mk1;

    move-object v0, p1

    check-cast v0, Landroidx/constraintlayout/widget/OooO0O0;

    invoke-virtual {v0, p0, p2}, Landroidx/constraintlayout/widget/OooO0O0;->OooO0O0(Llyiahf/vczjk/nk1;Llyiahf/vczjk/p90;)V

    iget v0, p2, Llyiahf/vczjk/p90;->OooO0o0:I

    :goto_6
    iput-object v7, p2, Llyiahf/vczjk/p90;->OooO0O0:Llyiahf/vczjk/mk1;

    iget v1, p0, Llyiahf/vczjk/nk1;->OoooOo0:I

    const/4 v3, -0x1

    if-ne v1, v3, :cond_11

    int-to-float v0, v0

    iget v1, p0, Llyiahf/vczjk/nk1;->OoooOOo:F

    div-float/2addr v0, v1

    float-to-int v0, v0

    iput v0, p2, Llyiahf/vczjk/p90;->OooO0Oo:I

    goto :goto_7

    :cond_11
    iget v1, p0, Llyiahf/vczjk/nk1;->OoooOOo:F

    int-to-float v0, v0

    mul-float/2addr v1, v0

    float-to-int v0, v1

    iput v0, p2, Llyiahf/vczjk/p90;->OooO0Oo:I

    :cond_12
    :goto_7
    check-cast p1, Landroidx/constraintlayout/widget/OooO0O0;

    invoke-virtual {p1, p0, p2}, Landroidx/constraintlayout/widget/OooO0O0;->OooO0O0(Llyiahf/vczjk/nk1;Llyiahf/vczjk/p90;)V

    iget p1, p2, Llyiahf/vczjk/p90;->OooO0o0:I

    invoke-virtual {p0, p1}, Llyiahf/vczjk/nk1;->Oooo0OO(I)V

    iget p1, p2, Llyiahf/vczjk/p90;->OooO0o:I

    invoke-virtual {p0, p1}, Llyiahf/vczjk/nk1;->Oooo00o(I)V

    iget-boolean p1, p2, Llyiahf/vczjk/p90;->OooO0oo:Z

    iput-boolean p1, p0, Llyiahf/vczjk/nk1;->OooOooO:Z

    iget p1, p2, Llyiahf/vczjk/p90;->OooO0oO:I

    invoke-virtual {p0, p1}, Llyiahf/vczjk/nk1;->OooOooo(I)V

    iput v2, p2, Llyiahf/vczjk/p90;->OooOO0:I

    return-void

    :cond_13
    :goto_8
    iput v2, p2, Llyiahf/vczjk/p90;->OooO0o0:I

    iput v2, p2, Llyiahf/vczjk/p90;->OooO0o:I

    return-void
.end method


# virtual methods
.method public final OooOoOO()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ok1;->o0Oo0oo:Llyiahf/vczjk/yz4;

    invoke-virtual {v0}, Llyiahf/vczjk/yz4;->OooOo00()V

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/ok1;->o0OO00O:I

    iput v0, p0, Llyiahf/vczjk/ok1;->oo0o0Oo:I

    iget-object v0, p0, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    invoke-super {p0}, Llyiahf/vczjk/nk1;->OooOoOO()V

    return-void
.end method

.method public final OooOooO(Llyiahf/vczjk/uqa;)V
    .locals 3

    invoke-super {p0, p1}, Llyiahf/vczjk/nk1;->OooOooO(Llyiahf/vczjk/uqa;)V

    iget-object v0, p0, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    iget-object v2, p0, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/nk1;

    invoke-virtual {v2, p1}, Llyiahf/vczjk/nk1;->OooOooO(Llyiahf/vczjk/uqa;)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public final Oooo(IZ)Z
    .locals 16

    move/from16 v0, p1

    move-object/from16 v1, p0

    iget-object v2, v1, Llyiahf/vczjk/ok1;->o0ooOO0:Llyiahf/vczjk/o62;

    iget-object v3, v2, Llyiahf/vczjk/o62;->OooO0Oo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ok1;

    const/4 v4, 0x0

    invoke-virtual {v3, v4}, Llyiahf/vczjk/nk1;->OooOO0O(I)Llyiahf/vczjk/mk1;

    move-result-object v5

    const/4 v6, 0x1

    invoke-virtual {v3, v6}, Llyiahf/vczjk/nk1;->OooOO0O(I)Llyiahf/vczjk/mk1;

    move-result-object v7

    invoke-virtual {v3}, Llyiahf/vczjk/nk1;->OooOOOo()I

    move-result v8

    invoke-virtual {v3}, Llyiahf/vczjk/nk1;->OooOOo0()I

    move-result v9

    iget-object v10, v2, Llyiahf/vczjk/o62;->OooO0o:Ljava/io/Serializable;

    check-cast v10, Ljava/util/ArrayList;

    sget-object v11, Llyiahf/vczjk/mk1;->OooOOO0:Llyiahf/vczjk/mk1;

    if-eqz p2, :cond_4

    sget-object v12, Llyiahf/vczjk/mk1;->OooOOO:Llyiahf/vczjk/mk1;

    if-eq v5, v12, :cond_0

    if-ne v7, v12, :cond_4

    :cond_0
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v13

    :cond_1
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    move-result v14

    if-eqz v14, :cond_2

    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/mma;

    iget v15, v14, Llyiahf/vczjk/mma;->OooO0o:I

    if-ne v15, v0, :cond_1

    invoke-virtual {v14}, Llyiahf/vczjk/mma;->OooOO0O()Z

    move-result v14

    if-nez v14, :cond_1

    move v13, v4

    goto :goto_0

    :cond_2
    move/from16 v13, p2

    :goto_0
    if-nez v0, :cond_3

    if-eqz v13, :cond_4

    if-ne v5, v12, :cond_4

    invoke-virtual {v3, v11}, Llyiahf/vczjk/nk1;->Oooo0(Llyiahf/vczjk/mk1;)V

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/o62;->OooO0Oo(Llyiahf/vczjk/ok1;I)I

    move-result v12

    invoke-virtual {v3, v12}, Llyiahf/vczjk/nk1;->Oooo0OO(I)V

    iget-object v12, v3, Llyiahf/vczjk/nk1;->OooO0Oo:Llyiahf/vczjk/ro3;

    iget-object v12, v12, Llyiahf/vczjk/mma;->OooO0o0:Llyiahf/vczjk/qb2;

    invoke-virtual {v3}, Llyiahf/vczjk/nk1;->OooOOOO()I

    move-result v13

    invoke-virtual {v12, v13}, Llyiahf/vczjk/qb2;->OooO0Oo(I)V

    goto :goto_1

    :cond_3
    if-eqz v13, :cond_4

    if-ne v7, v12, :cond_4

    invoke-virtual {v3, v11}, Llyiahf/vczjk/nk1;->Oooo0O0(Llyiahf/vczjk/mk1;)V

    invoke-virtual {v2, v3, v6}, Llyiahf/vczjk/o62;->OooO0Oo(Llyiahf/vczjk/ok1;I)I

    move-result v12

    invoke-virtual {v3, v12}, Llyiahf/vczjk/nk1;->Oooo00o(I)V

    iget-object v12, v3, Llyiahf/vczjk/nk1;->OooO0o0:Llyiahf/vczjk/gfa;

    iget-object v12, v12, Llyiahf/vczjk/mma;->OooO0o0:Llyiahf/vczjk/qb2;

    invoke-virtual {v3}, Llyiahf/vczjk/nk1;->OooOO0o()I

    move-result v13

    invoke-virtual {v12, v13}, Llyiahf/vczjk/qb2;->OooO0Oo(I)V

    :cond_4
    :goto_1
    sget-object v12, Llyiahf/vczjk/mk1;->OooOOOo:Llyiahf/vczjk/mk1;

    if-nez v0, :cond_6

    iget-object v9, v3, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    aget-object v9, v9, v4

    if-eq v9, v11, :cond_5

    if-ne v9, v12, :cond_7

    :cond_5
    invoke-virtual {v3}, Llyiahf/vczjk/nk1;->OooOOOO()I

    move-result v9

    add-int/2addr v9, v8

    iget-object v11, v3, Llyiahf/vczjk/nk1;->OooO0Oo:Llyiahf/vczjk/ro3;

    iget-object v11, v11, Llyiahf/vczjk/mma;->OooO:Llyiahf/vczjk/p62;

    invoke-virtual {v11, v9}, Llyiahf/vczjk/p62;->OooO0Oo(I)V

    iget-object v11, v3, Llyiahf/vczjk/nk1;->OooO0Oo:Llyiahf/vczjk/ro3;

    iget-object v11, v11, Llyiahf/vczjk/mma;->OooO0o0:Llyiahf/vczjk/qb2;

    sub-int/2addr v9, v8

    invoke-virtual {v11, v9}, Llyiahf/vczjk/qb2;->OooO0Oo(I)V

    :goto_2
    move v8, v6

    goto :goto_4

    :cond_6
    iget-object v8, v3, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    aget-object v8, v8, v6

    if-eq v8, v11, :cond_8

    if-ne v8, v12, :cond_7

    goto :goto_3

    :cond_7
    move v8, v4

    goto :goto_4

    :cond_8
    :goto_3
    invoke-virtual {v3}, Llyiahf/vczjk/nk1;->OooOO0o()I

    move-result v8

    add-int/2addr v8, v9

    iget-object v11, v3, Llyiahf/vczjk/nk1;->OooO0o0:Llyiahf/vczjk/gfa;

    iget-object v11, v11, Llyiahf/vczjk/mma;->OooO:Llyiahf/vczjk/p62;

    invoke-virtual {v11, v8}, Llyiahf/vczjk/p62;->OooO0Oo(I)V

    iget-object v11, v3, Llyiahf/vczjk/nk1;->OooO0o0:Llyiahf/vczjk/gfa;

    iget-object v11, v11, Llyiahf/vczjk/mma;->OooO0o0:Llyiahf/vczjk/qb2;

    sub-int/2addr v8, v9

    invoke-virtual {v11, v8}, Llyiahf/vczjk/qb2;->OooO0Oo(I)V

    goto :goto_2

    :goto_4
    invoke-virtual {v2}, Llyiahf/vczjk/o62;->OooO0oO()V

    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_5
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    if-eqz v9, :cond_b

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/mma;

    iget v11, v9, Llyiahf/vczjk/mma;->OooO0o:I

    if-eq v11, v0, :cond_9

    goto :goto_5

    :cond_9
    iget-object v11, v9, Llyiahf/vczjk/mma;->OooO0O0:Llyiahf/vczjk/nk1;

    if-ne v11, v3, :cond_a

    iget-boolean v11, v9, Llyiahf/vczjk/mma;->OooO0oO:Z

    if-nez v11, :cond_a

    goto :goto_5

    :cond_a
    invoke-virtual {v9}, Llyiahf/vczjk/mma;->OooO0o0()V

    goto :goto_5

    :cond_b
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_c
    :goto_6
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    if-eqz v9, :cond_11

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/mma;

    iget v10, v9, Llyiahf/vczjk/mma;->OooO0o:I

    if-eq v10, v0, :cond_d

    goto :goto_6

    :cond_d
    if-nez v8, :cond_e

    iget-object v10, v9, Llyiahf/vczjk/mma;->OooO0O0:Llyiahf/vczjk/nk1;

    if-ne v10, v3, :cond_e

    goto :goto_6

    :cond_e
    iget-object v10, v9, Llyiahf/vczjk/mma;->OooO0oo:Llyiahf/vczjk/p62;

    iget-boolean v10, v10, Llyiahf/vczjk/p62;->OooOO0:Z

    if-nez v10, :cond_f

    goto :goto_7

    :cond_f
    iget-object v10, v9, Llyiahf/vczjk/mma;->OooO:Llyiahf/vczjk/p62;

    iget-boolean v10, v10, Llyiahf/vczjk/p62;->OooOO0:Z

    if-nez v10, :cond_10

    goto :goto_7

    :cond_10
    instance-of v10, v9, Llyiahf/vczjk/as0;

    if-nez v10, :cond_c

    iget-object v9, v9, Llyiahf/vczjk/mma;->OooO0o0:Llyiahf/vczjk/qb2;

    iget-boolean v9, v9, Llyiahf/vczjk/p62;->OooOO0:Z

    if-nez v9, :cond_c

    goto :goto_7

    :cond_11
    move v4, v6

    :goto_7
    invoke-virtual {v3, v5}, Llyiahf/vczjk/nk1;->Oooo0(Llyiahf/vczjk/mk1;)V

    invoke-virtual {v3, v7}, Llyiahf/vczjk/nk1;->Oooo0O0(Llyiahf/vczjk/mk1;)V

    return v4
.end method

.method public final Oooo0o0(ZZ)V
    .locals 3

    invoke-super {p0, p1, p2}, Llyiahf/vczjk/nk1;->Oooo0o0(ZZ)V

    iget-object v0, p0, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    iget-object v2, p0, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/nk1;

    invoke-virtual {v2, p1, p2}, Llyiahf/vczjk/nk1;->Oooo0o0(ZZ)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public final Oooo0oO(Llyiahf/vczjk/nk1;I)V
    .locals 5

    const/4 v0, 0x1

    if-nez p2, :cond_1

    iget p2, p0, Llyiahf/vczjk/ok1;->o0O0O00:I

    add-int/2addr p2, v0

    iget-object v1, p0, Llyiahf/vczjk/ok1;->o000000O:[Llyiahf/vczjk/zr0;

    array-length v2, v1

    if-lt p2, v2, :cond_0

    array-length p2, v1

    mul-int/lit8 p2, p2, 0x2

    invoke-static {v1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    check-cast p2, [Llyiahf/vczjk/zr0;

    iput-object p2, p0, Llyiahf/vczjk/ok1;->o000000O:[Llyiahf/vczjk/zr0;

    :cond_0
    iget-object p2, p0, Llyiahf/vczjk/ok1;->o000000O:[Llyiahf/vczjk/zr0;

    iget v1, p0, Llyiahf/vczjk/ok1;->o0O0O00:I

    new-instance v2, Llyiahf/vczjk/zr0;

    iget-boolean v3, p0, Llyiahf/vczjk/ok1;->o0OOO0o:Z

    const/4 v4, 0x0

    invoke-direct {v2, p1, v4, v3}, Llyiahf/vczjk/zr0;-><init>(Llyiahf/vczjk/nk1;IZ)V

    aput-object v2, p2, v1

    add-int/2addr v1, v0

    iput v1, p0, Llyiahf/vczjk/ok1;->o0O0O00:I

    return-void

    :cond_1
    if-ne p2, v0, :cond_3

    iget p2, p0, Llyiahf/vczjk/ok1;->o000OOo:I

    add-int/2addr p2, v0

    iget-object v1, p0, Llyiahf/vczjk/ok1;->o000000:[Llyiahf/vczjk/zr0;

    array-length v2, v1

    if-lt p2, v2, :cond_2

    array-length p2, v1

    mul-int/lit8 p2, p2, 0x2

    invoke-static {v1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    check-cast p2, [Llyiahf/vczjk/zr0;

    iput-object p2, p0, Llyiahf/vczjk/ok1;->o000000:[Llyiahf/vczjk/zr0;

    :cond_2
    iget-object p2, p0, Llyiahf/vczjk/ok1;->o000000:[Llyiahf/vczjk/zr0;

    iget v1, p0, Llyiahf/vczjk/ok1;->o000OOo:I

    new-instance v2, Llyiahf/vczjk/zr0;

    iget-boolean v3, p0, Llyiahf/vczjk/ok1;->o0OOO0o:Z

    invoke-direct {v2, p1, v0, v3}, Llyiahf/vczjk/zr0;-><init>(Llyiahf/vczjk/nk1;IZ)V

    aput-object v2, p2, v1

    add-int/2addr v1, v0

    iput v1, p0, Llyiahf/vczjk/ok1;->o000OOo:I

    :cond_3
    return-void
.end method

.method public final Oooo0oo(Llyiahf/vczjk/yz4;)V
    .locals 12

    const/16 v0, 0x40

    invoke-virtual {p0, v0}, Llyiahf/vczjk/ok1;->OoooO0O(I)Z

    move-result v0

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/nk1;->OooO0O0(Llyiahf/vczjk/yz4;Z)V

    iget-object v1, p0, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v1

    const/4 v2, 0x0

    move v3, v2

    move v4, v3

    :goto_0
    const/4 v5, 0x1

    if-ge v3, v1, :cond_1

    iget-object v6, p0, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v6, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/nk1;

    iget-object v7, v6, Llyiahf/vczjk/nk1;->OoooO0O:[Z

    aput-boolean v2, v7, v2

    aput-boolean v2, v7, v5

    instance-of v6, v6, Llyiahf/vczjk/w50;

    if-eqz v6, :cond_0

    move v4, v5

    :cond_0
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    if-eqz v4, :cond_8

    move v3, v2

    :goto_1
    if-ge v3, v1, :cond_8

    iget-object v4, p0, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/nk1;

    instance-of v6, v4, Llyiahf/vczjk/w50;

    if-eqz v6, :cond_7

    check-cast v4, Llyiahf/vczjk/w50;

    move v6, v2

    :goto_2
    iget v7, v4, Llyiahf/vczjk/in3;->o00oO0O:I

    if-ge v6, v7, :cond_7

    iget-object v7, v4, Llyiahf/vczjk/in3;->o00oO0o:[Llyiahf/vczjk/nk1;

    aget-object v7, v7, v6

    iget-boolean v8, v4, Llyiahf/vczjk/w50;->o0ooOOo:Z

    if-nez v8, :cond_2

    invoke-virtual {v7}, Llyiahf/vczjk/nk1;->OooO0OO()Z

    move-result v8

    if-nez v8, :cond_2

    goto :goto_4

    :cond_2
    iget v8, v4, Llyiahf/vczjk/w50;->o0ooOO0:I

    if-eqz v8, :cond_5

    if-ne v8, v5, :cond_3

    goto :goto_3

    :cond_3
    const/4 v9, 0x2

    if-eq v8, v9, :cond_4

    const/4 v9, 0x3

    if-ne v8, v9, :cond_6

    :cond_4
    iget-object v7, v7, Llyiahf/vczjk/nk1;->OoooO0O:[Z

    aput-boolean v5, v7, v5

    goto :goto_4

    :cond_5
    :goto_3
    iget-object v7, v7, Llyiahf/vczjk/nk1;->OoooO0O:[Z

    aput-boolean v5, v7, v2

    :cond_6
    :goto_4
    add-int/lit8 v6, v6, 0x1

    goto :goto_2

    :cond_7
    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_8
    iget-object v3, p0, Llyiahf/vczjk/ok1;->o0000Ooo:Ljava/util/HashSet;

    invoke-virtual {v3}, Ljava/util/HashSet;->clear()V

    move v4, v2

    :goto_5
    if-ge v4, v1, :cond_c

    iget-object v6, p0, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/nk1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v7, v6, Llyiahf/vczjk/g43;

    if-nez v7, :cond_9

    instance-of v8, v6, Llyiahf/vczjk/uk3;

    if-eqz v8, :cond_b

    :cond_9
    if-eqz v7, :cond_a

    invoke-virtual {v3, v6}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    goto :goto_6

    :cond_a
    invoke-virtual {v6, p1, v0}, Llyiahf/vczjk/nk1;->OooO0O0(Llyiahf/vczjk/yz4;Z)V

    :cond_b
    :goto_6
    add-int/lit8 v4, v4, 0x1

    goto :goto_5

    :cond_c
    :goto_7
    invoke-virtual {v3}, Ljava/util/HashSet;->size()I

    move-result v4

    if-lez v4, :cond_11

    invoke-virtual {v3}, Ljava/util/HashSet;->size()I

    move-result v4

    invoke-virtual {v3}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :cond_d
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_f

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/nk1;

    check-cast v7, Llyiahf/vczjk/g43;

    move v8, v2

    :goto_8
    iget v9, v7, Llyiahf/vczjk/in3;->o00oO0O:I

    if-ge v8, v9, :cond_d

    iget-object v9, v7, Llyiahf/vczjk/in3;->o00oO0o:[Llyiahf/vczjk/nk1;

    aget-object v9, v9, v8

    invoke-virtual {v3, v9}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_e

    invoke-virtual {v7, p1, v0}, Llyiahf/vczjk/g43;->OooO0O0(Llyiahf/vczjk/yz4;Z)V

    invoke-virtual {v3, v7}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    goto :goto_9

    :cond_e
    add-int/lit8 v8, v8, 0x1

    goto :goto_8

    :cond_f
    :goto_9
    invoke-virtual {v3}, Ljava/util/HashSet;->size()I

    move-result v6

    if-ne v4, v6, :cond_c

    invoke-virtual {v3}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_a
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_10

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/nk1;

    invoke-virtual {v6, p1, v0}, Llyiahf/vczjk/nk1;->OooO0O0(Llyiahf/vczjk/yz4;Z)V

    goto :goto_a

    :cond_10
    invoke-virtual {v3}, Ljava/util/HashSet;->clear()V

    goto :goto_7

    :cond_11
    sget-boolean v3, Llyiahf/vczjk/yz4;->OooOOOo:Z

    sget-object v4, Llyiahf/vczjk/mk1;->OooOOO:Llyiahf/vczjk/mk1;

    if-eqz v3, :cond_16

    new-instance v9, Ljava/util/HashSet;

    invoke-direct {v9}, Ljava/util/HashSet;-><init>()V

    move v3, v2

    :goto_b
    if-ge v3, v1, :cond_14

    iget-object v6, p0, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v6, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/nk1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v7, v6, Llyiahf/vczjk/g43;

    if-nez v7, :cond_13

    instance-of v7, v6, Llyiahf/vczjk/uk3;

    if-eqz v7, :cond_12

    goto :goto_c

    :cond_12
    invoke-virtual {v9, v6}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    :cond_13
    :goto_c
    add-int/lit8 v3, v3, 0x1

    goto :goto_b

    :cond_14
    iget-object v1, p0, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    aget-object v1, v1, v2

    if-ne v1, v4, :cond_15

    move v10, v2

    goto :goto_d

    :cond_15
    move v10, v5

    :goto_d
    const/4 v11, 0x0

    move-object v7, p0

    move-object v6, p0

    move-object v8, p1

    invoke-virtual/range {v6 .. v11}, Llyiahf/vczjk/nk1;->OooO00o(Llyiahf/vczjk/ok1;Llyiahf/vczjk/yz4;Ljava/util/HashSet;IZ)V

    invoke-virtual {v9}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_e
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1d

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/nk1;

    invoke-static {p0, v8, v1}, Llyiahf/vczjk/sb;->OooOo0(Llyiahf/vczjk/ok1;Llyiahf/vczjk/yz4;Llyiahf/vczjk/nk1;)V

    invoke-virtual {v1, v8, v0}, Llyiahf/vczjk/nk1;->OooO0O0(Llyiahf/vczjk/yz4;Z)V

    goto :goto_e

    :cond_16
    move-object v6, p0

    move-object v8, p1

    move p1, v2

    :goto_f
    if-ge p1, v1, :cond_1d

    iget-object v3, v6, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v3, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/nk1;

    instance-of v7, v3, Llyiahf/vczjk/ok1;

    if-eqz v7, :cond_1a

    iget-object v7, v3, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    aget-object v9, v7, v2

    aget-object v7, v7, v5

    sget-object v10, Llyiahf/vczjk/mk1;->OooOOO0:Llyiahf/vczjk/mk1;

    if-ne v9, v4, :cond_17

    invoke-virtual {v3, v10}, Llyiahf/vczjk/nk1;->Oooo0(Llyiahf/vczjk/mk1;)V

    :cond_17
    if-ne v7, v4, :cond_18

    invoke-virtual {v3, v10}, Llyiahf/vczjk/nk1;->Oooo0O0(Llyiahf/vczjk/mk1;)V

    :cond_18
    invoke-virtual {v3, v8, v0}, Llyiahf/vczjk/nk1;->OooO0O0(Llyiahf/vczjk/yz4;Z)V

    if-ne v9, v4, :cond_19

    invoke-virtual {v3, v9}, Llyiahf/vczjk/nk1;->Oooo0(Llyiahf/vczjk/mk1;)V

    :cond_19
    if-ne v7, v4, :cond_1c

    invoke-virtual {v3, v7}, Llyiahf/vczjk/nk1;->Oooo0O0(Llyiahf/vczjk/mk1;)V

    goto :goto_10

    :cond_1a
    invoke-static {p0, v8, v3}, Llyiahf/vczjk/sb;->OooOo0(Llyiahf/vczjk/ok1;Llyiahf/vczjk/yz4;Llyiahf/vczjk/nk1;)V

    instance-of v7, v3, Llyiahf/vczjk/g43;

    if-nez v7, :cond_1c

    instance-of v7, v3, Llyiahf/vczjk/uk3;

    if-eqz v7, :cond_1b

    goto :goto_10

    :cond_1b
    invoke-virtual {v3, v8, v0}, Llyiahf/vczjk/nk1;->OooO0O0(Llyiahf/vczjk/yz4;Z)V

    :cond_1c
    :goto_10
    add-int/lit8 p1, p1, 0x1

    goto :goto_f

    :cond_1d
    iget p1, v6, Llyiahf/vczjk/ok1;->o0O0O00:I

    const/4 v0, 0x0

    if-lez p1, :cond_1e

    invoke-static {p0, v8, v0, v2}, Llyiahf/vczjk/sb;->OooOo00(Llyiahf/vczjk/ok1;Llyiahf/vczjk/yz4;Ljava/util/ArrayList;I)V

    :cond_1e
    iget p1, v6, Llyiahf/vczjk/ok1;->o000OOo:I

    if-lez p1, :cond_1f

    invoke-static {p0, v8, v0, v5}, Llyiahf/vczjk/sb;->OooOo00(Llyiahf/vczjk/ok1;Llyiahf/vczjk/yz4;Ljava/util/ArrayList;I)V

    :cond_1f
    return-void
.end method

.method public final OoooO00()V
    .locals 33

    move-object/from16 v1, p0

    const/4 v2, 0x0

    iput v2, v1, Llyiahf/vczjk/nk1;->OoooOoO:I

    iput v2, v1, Llyiahf/vczjk/nk1;->OoooOoo:I

    iput-boolean v2, v1, Llyiahf/vczjk/ok1;->o00000:Z

    iput-boolean v2, v1, Llyiahf/vczjk/ok1;->o00000O0:Z

    iget-object v0, v1, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v3

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOOOO()I

    move-result v0

    invoke-static {v2, v0}, Ljava/lang/Math;->max(II)I

    move-result v0

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOO0o()I

    move-result v4

    invoke-static {v2, v4}, Ljava/lang/Math;->max(II)I

    move-result v4

    iget-object v5, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    const/4 v6, 0x1

    aget-object v7, v5, v6

    aget-object v5, v5, v2

    iget v8, v1, Llyiahf/vczjk/ok1;->o0ooOOo:I

    sget-object v9, Llyiahf/vczjk/mk1;->OooOOOO:Llyiahf/vczjk/mk1;

    iget-object v10, v1, Llyiahf/vczjk/nk1;->Oooo0O0:Llyiahf/vczjk/nj1;

    iget-object v11, v1, Llyiahf/vczjk/nk1;->Oooo0:Llyiahf/vczjk/nj1;

    sget-object v12, Llyiahf/vczjk/mk1;->OooOOO0:Llyiahf/vczjk/mk1;

    if-nez v8, :cond_1e

    iget v8, v1, Llyiahf/vczjk/ok1;->o000000o:I

    invoke-static {v8, v6}, Llyiahf/vczjk/sb;->OooOo(II)Z

    move-result v8

    if-eqz v8, :cond_1e

    iget-object v8, v1, Llyiahf/vczjk/ok1;->o0ooOoO:Llyiahf/vczjk/q90;

    iget-object v14, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    aget-object v15, v14, v2

    aget-object v14, v14, v6

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOoo()V

    iget-object v13, v1, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v13}, Ljava/util/ArrayList;->size()I

    move-result v6

    :goto_0
    if-ge v2, v6, :cond_0

    invoke-virtual {v13, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v18

    check-cast v18, Llyiahf/vczjk/nk1;

    invoke-virtual/range {v18 .. v18}, Llyiahf/vczjk/nk1;->OooOoo()V

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_0
    iget-boolean v2, v1, Llyiahf/vczjk/ok1;->o0OOO0o:Z

    if-ne v15, v12, :cond_1

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOOOO()I

    move-result v15

    move/from16 v18, v4

    const/4 v4, 0x0

    invoke-virtual {v1, v4, v15}, Llyiahf/vczjk/nk1;->Oooo000(II)V

    goto :goto_1

    :cond_1
    move/from16 v18, v4

    const/4 v4, 0x0

    invoke-virtual {v11, v4}, Llyiahf/vczjk/nj1;->OooOO0o(I)V

    iput v4, v1, Llyiahf/vczjk/nk1;->OoooOoO:I

    :goto_1
    const/4 v4, 0x0

    const/4 v15, 0x0

    const/16 v19, 0x0

    :goto_2
    const/high16 v20, 0x3f000000    # 0.5f

    if-ge v15, v6, :cond_7

    invoke-virtual {v13, v15}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v21

    move/from16 v22, v4

    move-object/from16 v4, v21

    check-cast v4, Llyiahf/vczjk/nk1;

    move/from16 v21, v15

    instance-of v15, v4, Llyiahf/vczjk/uk3;

    if-eqz v15, :cond_6

    check-cast v4, Llyiahf/vczjk/uk3;

    iget v15, v4, Llyiahf/vczjk/uk3;->o0ooOoO:I

    move-object/from16 v23, v11

    const/4 v11, 0x1

    if-ne v15, v11, :cond_5

    iget v11, v4, Llyiahf/vczjk/uk3;->o00oO0O:I

    const/4 v15, -0x1

    if-eq v11, v15, :cond_2

    invoke-virtual {v4, v11}, Llyiahf/vczjk/uk3;->Oooo0oO(I)V

    goto :goto_3

    :cond_2
    iget v11, v4, Llyiahf/vczjk/uk3;->o0ooOO0:I

    if-eq v11, v15, :cond_3

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOoO0()Z

    move-result v11

    if-eqz v11, :cond_3

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOOOO()I

    move-result v11

    iget v15, v4, Llyiahf/vczjk/uk3;->o0ooOO0:I

    sub-int/2addr v11, v15

    invoke-virtual {v4, v11}, Llyiahf/vczjk/uk3;->Oooo0oO(I)V

    goto :goto_3

    :cond_3
    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOoO0()Z

    move-result v11

    if-eqz v11, :cond_4

    iget v11, v4, Llyiahf/vczjk/uk3;->o00oO0o:F

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOOOO()I

    move-result v15

    int-to-float v15, v15

    mul-float/2addr v11, v15

    add-float v11, v11, v20

    float-to-int v11, v11

    invoke-virtual {v4, v11}, Llyiahf/vczjk/uk3;->Oooo0oO(I)V

    :cond_4
    :goto_3
    const/16 v22, 0x1

    :cond_5
    move/from16 v4, v22

    goto :goto_4

    :cond_6
    move-object/from16 v23, v11

    instance-of v11, v4, Llyiahf/vczjk/w50;

    if-eqz v11, :cond_5

    check-cast v4, Llyiahf/vczjk/w50;

    invoke-virtual {v4}, Llyiahf/vczjk/w50;->OoooO0()I

    move-result v4

    if-nez v4, :cond_5

    move/from16 v4, v22

    const/16 v19, 0x1

    :goto_4
    add-int/lit8 v15, v21, 0x1

    move-object/from16 v11, v23

    goto :goto_2

    :cond_7
    move/from16 v22, v4

    move-object/from16 v23, v11

    if-eqz v22, :cond_a

    const/4 v4, 0x0

    :goto_5
    if-ge v4, v6, :cond_a

    invoke-virtual {v13, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/nk1;

    instance-of v15, v11, Llyiahf/vczjk/uk3;

    if-eqz v15, :cond_9

    check-cast v11, Llyiahf/vczjk/uk3;

    iget v15, v11, Llyiahf/vczjk/uk3;->o0ooOoO:I

    move/from16 v21, v4

    const/4 v4, 0x1

    if-ne v15, v4, :cond_8

    const/4 v4, 0x0

    invoke-static {v4, v8, v11, v2}, Llyiahf/vczjk/cp7;->OooOoo(ILlyiahf/vczjk/q90;Llyiahf/vczjk/nk1;Z)V

    goto :goto_7

    :cond_8
    :goto_6
    const/4 v4, 0x0

    goto :goto_7

    :cond_9
    move/from16 v21, v4

    goto :goto_6

    :goto_7
    add-int/lit8 v11, v21, 0x1

    move v4, v11

    goto :goto_5

    :cond_a
    const/4 v4, 0x0

    invoke-static {v4, v8, v1, v2}, Llyiahf/vczjk/cp7;->OooOoo(ILlyiahf/vczjk/q90;Llyiahf/vczjk/nk1;Z)V

    if-eqz v19, :cond_c

    const/4 v4, 0x0

    :goto_8
    if-ge v4, v6, :cond_c

    invoke-virtual {v13, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/nk1;

    instance-of v15, v11, Llyiahf/vczjk/w50;

    if-eqz v15, :cond_b

    check-cast v11, Llyiahf/vczjk/w50;

    invoke-virtual {v11}, Llyiahf/vczjk/w50;->OoooO0()I

    move-result v15

    if-nez v15, :cond_b

    invoke-virtual {v11}, Llyiahf/vczjk/w50;->OoooO00()Z

    move-result v15

    if-eqz v15, :cond_b

    const/4 v15, 0x1

    invoke-static {v15, v8, v11, v2}, Llyiahf/vczjk/cp7;->OooOoo(ILlyiahf/vczjk/q90;Llyiahf/vczjk/nk1;Z)V

    :cond_b
    add-int/lit8 v4, v4, 0x1

    goto :goto_8

    :cond_c
    if-ne v14, v12, :cond_d

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOO0o()I

    move-result v4

    const/4 v11, 0x0

    invoke-virtual {v1, v11, v4}, Llyiahf/vczjk/nk1;->Oooo00O(II)V

    goto :goto_9

    :cond_d
    const/4 v11, 0x0

    invoke-virtual {v10, v11}, Llyiahf/vczjk/nj1;->OooOO0o(I)V

    iput v11, v1, Llyiahf/vczjk/nk1;->OoooOoo:I

    :goto_9
    const/4 v4, 0x0

    const/4 v11, 0x0

    const/4 v14, 0x0

    :goto_a
    if-ge v4, v6, :cond_13

    invoke-virtual {v13, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Llyiahf/vczjk/nk1;

    move/from16 v19, v4

    instance-of v4, v15, Llyiahf/vczjk/uk3;

    if-eqz v4, :cond_11

    check-cast v15, Llyiahf/vczjk/uk3;

    iget v4, v15, Llyiahf/vczjk/uk3;->o0ooOoO:I

    if-nez v4, :cond_12

    iget v4, v15, Llyiahf/vczjk/uk3;->o00oO0O:I

    const/4 v11, -0x1

    if-eq v4, v11, :cond_e

    invoke-virtual {v15, v4}, Llyiahf/vczjk/uk3;->Oooo0oO(I)V

    goto :goto_b

    :cond_e
    iget v4, v15, Llyiahf/vczjk/uk3;->o0ooOO0:I

    if-eq v4, v11, :cond_f

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOoO()Z

    move-result v4

    if-eqz v4, :cond_f

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOO0o()I

    move-result v4

    iget v11, v15, Llyiahf/vczjk/uk3;->o0ooOO0:I

    sub-int/2addr v4, v11

    invoke-virtual {v15, v4}, Llyiahf/vczjk/uk3;->Oooo0oO(I)V

    goto :goto_b

    :cond_f
    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOoO()Z

    move-result v4

    if-eqz v4, :cond_10

    iget v4, v15, Llyiahf/vczjk/uk3;->o00oO0o:F

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOO0o()I

    move-result v11

    int-to-float v11, v11

    mul-float/2addr v4, v11

    add-float v4, v4, v20

    float-to-int v4, v4

    invoke-virtual {v15, v4}, Llyiahf/vczjk/uk3;->Oooo0oO(I)V

    :cond_10
    :goto_b
    const/4 v11, 0x1

    goto :goto_c

    :cond_11
    instance-of v4, v15, Llyiahf/vczjk/w50;

    if-eqz v4, :cond_12

    check-cast v15, Llyiahf/vczjk/w50;

    invoke-virtual {v15}, Llyiahf/vczjk/w50;->OoooO0()I

    move-result v4

    const/4 v15, 0x1

    if-ne v4, v15, :cond_12

    const/4 v14, 0x1

    :cond_12
    :goto_c
    add-int/lit8 v4, v19, 0x1

    goto :goto_a

    :cond_13
    if-eqz v11, :cond_15

    const/4 v4, 0x0

    :goto_d
    if-ge v4, v6, :cond_15

    invoke-virtual {v13, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/nk1;

    instance-of v15, v11, Llyiahf/vczjk/uk3;

    if-eqz v15, :cond_14

    check-cast v11, Llyiahf/vczjk/uk3;

    iget v15, v11, Llyiahf/vczjk/uk3;->o0ooOoO:I

    if-nez v15, :cond_14

    const/4 v15, 0x1

    invoke-static {v15, v8, v11}, Llyiahf/vczjk/cp7;->OoooO0O(ILlyiahf/vczjk/q90;Llyiahf/vczjk/nk1;)V

    :cond_14
    add-int/lit8 v4, v4, 0x1

    goto :goto_d

    :cond_15
    const/4 v4, 0x0

    invoke-static {v4, v8, v1}, Llyiahf/vczjk/cp7;->OoooO0O(ILlyiahf/vczjk/q90;Llyiahf/vczjk/nk1;)V

    if-eqz v14, :cond_17

    const/4 v4, 0x0

    :goto_e
    if-ge v4, v6, :cond_17

    invoke-virtual {v13, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/nk1;

    instance-of v14, v11, Llyiahf/vczjk/w50;

    if-eqz v14, :cond_16

    check-cast v11, Llyiahf/vczjk/w50;

    invoke-virtual {v11}, Llyiahf/vczjk/w50;->OoooO0()I

    move-result v14

    const/4 v15, 0x1

    if-ne v14, v15, :cond_16

    invoke-virtual {v11}, Llyiahf/vczjk/w50;->OoooO00()Z

    move-result v14

    if-eqz v14, :cond_16

    invoke-static {v15, v8, v11}, Llyiahf/vczjk/cp7;->OoooO0O(ILlyiahf/vczjk/q90;Llyiahf/vczjk/nk1;)V

    :cond_16
    add-int/lit8 v4, v4, 0x1

    goto :goto_e

    :cond_17
    const/4 v4, 0x0

    :goto_f
    if-ge v4, v6, :cond_1b

    invoke-virtual {v13, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/nk1;

    invoke-virtual {v11}, Llyiahf/vczjk/nk1;->OooOo()Z

    move-result v14

    if-eqz v14, :cond_1a

    invoke-static {v11}, Llyiahf/vczjk/cp7;->OooO0oo(Llyiahf/vczjk/nk1;)Z

    move-result v14

    if-eqz v14, :cond_1a

    sget-object v14, Llyiahf/vczjk/cp7;->OooO0OO:Llyiahf/vczjk/p90;

    invoke-static {v11, v8, v14}, Llyiahf/vczjk/ok1;->OoooO0(Llyiahf/vczjk/nk1;Llyiahf/vczjk/q90;Llyiahf/vczjk/p90;)V

    instance-of v14, v11, Llyiahf/vczjk/uk3;

    if-eqz v14, :cond_19

    move-object v14, v11

    check-cast v14, Llyiahf/vczjk/uk3;

    iget v14, v14, Llyiahf/vczjk/uk3;->o0ooOoO:I

    if-nez v14, :cond_18

    const/4 v14, 0x0

    invoke-static {v14, v8, v11}, Llyiahf/vczjk/cp7;->OoooO0O(ILlyiahf/vczjk/q90;Llyiahf/vczjk/nk1;)V

    goto :goto_10

    :cond_18
    const/4 v14, 0x0

    invoke-static {v14, v8, v11, v2}, Llyiahf/vczjk/cp7;->OooOoo(ILlyiahf/vczjk/q90;Llyiahf/vczjk/nk1;Z)V

    goto :goto_10

    :cond_19
    const/4 v14, 0x0

    invoke-static {v14, v8, v11, v2}, Llyiahf/vczjk/cp7;->OooOoo(ILlyiahf/vczjk/q90;Llyiahf/vczjk/nk1;Z)V

    invoke-static {v14, v8, v11}, Llyiahf/vczjk/cp7;->OoooO0O(ILlyiahf/vczjk/q90;Llyiahf/vczjk/nk1;)V

    :cond_1a
    :goto_10
    add-int/lit8 v4, v4, 0x1

    goto :goto_f

    :cond_1b
    const/4 v2, 0x0

    :goto_11
    if-ge v2, v3, :cond_1f

    iget-object v4, v1, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/nk1;

    invoke-virtual {v4}, Llyiahf/vczjk/nk1;->OooOo()Z

    move-result v6

    if-eqz v6, :cond_1d

    instance-of v6, v4, Llyiahf/vczjk/uk3;

    if-nez v6, :cond_1d

    instance-of v6, v4, Llyiahf/vczjk/w50;

    if-nez v6, :cond_1d

    instance-of v6, v4, Llyiahf/vczjk/g43;

    if-nez v6, :cond_1d

    iget-boolean v6, v4, Llyiahf/vczjk/nk1;->Oooo000:Z

    if-nez v6, :cond_1d

    const/4 v11, 0x0

    invoke-virtual {v4, v11}, Llyiahf/vczjk/nk1;->OooOO0O(I)Llyiahf/vczjk/mk1;

    move-result-object v6

    const/4 v15, 0x1

    invoke-virtual {v4, v15}, Llyiahf/vczjk/nk1;->OooOO0O(I)Llyiahf/vczjk/mk1;

    move-result-object v8

    if-ne v6, v9, :cond_1c

    iget v6, v4, Llyiahf/vczjk/nk1;->OooOOo0:I

    if-eq v6, v15, :cond_1c

    if-ne v8, v9, :cond_1c

    iget v6, v4, Llyiahf/vczjk/nk1;->OooOOo:I

    if-eq v6, v15, :cond_1c

    goto :goto_12

    :cond_1c
    new-instance v6, Llyiahf/vczjk/p90;

    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    iget-object v8, v1, Llyiahf/vczjk/ok1;->o0ooOoO:Llyiahf/vczjk/q90;

    invoke-static {v4, v8, v6}, Llyiahf/vczjk/ok1;->OoooO0(Llyiahf/vczjk/nk1;Llyiahf/vczjk/q90;Llyiahf/vczjk/p90;)V

    :cond_1d
    :goto_12
    add-int/lit8 v2, v2, 0x1

    goto :goto_11

    :cond_1e
    move/from16 v18, v4

    move-object/from16 v23, v11

    :cond_1f
    sget-object v2, Llyiahf/vczjk/mk1;->OooOOO:Llyiahf/vczjk/mk1;

    iget-object v4, v1, Llyiahf/vczjk/ok1;->o0Oo0oo:Llyiahf/vczjk/yz4;

    const/4 v6, 0x2

    if-le v3, v6, :cond_20

    if-eq v5, v2, :cond_22

    if-ne v7, v2, :cond_20

    goto :goto_14

    :cond_20
    move/from16 v26, v3

    move-object/from16 v22, v10

    :cond_21
    :goto_13
    move/from16 v6, v18

    goto/16 :goto_3b

    :cond_22
    :goto_14
    iget v13, v1, Llyiahf/vczjk/ok1;->o000000o:I

    const/16 v14, 0x400

    invoke-static {v13, v14}, Llyiahf/vczjk/sb;->OooOo(II)Z

    move-result v13

    if-eqz v13, :cond_20

    iget-object v13, v1, Llyiahf/vczjk/ok1;->o0ooOoO:Llyiahf/vczjk/q90;

    iget-object v14, v1, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v14}, Ljava/util/ArrayList;->size()I

    move-result v15

    const/4 v11, 0x0

    :goto_15
    if-ge v11, v15, :cond_25

    invoke-virtual {v14, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v20

    move-object/from16 v6, v20

    check-cast v6, Llyiahf/vczjk/nk1;

    iget-object v8, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    move-object/from16 v22, v8

    const/16 v17, 0x0

    aget-object v8, v22, v17

    move/from16 v24, v11

    const/16 v16, 0x1

    aget-object v11, v22, v16

    move-object/from16 v22, v10

    iget-object v10, v6, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    move-object/from16 v25, v10

    aget-object v10, v25, v17

    move/from16 v26, v3

    aget-object v3, v25, v16

    invoke-static {v8, v11, v10, v3}, Llyiahf/vczjk/nqa;->OoooOOO(Llyiahf/vczjk/mk1;Llyiahf/vczjk/mk1;Llyiahf/vczjk/mk1;Llyiahf/vczjk/mk1;)Z

    move-result v3

    if-nez v3, :cond_23

    goto :goto_13

    :cond_23
    instance-of v3, v6, Llyiahf/vczjk/g43;

    if-eqz v3, :cond_24

    goto :goto_13

    :cond_24
    add-int/lit8 v11, v24, 0x1

    move-object/from16 v10, v22

    move/from16 v3, v26

    const/4 v6, 0x2

    goto :goto_15

    :cond_25
    move/from16 v26, v3

    move-object/from16 v22, v10

    const/4 v3, 0x0

    const/4 v6, 0x0

    const/4 v8, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    :goto_16
    if-ge v3, v15, :cond_38

    invoke-virtual {v14, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v27

    move/from16 v28, v3

    move-object/from16 v3, v27

    check-cast v3, Llyiahf/vczjk/nk1;

    move-object/from16 v27, v6

    iget-object v6, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    move-object/from16 v29, v6

    const/16 v17, 0x0

    aget-object v6, v29, v17

    move-object/from16 v30, v8

    const/16 v16, 0x1

    aget-object v8, v29, v16

    move-object/from16 v29, v10

    iget-object v10, v3, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    move-object/from16 v31, v10

    aget-object v10, v31, v17

    move-object/from16 v32, v11

    aget-object v11, v31, v16

    invoke-static {v6, v8, v10, v11}, Llyiahf/vczjk/nqa;->OoooOOO(Llyiahf/vczjk/mk1;Llyiahf/vczjk/mk1;Llyiahf/vczjk/mk1;Llyiahf/vczjk/mk1;)Z

    move-result v6

    if-nez v6, :cond_26

    iget-object v6, v1, Llyiahf/vczjk/ok1;->o00000oO:Llyiahf/vczjk/p90;

    invoke-static {v3, v13, v6}, Llyiahf/vczjk/ok1;->OoooO0(Llyiahf/vczjk/nk1;Llyiahf/vczjk/q90;Llyiahf/vczjk/p90;)V

    :cond_26
    instance-of v6, v3, Llyiahf/vczjk/uk3;

    if-eqz v6, :cond_2b

    move-object v8, v3

    check-cast v8, Llyiahf/vczjk/uk3;

    iget v10, v8, Llyiahf/vczjk/uk3;->o0ooOoO:I

    if-nez v10, :cond_28

    if-nez v29, :cond_27

    new-instance v10, Ljava/util/ArrayList;

    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    goto :goto_17

    :cond_27
    move-object/from16 v10, v29

    :goto_17
    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_18

    :cond_28
    move-object/from16 v10, v29

    :goto_18
    iget v11, v8, Llyiahf/vczjk/uk3;->o0ooOoO:I

    move/from16 v31, v6

    const/4 v6, 0x1

    if-ne v11, v6, :cond_2a

    if-nez v27, :cond_29

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    goto :goto_19

    :cond_29
    move-object/from16 v6, v27

    :goto_19
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1a

    :cond_2a
    move-object/from16 v6, v27

    goto :goto_1a

    :cond_2b
    move/from16 v31, v6

    move-object/from16 v6, v27

    move-object/from16 v10, v29

    :goto_1a
    instance-of v8, v3, Llyiahf/vczjk/in3;

    if-eqz v8, :cond_33

    instance-of v8, v3, Llyiahf/vczjk/w50;

    if-eqz v8, :cond_30

    move-object v8, v3

    check-cast v8, Llyiahf/vczjk/w50;

    invoke-virtual {v8}, Llyiahf/vczjk/w50;->OoooO0()I

    move-result v11

    if-nez v11, :cond_2d

    if-nez v30, :cond_2c

    new-instance v11, Ljava/util/ArrayList;

    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    goto :goto_1b

    :cond_2c
    move-object/from16 v11, v30

    :goto_1b
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v30, v11

    :cond_2d
    invoke-virtual {v8}, Llyiahf/vczjk/w50;->OoooO0()I

    move-result v11

    move-object/from16 v27, v6

    const/4 v6, 0x1

    if-ne v11, v6, :cond_2f

    if-nez v32, :cond_2e

    new-instance v11, Ljava/util/ArrayList;

    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    goto :goto_1c

    :cond_2e
    move-object/from16 v11, v32

    :goto_1c
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1d

    :cond_2f
    move-object/from16 v11, v32

    :goto_1d
    move-object/from16 v8, v30

    goto :goto_20

    :cond_30
    move-object/from16 v27, v6

    move-object v6, v3

    check-cast v6, Llyiahf/vczjk/in3;

    if-nez v30, :cond_31

    new-instance v8, Ljava/util/ArrayList;

    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    goto :goto_1e

    :cond_31
    move-object/from16 v8, v30

    :goto_1e
    invoke-virtual {v8, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    if-nez v32, :cond_32

    new-instance v11, Ljava/util/ArrayList;

    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    goto :goto_1f

    :cond_32
    move-object/from16 v11, v32

    :goto_1f
    invoke-virtual {v11, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_20

    :cond_33
    move-object/from16 v27, v6

    move-object/from16 v8, v30

    move-object/from16 v11, v32

    :goto_20
    iget-object v6, v3, Llyiahf/vczjk/nk1;->Oooo0:Llyiahf/vczjk/nj1;

    iget-object v6, v6, Llyiahf/vczjk/nj1;->OooO0o:Llyiahf/vczjk/nj1;

    if-nez v6, :cond_35

    iget-object v6, v3, Llyiahf/vczjk/nk1;->Oooo0OO:Llyiahf/vczjk/nj1;

    iget-object v6, v6, Llyiahf/vczjk/nj1;->OooO0o:Llyiahf/vczjk/nj1;

    if-nez v6, :cond_35

    if-nez v31, :cond_35

    instance-of v6, v3, Llyiahf/vczjk/w50;

    if-nez v6, :cond_35

    if-nez v24, :cond_34

    new-instance v24, Ljava/util/ArrayList;

    invoke-direct/range {v24 .. v24}, Ljava/util/ArrayList;-><init>()V

    :cond_34
    move-object/from16 v6, v24

    invoke-virtual {v6, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v24, v6

    :cond_35
    iget-object v6, v3, Llyiahf/vczjk/nk1;->Oooo0O0:Llyiahf/vczjk/nj1;

    iget-object v6, v6, Llyiahf/vczjk/nj1;->OooO0o:Llyiahf/vczjk/nj1;

    if-nez v6, :cond_37

    iget-object v6, v3, Llyiahf/vczjk/nk1;->Oooo0o0:Llyiahf/vczjk/nj1;

    iget-object v6, v6, Llyiahf/vczjk/nj1;->OooO0o:Llyiahf/vczjk/nj1;

    if-nez v6, :cond_37

    iget-object v6, v3, Llyiahf/vczjk/nk1;->Oooo0o:Llyiahf/vczjk/nj1;

    iget-object v6, v6, Llyiahf/vczjk/nj1;->OooO0o:Llyiahf/vczjk/nj1;

    if-nez v6, :cond_37

    if-nez v31, :cond_37

    instance-of v6, v3, Llyiahf/vczjk/w50;

    if-nez v6, :cond_37

    if-nez v25, :cond_36

    new-instance v25, Ljava/util/ArrayList;

    invoke-direct/range {v25 .. v25}, Ljava/util/ArrayList;-><init>()V

    :cond_36
    move-object/from16 v6, v25

    invoke-virtual {v6, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v25, v6

    :cond_37
    add-int/lit8 v3, v28, 0x1

    move-object/from16 v6, v27

    goto/16 :goto_16

    :cond_38
    move-object/from16 v27, v6

    move-object/from16 v30, v8

    move-object/from16 v29, v10

    move-object/from16 v32, v11

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    if-eqz v27, :cond_39

    invoke-virtual/range {v27 .. v27}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_21
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_39

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/uk3;

    const/4 v10, 0x0

    const/4 v11, 0x0

    invoke-static {v8, v11, v3, v10}, Llyiahf/vczjk/nqa;->OooOo(Llyiahf/vczjk/nk1;ILjava/util/ArrayList;Llyiahf/vczjk/lma;)Llyiahf/vczjk/lma;

    goto :goto_21

    :cond_39
    const/4 v10, 0x0

    const/4 v11, 0x0

    if-eqz v30, :cond_3a

    invoke-virtual/range {v30 .. v30}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_22
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_3a

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/in3;

    invoke-static {v8, v11, v3, v10}, Llyiahf/vczjk/nqa;->OooOo(Llyiahf/vczjk/nk1;ILjava/util/ArrayList;Llyiahf/vczjk/lma;)Llyiahf/vczjk/lma;

    move-result-object v13

    invoke-virtual {v8, v11, v3, v13}, Llyiahf/vczjk/in3;->Oooo0oo(ILjava/util/ArrayList;Llyiahf/vczjk/lma;)V

    invoke-virtual {v13, v3}, Llyiahf/vczjk/lma;->OooO00o(Ljava/util/ArrayList;)V

    const/4 v10, 0x0

    const/4 v11, 0x0

    goto :goto_22

    :cond_3a
    const/4 v6, 0x2

    invoke-virtual {v1, v6}, Llyiahf/vczjk/nk1;->OooOO0(I)Llyiahf/vczjk/nj1;

    move-result-object v8

    iget-object v6, v8, Llyiahf/vczjk/nj1;->OooO00o:Ljava/util/HashSet;

    if-eqz v6, :cond_3b

    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_23
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_3b

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/nj1;

    iget-object v8, v8, Llyiahf/vczjk/nj1;->OooO0Oo:Llyiahf/vczjk/nk1;

    const/4 v10, 0x0

    const/4 v11, 0x0

    invoke-static {v8, v11, v3, v10}, Llyiahf/vczjk/nqa;->OooOo(Llyiahf/vczjk/nk1;ILjava/util/ArrayList;Llyiahf/vczjk/lma;)Llyiahf/vczjk/lma;

    goto :goto_23

    :cond_3b
    const/4 v6, 0x4

    invoke-virtual {v1, v6}, Llyiahf/vczjk/nk1;->OooOO0(I)Llyiahf/vczjk/nj1;

    move-result-object v6

    iget-object v6, v6, Llyiahf/vczjk/nj1;->OooO00o:Ljava/util/HashSet;

    if-eqz v6, :cond_3c

    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_24
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_3c

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/nj1;

    iget-object v8, v8, Llyiahf/vczjk/nj1;->OooO0Oo:Llyiahf/vczjk/nk1;

    const/4 v10, 0x0

    const/4 v11, 0x0

    invoke-static {v8, v11, v3, v10}, Llyiahf/vczjk/nqa;->OooOo(Llyiahf/vczjk/nk1;ILjava/util/ArrayList;Llyiahf/vczjk/lma;)Llyiahf/vczjk/lma;

    goto :goto_24

    :cond_3c
    const/4 v6, 0x7

    invoke-virtual {v1, v6}, Llyiahf/vczjk/nk1;->OooOO0(I)Llyiahf/vczjk/nj1;

    move-result-object v8

    iget-object v8, v8, Llyiahf/vczjk/nj1;->OooO00o:Ljava/util/HashSet;

    if-eqz v8, :cond_3d

    invoke-virtual {v8}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v8

    :goto_25
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    move-result v10

    if-eqz v10, :cond_3d

    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/nj1;

    iget-object v10, v10, Llyiahf/vczjk/nj1;->OooO0Oo:Llyiahf/vczjk/nk1;

    const/4 v11, 0x0

    const/4 v13, 0x0

    invoke-static {v10, v11, v3, v13}, Llyiahf/vczjk/nqa;->OooOo(Llyiahf/vczjk/nk1;ILjava/util/ArrayList;Llyiahf/vczjk/lma;)Llyiahf/vczjk/lma;

    goto :goto_25

    :cond_3d
    const/4 v11, 0x0

    const/4 v13, 0x0

    if-eqz v24, :cond_3e

    invoke-virtual/range {v24 .. v24}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v8

    :goto_26
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    move-result v10

    if-eqz v10, :cond_3e

    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/nk1;

    invoke-static {v10, v11, v3, v13}, Llyiahf/vczjk/nqa;->OooOo(Llyiahf/vczjk/nk1;ILjava/util/ArrayList;Llyiahf/vczjk/lma;)Llyiahf/vczjk/lma;

    goto :goto_26

    :cond_3e
    if-eqz v29, :cond_3f

    invoke-virtual/range {v29 .. v29}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v8

    :goto_27
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    move-result v10

    if-eqz v10, :cond_3f

    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/uk3;

    const/4 v11, 0x1

    invoke-static {v10, v11, v3, v13}, Llyiahf/vczjk/nqa;->OooOo(Llyiahf/vczjk/nk1;ILjava/util/ArrayList;Llyiahf/vczjk/lma;)Llyiahf/vczjk/lma;

    goto :goto_27

    :cond_3f
    const/4 v11, 0x1

    if-eqz v32, :cond_40

    invoke-virtual/range {v32 .. v32}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v8

    :goto_28
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    move-result v10

    if-eqz v10, :cond_40

    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/in3;

    invoke-static {v10, v11, v3, v13}, Llyiahf/vczjk/nqa;->OooOo(Llyiahf/vczjk/nk1;ILjava/util/ArrayList;Llyiahf/vczjk/lma;)Llyiahf/vczjk/lma;

    move-result-object v6

    invoke-virtual {v10, v11, v3, v6}, Llyiahf/vczjk/in3;->Oooo0oo(ILjava/util/ArrayList;Llyiahf/vczjk/lma;)V

    invoke-virtual {v6, v3}, Llyiahf/vczjk/lma;->OooO00o(Ljava/util/ArrayList;)V

    const/4 v6, 0x7

    const/4 v11, 0x1

    const/4 v13, 0x0

    goto :goto_28

    :cond_40
    const/4 v6, 0x3

    invoke-virtual {v1, v6}, Llyiahf/vczjk/nk1;->OooOO0(I)Llyiahf/vczjk/nj1;

    move-result-object v6

    iget-object v6, v6, Llyiahf/vczjk/nj1;->OooO00o:Ljava/util/HashSet;

    if-eqz v6, :cond_41

    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_29
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_41

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/nj1;

    iget-object v8, v8, Llyiahf/vczjk/nj1;->OooO0Oo:Llyiahf/vczjk/nk1;

    const/4 v10, 0x0

    const/4 v11, 0x1

    invoke-static {v8, v11, v3, v10}, Llyiahf/vczjk/nqa;->OooOo(Llyiahf/vczjk/nk1;ILjava/util/ArrayList;Llyiahf/vczjk/lma;)Llyiahf/vczjk/lma;

    goto :goto_29

    :cond_41
    const/4 v6, 0x6

    invoke-virtual {v1, v6}, Llyiahf/vczjk/nk1;->OooOO0(I)Llyiahf/vczjk/nj1;

    move-result-object v6

    iget-object v6, v6, Llyiahf/vczjk/nj1;->OooO00o:Ljava/util/HashSet;

    if-eqz v6, :cond_42

    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_2a
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_42

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/nj1;

    iget-object v8, v8, Llyiahf/vczjk/nj1;->OooO0Oo:Llyiahf/vczjk/nk1;

    const/4 v10, 0x0

    const/4 v11, 0x1

    invoke-static {v8, v11, v3, v10}, Llyiahf/vczjk/nqa;->OooOo(Llyiahf/vczjk/nk1;ILjava/util/ArrayList;Llyiahf/vczjk/lma;)Llyiahf/vczjk/lma;

    goto :goto_2a

    :cond_42
    const/4 v6, 0x5

    invoke-virtual {v1, v6}, Llyiahf/vczjk/nk1;->OooOO0(I)Llyiahf/vczjk/nj1;

    move-result-object v8

    iget-object v6, v8, Llyiahf/vczjk/nj1;->OooO00o:Ljava/util/HashSet;

    if-eqz v6, :cond_43

    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_2b
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_43

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/nj1;

    iget-object v8, v8, Llyiahf/vczjk/nj1;->OooO0Oo:Llyiahf/vczjk/nk1;

    const/4 v10, 0x0

    const/4 v11, 0x1

    invoke-static {v8, v11, v3, v10}, Llyiahf/vczjk/nqa;->OooOo(Llyiahf/vczjk/nk1;ILjava/util/ArrayList;Llyiahf/vczjk/lma;)Llyiahf/vczjk/lma;

    goto :goto_2b

    :cond_43
    const/4 v6, 0x7

    invoke-virtual {v1, v6}, Llyiahf/vczjk/nk1;->OooOO0(I)Llyiahf/vczjk/nj1;

    move-result-object v6

    iget-object v6, v6, Llyiahf/vczjk/nj1;->OooO00o:Ljava/util/HashSet;

    if-eqz v6, :cond_44

    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_2c
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_44

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/nj1;

    iget-object v8, v8, Llyiahf/vczjk/nj1;->OooO0Oo:Llyiahf/vczjk/nk1;

    const/4 v10, 0x0

    const/4 v11, 0x1

    invoke-static {v8, v11, v3, v10}, Llyiahf/vczjk/nqa;->OooOo(Llyiahf/vczjk/nk1;ILjava/util/ArrayList;Llyiahf/vczjk/lma;)Llyiahf/vczjk/lma;

    goto :goto_2c

    :cond_44
    const/4 v10, 0x0

    const/4 v11, 0x1

    if-eqz v25, :cond_45

    invoke-virtual/range {v25 .. v25}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_2d
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_45

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/nk1;

    invoke-static {v8, v11, v3, v10}, Llyiahf/vczjk/nqa;->OooOo(Llyiahf/vczjk/nk1;ILjava/util/ArrayList;Llyiahf/vczjk/lma;)Llyiahf/vczjk/lma;

    goto :goto_2d

    :cond_45
    const/4 v6, 0x0

    :goto_2e
    if-ge v6, v15, :cond_4c

    invoke-virtual {v14, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/nk1;

    iget-object v10, v8, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    const/16 v17, 0x0

    aget-object v11, v10, v17

    if-ne v11, v9, :cond_4a

    const/16 v16, 0x1

    aget-object v10, v10, v16

    if-ne v10, v9, :cond_4a

    iget v10, v8, Llyiahf/vczjk/nk1;->o00ooo:I

    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v11

    const/4 v13, 0x0

    :goto_2f
    if-ge v13, v11, :cond_47

    invoke-virtual {v3, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v24

    move/from16 v25, v6

    move-object/from16 v6, v24

    check-cast v6, Llyiahf/vczjk/lma;

    move-object/from16 v24, v9

    iget v9, v6, Llyiahf/vczjk/lma;->OooO0O0:I

    if-ne v10, v9, :cond_46

    goto :goto_30

    :cond_46
    add-int/lit8 v13, v13, 0x1

    move-object/from16 v9, v24

    move/from16 v6, v25

    goto :goto_2f

    :cond_47
    move/from16 v25, v6

    move-object/from16 v24, v9

    const/4 v6, 0x0

    :goto_30
    iget v8, v8, Llyiahf/vczjk/nk1;->oo000o:I

    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v9

    const/4 v10, 0x0

    :goto_31
    if-ge v10, v9, :cond_49

    invoke-virtual {v3, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/lma;

    iget v13, v11, Llyiahf/vczjk/lma;->OooO0O0:I

    if-ne v8, v13, :cond_48

    goto :goto_32

    :cond_48
    add-int/lit8 v10, v10, 0x1

    goto :goto_31

    :cond_49
    const/4 v11, 0x0

    :goto_32
    if-eqz v6, :cond_4b

    if-eqz v11, :cond_4b

    const/4 v8, 0x0

    invoke-virtual {v6, v8, v11}, Llyiahf/vczjk/lma;->OooO0OO(ILlyiahf/vczjk/lma;)V

    const/4 v8, 0x2

    iput v8, v11, Llyiahf/vczjk/lma;->OooO0OO:I

    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    goto :goto_33

    :cond_4a
    move/from16 v25, v6

    move-object/from16 v24, v9

    :cond_4b
    :goto_33
    add-int/lit8 v6, v25, 0x1

    move-object/from16 v9, v24

    goto :goto_2e

    :cond_4c
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v6

    const/4 v11, 0x1

    if-gt v6, v11, :cond_4d

    goto/16 :goto_13

    :cond_4d
    iget-object v6, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    const/16 v17, 0x0

    aget-object v6, v6, v17

    if-ne v6, v2, :cond_51

    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v6

    const/4 v8, 0x0

    const/4 v9, 0x0

    :cond_4e
    :goto_34
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v10

    if-eqz v10, :cond_50

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/lma;

    iget v11, v10, Llyiahf/vczjk/lma;->OooO0OO:I

    const/4 v15, 0x1

    if-ne v11, v15, :cond_4f

    goto :goto_34

    :cond_4f
    const/4 v11, 0x0

    invoke-virtual {v10, v4, v11}, Llyiahf/vczjk/lma;->OooO0O0(Llyiahf/vczjk/yz4;I)I

    move-result v13

    if-le v13, v8, :cond_4e

    move-object v9, v10

    move v8, v13

    goto :goto_34

    :cond_50
    if-eqz v9, :cond_51

    invoke-virtual {v1, v12}, Llyiahf/vczjk/nk1;->Oooo0(Llyiahf/vczjk/mk1;)V

    invoke-virtual {v1, v8}, Llyiahf/vczjk/nk1;->Oooo0OO(I)V

    goto :goto_35

    :cond_51
    const/4 v9, 0x0

    :goto_35
    iget-object v6, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    const/16 v16, 0x1

    aget-object v6, v6, v16

    if-ne v6, v2, :cond_55

    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v3

    const/4 v6, 0x0

    const/4 v8, 0x0

    :cond_52
    :goto_36
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v10

    if-eqz v10, :cond_54

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/lma;

    iget v11, v10, Llyiahf/vczjk/lma;->OooO0OO:I

    if-nez v11, :cond_53

    goto :goto_36

    :cond_53
    const/4 v11, 0x1

    invoke-virtual {v10, v4, v11}, Llyiahf/vczjk/lma;->OooO0O0(Llyiahf/vczjk/yz4;I)I

    move-result v13

    if-le v13, v6, :cond_52

    move-object v8, v10

    move v6, v13

    goto :goto_36

    :cond_54
    if-eqz v8, :cond_55

    invoke-virtual {v1, v12}, Llyiahf/vczjk/nk1;->Oooo0O0(Llyiahf/vczjk/mk1;)V

    invoke-virtual {v1, v6}, Llyiahf/vczjk/nk1;->Oooo00o(I)V

    goto :goto_37

    :cond_55
    const/4 v8, 0x0

    :goto_37
    if-nez v9, :cond_56

    if-eqz v8, :cond_21

    :cond_56
    if-ne v5, v2, :cond_58

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOOOO()I

    move-result v3

    if-ge v0, v3, :cond_57

    if-lez v0, :cond_57

    invoke-virtual {v1, v0}, Llyiahf/vczjk/nk1;->Oooo0OO(I)V

    const/4 v11, 0x1

    iput-boolean v11, v1, Llyiahf/vczjk/ok1;->o00000:Z

    goto :goto_38

    :cond_57
    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOOOO()I

    move-result v0

    :cond_58
    :goto_38
    if-ne v7, v2, :cond_5a

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOO0o()I

    move-result v3

    move/from16 v6, v18

    if-ge v6, v3, :cond_59

    if-lez v6, :cond_59

    invoke-virtual {v1, v6}, Llyiahf/vczjk/nk1;->Oooo00o(I)V

    const/4 v11, 0x1

    iput-boolean v11, v1, Llyiahf/vczjk/ok1;->o00000O0:Z

    goto :goto_39

    :cond_59
    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOO0o()I

    move-result v3

    goto :goto_3a

    :cond_5a
    move/from16 v6, v18

    :goto_39
    move v3, v6

    :goto_3a
    move v6, v3

    move v3, v0

    const/4 v0, 0x1

    goto :goto_3c

    :goto_3b
    move v3, v0

    const/4 v0, 0x0

    :goto_3c
    const/16 v8, 0x40

    invoke-virtual {v1, v8}, Llyiahf/vczjk/ok1;->OoooO0O(I)Z

    move-result v9

    if-nez v9, :cond_5c

    const/16 v9, 0x80

    invoke-virtual {v1, v9}, Llyiahf/vczjk/ok1;->OoooO0O(I)Z

    move-result v9

    if-eqz v9, :cond_5b

    goto :goto_3d

    :cond_5b
    const/4 v9, 0x0

    goto :goto_3e

    :cond_5c
    :goto_3d
    const/4 v9, 0x1

    :goto_3e
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v11, 0x0

    iput-boolean v11, v4, Llyiahf/vczjk/yz4;->OooO0oO:Z

    iget v10, v1, Llyiahf/vczjk/ok1;->o000000o:I

    if-eqz v10, :cond_5d

    if-eqz v9, :cond_5d

    const/4 v15, 0x1

    iput-boolean v15, v4, Llyiahf/vczjk/yz4;->OooO0oO:Z

    goto :goto_3f

    :cond_5d
    const/4 v15, 0x1

    :goto_3f
    iget-object v9, v1, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    iget-object v10, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    aget-object v13, v10, v11

    if-eq v13, v2, :cond_5f

    aget-object v10, v10, v15

    if-ne v10, v2, :cond_5e

    goto :goto_40

    :cond_5e
    move v10, v11

    goto :goto_41

    :cond_5f
    :goto_40
    const/4 v10, 0x1

    :goto_41
    iput v11, v1, Llyiahf/vczjk/ok1;->o0O0O00:I

    iput v11, v1, Llyiahf/vczjk/ok1;->o000OOo:I

    move/from16 v13, v26

    const/4 v11, 0x0

    :goto_42
    if-ge v11, v13, :cond_61

    iget-object v14, v1, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v14, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/nk1;

    instance-of v15, v14, Llyiahf/vczjk/ok1;

    if-eqz v15, :cond_60

    check-cast v14, Llyiahf/vczjk/ok1;

    invoke-virtual {v14}, Llyiahf/vczjk/ok1;->OoooO00()V

    :cond_60
    add-int/lit8 v11, v11, 0x1

    goto :goto_42

    :cond_61
    invoke-virtual {v1, v8}, Llyiahf/vczjk/ok1;->OoooO0O(I)Z

    move-result v11

    move v14, v0

    const/4 v0, 0x0

    const/4 v15, 0x1

    :goto_43
    if-eqz v15, :cond_75

    const/16 v16, 0x1

    add-int/lit8 v8, v0, 0x1

    :try_start_0
    invoke-virtual {v4}, Llyiahf/vczjk/yz4;->OooOo00()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_b

    move/from16 v24, v10

    const/4 v10, 0x0

    :try_start_1
    iput v10, v1, Llyiahf/vczjk/ok1;->o0O0O00:I

    iput v10, v1, Llyiahf/vczjk/ok1;->o000OOo:I

    invoke-virtual {v1, v4}, Llyiahf/vczjk/nk1;->OooO0oo(Llyiahf/vczjk/yz4;)V

    const/4 v0, 0x0

    :goto_44
    if-ge v0, v13, :cond_62

    iget-object v10, v1, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v10, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/nk1;

    invoke-virtual {v10, v4}, Llyiahf/vczjk/nk1;->OooO0oo(Llyiahf/vczjk/yz4;)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_44

    :catch_0
    move-exception v0

    :goto_45
    move-object/from16 v25, v12

    move/from16 v26, v14

    const/4 v10, 0x0

    :goto_46
    const/16 v19, 0x5

    goto/16 :goto_4e

    :cond_62
    invoke-virtual {v1, v4}, Llyiahf/vczjk/ok1;->Oooo0oo(Llyiahf/vczjk/yz4;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    :try_start_2
    iget-object v0, v1, Llyiahf/vczjk/ok1;->o00000O:Ljava/lang/ref/WeakReference;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_a

    if-eqz v0, :cond_63

    :try_start_3
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_63

    iget-object v0, v1, Llyiahf/vczjk/ok1;->o00000O:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nj1;
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_4

    move-object/from16 v10, v22

    :try_start_4
    invoke-virtual {v4, v10}, Llyiahf/vczjk/yz4;->OooOO0O(Ljava/lang/Object;)Llyiahf/vczjk/jx8;

    move-result-object v15
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_3

    move-object/from16 v22, v10

    :try_start_5
    iget-object v10, v1, Llyiahf/vczjk/ok1;->o0Oo0oo:Llyiahf/vczjk/yz4;

    invoke-virtual {v10, v0}, Llyiahf/vczjk/yz4;->OooOO0O(Ljava/lang/Object;)Llyiahf/vczjk/jx8;

    move-result-object v0
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_2

    move-object/from16 v25, v12

    move/from16 v26, v14

    const/4 v12, 0x0

    const/4 v14, 0x5

    :try_start_6
    invoke-virtual {v10, v0, v15, v12, v14}, Llyiahf/vczjk/yz4;->OooO0o(Llyiahf/vczjk/jx8;Llyiahf/vczjk/jx8;II)V

    const/4 v10, 0x0

    iput-object v10, v1, Llyiahf/vczjk/ok1;->o00000O:Ljava/lang/ref/WeakReference;
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_1

    goto :goto_49

    :catch_1
    move-exception v0

    :goto_47
    const/4 v10, 0x0

    const/4 v15, 0x1

    goto :goto_46

    :catch_2
    move-exception v0

    goto :goto_48

    :catch_3
    move-exception v0

    move-object/from16 v22, v10

    :goto_48
    move-object/from16 v25, v12

    move/from16 v26, v14

    goto :goto_47

    :catch_4
    move-exception v0

    goto :goto_48

    :cond_63
    move-object/from16 v25, v12

    move/from16 v26, v14

    :goto_49
    :try_start_7
    iget-object v0, v1, Llyiahf/vczjk/ok1;->o00000Oo:Ljava/lang/ref/WeakReference;
    :try_end_7
    .catch Ljava/lang/Exception; {:try_start_7 .. :try_end_7} :catch_9

    if-eqz v0, :cond_64

    :try_start_8
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_64

    iget-object v0, v1, Llyiahf/vczjk/ok1;->o00000Oo:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nj1;

    iget-object v10, v1, Llyiahf/vczjk/nk1;->Oooo0o0:Llyiahf/vczjk/nj1;

    invoke-virtual {v4, v10}, Llyiahf/vczjk/yz4;->OooOO0O(Ljava/lang/Object;)Llyiahf/vczjk/jx8;

    move-result-object v10

    iget-object v12, v1, Llyiahf/vczjk/ok1;->o0Oo0oo:Llyiahf/vczjk/yz4;

    invoke-virtual {v12, v0}, Llyiahf/vczjk/yz4;->OooOO0O(Ljava/lang/Object;)Llyiahf/vczjk/jx8;

    move-result-object v0

    const/4 v14, 0x0

    const/4 v15, 0x5

    invoke-virtual {v12, v10, v0, v14, v15}, Llyiahf/vczjk/yz4;->OooO0o(Llyiahf/vczjk/jx8;Llyiahf/vczjk/jx8;II)V

    const/4 v10, 0x0

    iput-object v10, v1, Llyiahf/vczjk/ok1;->o00000Oo:Ljava/lang/ref/WeakReference;
    :try_end_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_1

    :cond_64
    :try_start_9
    iget-object v0, v1, Llyiahf/vczjk/ok1;->o00000OO:Ljava/lang/ref/WeakReference;
    :try_end_9
    .catch Ljava/lang/Exception; {:try_start_9 .. :try_end_9} :catch_9

    if-eqz v0, :cond_65

    :try_start_a
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_65

    iget-object v0, v1, Llyiahf/vczjk/ok1;->o00000OO:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nj1;
    :try_end_a
    .catch Ljava/lang/Exception; {:try_start_a .. :try_end_a} :catch_1

    move-object/from16 v10, v23

    :try_start_b
    invoke-virtual {v4, v10}, Llyiahf/vczjk/yz4;->OooOO0O(Ljava/lang/Object;)Llyiahf/vczjk/jx8;

    move-result-object v12

    iget-object v14, v1, Llyiahf/vczjk/ok1;->o0Oo0oo:Llyiahf/vczjk/yz4;

    invoke-virtual {v14, v0}, Llyiahf/vczjk/yz4;->OooOO0O(Ljava/lang/Object;)Llyiahf/vczjk/jx8;

    move-result-object v0
    :try_end_b
    .catch Ljava/lang/Exception; {:try_start_b .. :try_end_b} :catch_5

    move-object/from16 v23, v10

    const/4 v10, 0x5

    const/4 v15, 0x0

    :try_start_c
    invoke-virtual {v14, v0, v12, v15, v10}, Llyiahf/vczjk/yz4;->OooO0o(Llyiahf/vczjk/jx8;Llyiahf/vczjk/jx8;II)V

    const/4 v10, 0x0

    iput-object v10, v1, Llyiahf/vczjk/ok1;->o00000OO:Ljava/lang/ref/WeakReference;
    :try_end_c
    .catch Ljava/lang/Exception; {:try_start_c .. :try_end_c} :catch_1

    goto :goto_4a

    :catch_5
    move-exception v0

    move-object/from16 v23, v10

    goto :goto_47

    :cond_65
    :goto_4a
    :try_start_d
    iget-object v0, v1, Llyiahf/vczjk/ok1;->o00000o0:Ljava/lang/ref/WeakReference;

    if-eqz v0, :cond_66

    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_66

    iget-object v0, v1, Llyiahf/vczjk/ok1;->o00000o0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nj1;

    iget-object v10, v1, Llyiahf/vczjk/nk1;->Oooo0OO:Llyiahf/vczjk/nj1;

    invoke-virtual {v4, v10}, Llyiahf/vczjk/yz4;->OooOO0O(Ljava/lang/Object;)Llyiahf/vczjk/jx8;

    move-result-object v10
    :try_end_d
    .catch Ljava/lang/Exception; {:try_start_d .. :try_end_d} :catch_9

    :try_start_e
    iget-object v12, v1, Llyiahf/vczjk/ok1;->o0Oo0oo:Llyiahf/vczjk/yz4;

    invoke-virtual {v12, v0}, Llyiahf/vczjk/yz4;->OooOO0O(Ljava/lang/Object;)Llyiahf/vczjk/jx8;

    move-result-object v0
    :try_end_e
    .catch Ljava/lang/Exception; {:try_start_e .. :try_end_e} :catch_8

    const/4 v14, 0x0

    const/4 v15, 0x5

    :try_start_f
    invoke-virtual {v12, v10, v0, v14, v15}, Llyiahf/vczjk/yz4;->OooO0o(Llyiahf/vczjk/jx8;Llyiahf/vczjk/jx8;II)V
    :try_end_f
    .catch Ljava/lang/Exception; {:try_start_f .. :try_end_f} :catch_7

    const/4 v10, 0x0

    :try_start_10
    iput-object v10, v1, Llyiahf/vczjk/ok1;->o00000o0:Ljava/lang/ref/WeakReference;

    goto :goto_4d

    :catch_6
    move-exception v0

    :goto_4b
    move/from16 v19, v15

    const/4 v15, 0x1

    goto :goto_4e

    :catch_7
    move-exception v0

    const/4 v10, 0x0

    goto :goto_4b

    :catch_8
    move-exception v0

    goto :goto_4c

    :catch_9
    move-exception v0

    :goto_4c
    const/4 v10, 0x0

    const/4 v15, 0x5

    goto :goto_4b

    :cond_66
    const/4 v10, 0x0

    const/4 v15, 0x5

    :goto_4d
    invoke-virtual {v4}, Llyiahf/vczjk/yz4;->OooOOOo()V
    :try_end_10
    .catch Ljava/lang/Exception; {:try_start_10 .. :try_end_10} :catch_6

    move/from16 v19, v15

    const/4 v15, 0x1

    goto :goto_4f

    :catch_a
    move-exception v0

    move-object/from16 v25, v12

    move/from16 v26, v14

    goto :goto_4c

    :catch_b
    move-exception v0

    move/from16 v24, v10

    goto/16 :goto_45

    :goto_4e
    invoke-virtual {v0}, Ljava/lang/Throwable;->printStackTrace()V

    sget-object v12, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v14, Ljava/lang/StringBuilder;

    const-string v10, "EXCEPTION : "

    invoke-direct {v14, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v14, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v12, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    :goto_4f
    sget-object v0, Llyiahf/vczjk/sb;->OooO0Oo:[Z

    if-eqz v15, :cond_6a

    const/16 v17, 0x0

    const/16 v21, 0x2

    aput-boolean v17, v0, v21

    const/16 v10, 0x40

    invoke-virtual {v1, v10}, Llyiahf/vczjk/ok1;->OoooO0O(I)Z

    move-result v12

    invoke-virtual {v1, v4, v12}, Llyiahf/vczjk/nk1;->Oooo0o(Llyiahf/vczjk/yz4;Z)V

    iget-object v14, v1, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v14}, Ljava/util/ArrayList;->size()I

    move-result v14

    const/4 v10, 0x0

    const/4 v15, 0x0

    :goto_50
    if-ge v10, v14, :cond_69

    move-object/from16 v27, v0

    iget-object v0, v1, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v0, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nk1;

    invoke-virtual {v0, v4, v12}, Llyiahf/vczjk/nk1;->Oooo0o(Llyiahf/vczjk/yz4;Z)V

    move/from16 v28, v10

    iget v10, v0, Llyiahf/vczjk/nk1;->OooO0oo:I

    move/from16 v29, v12

    const/4 v12, -0x1

    if-ne v10, v12, :cond_67

    iget v0, v0, Llyiahf/vczjk/nk1;->OooO:I

    if-eq v0, v12, :cond_68

    :cond_67
    const/4 v15, 0x1

    :cond_68
    add-int/lit8 v10, v28, 0x1

    move-object/from16 v0, v27

    move/from16 v12, v29

    goto :goto_50

    :cond_69
    move-object/from16 v27, v0

    const/4 v12, -0x1

    goto :goto_52

    :cond_6a
    move-object/from16 v27, v0

    const/4 v12, -0x1

    invoke-virtual {v1, v4, v11}, Llyiahf/vczjk/nk1;->Oooo0o(Llyiahf/vczjk/yz4;Z)V

    const/4 v0, 0x0

    :goto_51
    if-ge v0, v13, :cond_6b

    iget-object v10, v1, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v10, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/nk1;

    invoke-virtual {v10, v4, v11}, Llyiahf/vczjk/nk1;->Oooo0o(Llyiahf/vczjk/yz4;Z)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_51

    :cond_6b
    const/4 v15, 0x0

    :goto_52
    const/16 v0, 0x8

    if-eqz v24, :cond_6e

    if-ge v8, v0, :cond_6e

    const/16 v21, 0x2

    aget-boolean v10, v27, v21

    if-eqz v10, :cond_6f

    const/4 v10, 0x0

    const/4 v12, 0x0

    const/4 v14, 0x0

    :goto_53
    if-ge v10, v13, :cond_6c

    iget-object v0, v1, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    invoke-virtual {v0, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nk1;

    move/from16 v28, v10

    iget v10, v0, Llyiahf/vczjk/nk1;->OoooOoO:I

    invoke-virtual {v0}, Llyiahf/vczjk/nk1;->OooOOOO()I

    move-result v29

    add-int v10, v29, v10

    invoke-static {v14, v10}, Ljava/lang/Math;->max(II)I

    move-result v14

    iget v10, v0, Llyiahf/vczjk/nk1;->OoooOoo:I

    invoke-virtual {v0}, Llyiahf/vczjk/nk1;->OooOO0o()I

    move-result v0

    add-int/2addr v0, v10

    invoke-static {v12, v0}, Ljava/lang/Math;->max(II)I

    move-result v12

    add-int/lit8 v10, v28, 0x1

    const/16 v0, 0x8

    goto :goto_53

    :cond_6c
    iget v0, v1, Llyiahf/vczjk/nk1;->Ooooo0o:I

    invoke-static {v0, v14}, Ljava/lang/Math;->max(II)I

    move-result v0

    iget v10, v1, Llyiahf/vczjk/nk1;->OooooO0:I

    invoke-static {v10, v12}, Ljava/lang/Math;->max(II)I

    move-result v10

    if-ne v5, v2, :cond_6d

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOOOO()I

    move-result v12

    if-ge v12, v0, :cond_6d

    invoke-virtual {v1, v0}, Llyiahf/vczjk/nk1;->Oooo0OO(I)V

    iget-object v0, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    const/16 v17, 0x0

    aput-object v2, v0, v17

    const/4 v15, 0x1

    const/16 v26, 0x1

    :cond_6d
    if-ne v7, v2, :cond_6f

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOO0o()I

    move-result v0

    if-ge v0, v10, :cond_6f

    invoke-virtual {v1, v10}, Llyiahf/vczjk/nk1;->Oooo00o(I)V

    iget-object v0, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    const/16 v16, 0x1

    aput-object v2, v0, v16

    const/4 v15, 0x1

    const/16 v26, 0x1

    goto :goto_54

    :cond_6e
    const/16 v21, 0x2

    :cond_6f
    :goto_54
    iget v0, v1, Llyiahf/vczjk/nk1;->Ooooo0o:I

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOOOO()I

    move-result v10

    invoke-static {v0, v10}, Ljava/lang/Math;->max(II)I

    move-result v0

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOOOO()I

    move-result v10

    if-le v0, v10, :cond_70

    invoke-virtual {v1, v0}, Llyiahf/vczjk/nk1;->Oooo0OO(I)V

    iget-object v0, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    const/16 v17, 0x0

    aput-object v25, v0, v17

    const/4 v15, 0x1

    const/16 v26, 0x1

    :cond_70
    iget v0, v1, Llyiahf/vczjk/nk1;->OooooO0:I

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOO0o()I

    move-result v10

    invoke-static {v0, v10}, Ljava/lang/Math;->max(II)I

    move-result v0

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOO0o()I

    move-result v10

    if-le v0, v10, :cond_71

    invoke-virtual {v1, v0}, Llyiahf/vczjk/nk1;->Oooo00o(I)V

    iget-object v0, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    const/4 v10, 0x1

    aput-object v25, v0, v10

    move v15, v10

    move/from16 v26, v15

    goto :goto_55

    :cond_71
    const/4 v10, 0x1

    :goto_55
    if-nez v26, :cond_73

    iget-object v0, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    const/16 v17, 0x0

    aget-object v0, v0, v17

    if-ne v0, v2, :cond_72

    if-lez v3, :cond_72

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOOOO()I

    move-result v0

    if-le v0, v3, :cond_72

    iput-boolean v10, v1, Llyiahf/vczjk/ok1;->o00000:Z

    iget-object v0, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    aput-object v25, v0, v17

    invoke-virtual {v1, v3}, Llyiahf/vczjk/nk1;->Oooo0OO(I)V

    move v15, v10

    move/from16 v26, v15

    :cond_72
    iget-object v0, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    aget-object v0, v0, v10

    if-ne v0, v2, :cond_73

    if-lez v6, :cond_73

    invoke-virtual {v1}, Llyiahf/vczjk/nk1;->OooOO0o()I

    move-result v0

    if-le v0, v6, :cond_73

    iput-boolean v10, v1, Llyiahf/vczjk/ok1;->o00000O0:Z

    iget-object v0, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    aput-object v25, v0, v10

    invoke-virtual {v1, v6}, Llyiahf/vczjk/nk1;->Oooo00o(I)V

    const/16 v0, 0x8

    const/4 v14, 0x1

    const/4 v15, 0x1

    goto :goto_56

    :cond_73
    move/from16 v14, v26

    const/16 v0, 0x8

    :goto_56
    if-le v8, v0, :cond_74

    const/4 v15, 0x0

    :cond_74
    move v0, v8

    move/from16 v10, v24

    move-object/from16 v12, v25

    const/16 v8, 0x40

    goto/16 :goto_43

    :cond_75
    move/from16 v26, v14

    iput-object v9, v1, Llyiahf/vczjk/ok1;->o00oO0o:Ljava/util/ArrayList;

    if-eqz v26, :cond_76

    iget-object v0, v1, Llyiahf/vczjk/nk1;->OoooO:[Llyiahf/vczjk/mk1;

    const/16 v17, 0x0

    aput-object v5, v0, v17

    const/16 v16, 0x1

    aput-object v7, v0, v16

    :cond_76
    iget-object v0, v4, Llyiahf/vczjk/yz4;->OooOO0o:Llyiahf/vczjk/uqa;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ok1;->OooOooO(Llyiahf/vczjk/uqa;)V

    return-void
.end method

.method public final OoooO0O(I)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ok1;->o000000o:I

    and-int/2addr v0, p1

    if-ne v0, p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method
