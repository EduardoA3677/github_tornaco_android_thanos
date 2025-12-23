.class public final Llyiahf/vczjk/oc7;
.super Llyiahf/vczjk/rg3;
.source "SourceFile"


# instance fields
.field public OooOOOo:I

.field public OooOOo:I

.field public OooOOo0:I

.field public OooOOoo:I

.field public OooOo:I

.field public OooOo0:I

.field public OooOo00:Llyiahf/vczjk/hd7;

.field public OooOo0O:Ljava/util/List;

.field public OooOo0o:Llyiahf/vczjk/hd7;

.field public OooOoO:Ljava/util/List;

.field public OooOoO0:Ljava/util/List;

.field public OooOoOO:Ljava/util/List;

.field public OooOoo:Ljava/util/List;

.field public OooOoo0:Llyiahf/vczjk/nd7;

.field public OooOooO:Llyiahf/vczjk/ec7;

.field public OooOooo:Ljava/util/List;


# direct methods
.method public static OooO0oo()Llyiahf/vczjk/oc7;
    .locals 3

    new-instance v0, Llyiahf/vczjk/oc7;

    invoke-direct {v0}, Llyiahf/vczjk/rg3;-><init>()V

    const/4 v1, 0x6

    iput v1, v0, Llyiahf/vczjk/oc7;->OooOOo0:I

    iput v1, v0, Llyiahf/vczjk/oc7;->OooOOo:I

    sget-object v1, Llyiahf/vczjk/hd7;->OooOOO0:Llyiahf/vczjk/hd7;

    iput-object v1, v0, Llyiahf/vczjk/oc7;->OooOo00:Llyiahf/vczjk/hd7;

    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v2, v0, Llyiahf/vczjk/oc7;->OooOo0O:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/oc7;->OooOo0o:Llyiahf/vczjk/hd7;

    iput-object v2, v0, Llyiahf/vczjk/oc7;->OooOoO0:Ljava/util/List;

    iput-object v2, v0, Llyiahf/vczjk/oc7;->OooOoO:Ljava/util/List;

    iput-object v2, v0, Llyiahf/vczjk/oc7;->OooOoOO:Ljava/util/List;

    sget-object v1, Llyiahf/vczjk/nd7;->OooOOO0:Llyiahf/vczjk/nd7;

    iput-object v1, v0, Llyiahf/vczjk/oc7;->OooOoo0:Llyiahf/vczjk/nd7;

    iput-object v2, v0, Llyiahf/vczjk/oc7;->OooOoo:Ljava/util/List;

    sget-object v1, Llyiahf/vczjk/ec7;->OooOOO0:Llyiahf/vczjk/ec7;

    iput-object v1, v0, Llyiahf/vczjk/oc7;->OooOooO:Llyiahf/vczjk/ec7;

    iput-object v2, v0, Llyiahf/vczjk/oc7;->OooOooo:Ljava/util/List;

    return-object v0
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/pc7;)V
    .locals 5

    sget-object v0, Llyiahf/vczjk/pc7;->OooOOO0:Llyiahf/vczjk/pc7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->OoooOOo()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->getFlags()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/lit8 v1, v1, 0x1

    iput v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOo0:I

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->OoooOoO()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->Oooo0oo()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/lit8 v1, v1, 0x2

    iput v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOo:I

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->OoooOo0()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->Oooo0oO()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/lit8 v1, v1, 0x4

    iput v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOoo:I

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->Ooooo0o()Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->OoooO0()Llyiahf/vczjk/hd7;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v2, 0x8

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_4

    iget-object v1, p0, Llyiahf/vczjk/oc7;->OooOo00:Llyiahf/vczjk/hd7;

    sget-object v3, Llyiahf/vczjk/hd7;->OooOOO0:Llyiahf/vczjk/hd7;

    if-eq v1, v3, :cond_4

    invoke-static {v1}, Llyiahf/vczjk/hd7;->Oooooo0(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/gd7;->OooO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    invoke-virtual {v1}, Llyiahf/vczjk/gd7;->OooO0oO()Llyiahf/vczjk/hd7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOo00:Llyiahf/vczjk/hd7;

    goto :goto_0

    :cond_4
    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOo00:Llyiahf/vczjk/hd7;

    :goto_0
    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->OooooO0()Z

    move-result v0

    if-eqz v0, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->OoooO0O()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/lit8 v1, v1, 0x10

    iput v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOo0:I

    :cond_6
    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOOoo(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_9

    iget-object v0, p0, Llyiahf/vczjk/oc7;->OooOo0O:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_7

    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOOoo(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOo0O:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    and-int/lit8 v0, v0, -0x21

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    goto :goto_1

    :cond_7
    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v1, 0x20

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_8

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOo0O:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOo0O:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_8
    iget-object v0, p0, Llyiahf/vczjk/oc7;->OooOo0O:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOOoo(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_9
    :goto_1
    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->OoooOoo()Z

    move-result v0

    if-eqz v0, :cond_b

    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->Oooo()Llyiahf/vczjk/hd7;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v2, 0x40

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_a

    iget-object v1, p0, Llyiahf/vczjk/oc7;->OooOo0o:Llyiahf/vczjk/hd7;

    sget-object v3, Llyiahf/vczjk/hd7;->OooOOO0:Llyiahf/vczjk/hd7;

    if-eq v1, v3, :cond_a

    invoke-static {v1}, Llyiahf/vczjk/hd7;->Oooooo0(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/gd7;->OooO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    invoke-virtual {v1}, Llyiahf/vczjk/gd7;->OooO0oO()Llyiahf/vczjk/hd7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOo0o:Llyiahf/vczjk/hd7;

    goto :goto_2

    :cond_a
    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOo0o:Llyiahf/vczjk/hd7;

    :goto_2
    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_b
    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->Ooooo00()Z

    move-result v0

    if-eqz v0, :cond_c

    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->OoooO00()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/lit16 v1, v1, 0x80

    iput v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOo:I

    :cond_c
    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOo0o(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_f

    iget-object v0, p0, Llyiahf/vczjk/oc7;->OooOoO0:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_d

    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOo0o(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOoO0:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    and-int/lit16 v0, v0, -0x101

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    goto :goto_3

    :cond_d
    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v1, 0x100

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_e

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOoO0:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOoO0:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_e
    iget-object v0, p0, Llyiahf/vczjk/oc7;->OooOoO0:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOo0o(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_f
    :goto_3
    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOoO0(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_12

    iget-object v0, p0, Llyiahf/vczjk/oc7;->OooOoO:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_10

    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOoO0(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOoO:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    and-int/lit16 v0, v0, -0x201

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    goto :goto_4

    :cond_10
    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v1, 0x200

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_11

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOoO:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOoO:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_11
    iget-object v0, p0, Llyiahf/vczjk/oc7;->OooOoO:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOoO0(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_12
    :goto_4
    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOoOO(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_15

    iget-object v0, p0, Llyiahf/vczjk/oc7;->OooOoOO:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_13

    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOoOO(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOoOO:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    and-int/lit16 v0, v0, -0x401

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    goto :goto_5

    :cond_13
    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v1, 0x400

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_14

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOoOO:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOoOO:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_14
    iget-object v0, p0, Llyiahf/vczjk/oc7;->OooOoOO:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOoOO(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_15
    :goto_5
    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->OooooOO()Z

    move-result v0

    if-eqz v0, :cond_17

    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->OoooOO0()Llyiahf/vczjk/nd7;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v2, 0x800

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_16

    iget-object v1, p0, Llyiahf/vczjk/oc7;->OooOoo0:Llyiahf/vczjk/nd7;

    sget-object v3, Llyiahf/vczjk/nd7;->OooOOO0:Llyiahf/vczjk/nd7;

    if-eq v1, v3, :cond_16

    invoke-static {v1}, Llyiahf/vczjk/nd7;->OooOO0o(Llyiahf/vczjk/nd7;)Llyiahf/vczjk/vb7;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/vb7;->OooOO0(Llyiahf/vczjk/nd7;)V

    invoke-virtual {v1}, Llyiahf/vczjk/vb7;->OooO0oO()Llyiahf/vczjk/nd7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOoo0:Llyiahf/vczjk/nd7;

    goto :goto_6

    :cond_16
    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOoo0:Llyiahf/vczjk/nd7;

    :goto_6
    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_17
    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOooO(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_1a

    iget-object v0, p0, Llyiahf/vczjk/oc7;->OooOoo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_18

    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOooO(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOoo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    and-int/lit16 v0, v0, -0x1001

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    goto :goto_7

    :cond_18
    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v1, 0x1000

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_19

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOoo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOoo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_19
    iget-object v0, p0, Llyiahf/vczjk/oc7;->OooOoo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/pc7;->OooOooO(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_1a
    :goto_7
    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->OoooOOO()Z

    move-result v0

    if-eqz v0, :cond_1c

    invoke-virtual {p1}, Llyiahf/vczjk/pc7;->Oooo0o()Llyiahf/vczjk/ec7;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v2, 0x2000

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_1b

    iget-object v1, p0, Llyiahf/vczjk/oc7;->OooOooO:Llyiahf/vczjk/ec7;

    sget-object v3, Llyiahf/vczjk/ec7;->OooOOO0:Llyiahf/vczjk/ec7;

    if-eq v1, v3, :cond_1b

    new-instance v3, Llyiahf/vczjk/dc7;

    const/4 v4, 0x0

    invoke-direct {v3, v4}, Llyiahf/vczjk/dc7;-><init>(I)V

    sget-object v4, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v4, v3, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/dc7;->OooOO0(Llyiahf/vczjk/ec7;)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/dc7;->OooOO0(Llyiahf/vczjk/ec7;)V

    invoke-virtual {v3}, Llyiahf/vczjk/dc7;->OooO0o0()Llyiahf/vczjk/ec7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOooO:Llyiahf/vczjk/ec7;

    goto :goto_8

    :cond_1b
    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOooO:Llyiahf/vczjk/ec7;

    :goto_8
    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_1c
    invoke-static {p1}, Llyiahf/vczjk/pc7;->Oooo00O(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_1f

    iget-object v0, p0, Llyiahf/vczjk/oc7;->OooOooo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1d

    invoke-static {p1}, Llyiahf/vczjk/pc7;->Oooo00O(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOooo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    and-int/lit16 v0, v0, -0x4001

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    goto :goto_9

    :cond_1d
    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v1, 0x4000

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_1e

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOooo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/oc7;->OooOooo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_1e
    iget-object v0, p0, Llyiahf/vczjk/oc7;->OooOooo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/pc7;->Oooo00O(Llyiahf/vczjk/pc7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_1f
    :goto_9
    invoke-virtual {p0, p1}, Llyiahf/vczjk/rg3;->OooO0o0(Llyiahf/vczjk/sg3;)V

    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/pc7;->Oooo0O0(Llyiahf/vczjk/pc7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final OooO0O0()Llyiahf/vczjk/pi5;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/oc7;->OooO0oO()Llyiahf/vczjk/pc7;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/pc7;->isInitialized()Z

    move-result v1

    if-eqz v1, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Llyiahf/vczjk/v8a;

    invoke-direct {v0}, Llyiahf/vczjk/v8a;-><init>()V

    throw v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/og3;
    .locals 2

    const/4 v0, 0x0

    :try_start_0
    sget-object v1, Llyiahf/vczjk/pc7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/pc7;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/pc7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v1}, Llyiahf/vczjk/oc7;->OooO(Llyiahf/vczjk/pc7;)V

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/pc7;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :try_start_2
    throw p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :catchall_1
    move-exception p1

    move-object v0, p2

    :goto_0
    if-eqz v0, :cond_0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/oc7;->OooO(Llyiahf/vczjk/pc7;)V

    :cond_0
    throw p1
.end method

.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/vg3;)Llyiahf/vczjk/og3;
    .locals 0

    check-cast p1, Llyiahf/vczjk/pc7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/oc7;->OooO(Llyiahf/vczjk/pc7;)V

    return-object p0
.end method

.method public final OooO0oO()Llyiahf/vczjk/pc7;
    .locals 5

    new-instance v0, Llyiahf/vczjk/pc7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/pc7;-><init>(Llyiahf/vczjk/oc7;)V

    iget v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    and-int/lit8 v2, v1, 0x1

    const/4 v3, 0x1

    if-ne v2, v3, :cond_0

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    iget v2, p0, Llyiahf/vczjk/oc7;->OooOOo0:I

    invoke-static {v0, v2}, Llyiahf/vczjk/pc7;->OooOOO(Llyiahf/vczjk/pc7;I)V

    and-int/lit8 v2, v1, 0x2

    const/4 v4, 0x2

    if-ne v2, v4, :cond_1

    or-int/lit8 v3, v3, 0x2

    :cond_1
    iget v2, p0, Llyiahf/vczjk/oc7;->OooOOo:I

    invoke-static {v0, v2}, Llyiahf/vczjk/pc7;->OooOOOO(Llyiahf/vczjk/pc7;I)V

    and-int/lit8 v2, v1, 0x4

    const/4 v4, 0x4

    if-ne v2, v4, :cond_2

    or-int/lit8 v3, v3, 0x4

    :cond_2
    iget v2, p0, Llyiahf/vczjk/oc7;->OooOOoo:I

    invoke-static {v0, v2}, Llyiahf/vczjk/pc7;->OooOOOo(Llyiahf/vczjk/pc7;I)V

    and-int/lit8 v2, v1, 0x8

    const/16 v4, 0x8

    if-ne v2, v4, :cond_3

    or-int/lit8 v3, v3, 0x8

    :cond_3
    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOo00:Llyiahf/vczjk/hd7;

    invoke-static {v0, v2}, Llyiahf/vczjk/pc7;->OooOOo0(Llyiahf/vczjk/pc7;Llyiahf/vczjk/hd7;)V

    and-int/lit8 v2, v1, 0x10

    const/16 v4, 0x10

    if-ne v2, v4, :cond_4

    or-int/lit8 v3, v3, 0x10

    :cond_4
    iget v2, p0, Llyiahf/vczjk/oc7;->OooOo0:I

    invoke-static {v0, v2}, Llyiahf/vczjk/pc7;->OooOOo(Llyiahf/vczjk/pc7;I)V

    iget v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v4, 0x20

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_5

    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOo0O:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/oc7;->OooOo0O:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    and-int/lit8 v2, v2, -0x21

    iput v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_5
    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOo0O:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/pc7;->OooOo00(Llyiahf/vczjk/pc7;Ljava/util/List;)V

    and-int/lit8 v2, v1, 0x40

    const/16 v4, 0x40

    if-ne v2, v4, :cond_6

    or-int/lit8 v3, v3, 0x20

    :cond_6
    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOo0o:Llyiahf/vczjk/hd7;

    invoke-static {v0, v2}, Llyiahf/vczjk/pc7;->OooOo0(Llyiahf/vczjk/pc7;Llyiahf/vczjk/hd7;)V

    and-int/lit16 v2, v1, 0x80

    const/16 v4, 0x80

    if-ne v2, v4, :cond_7

    or-int/lit8 v3, v3, 0x40

    :cond_7
    iget v2, p0, Llyiahf/vczjk/oc7;->OooOo:I

    invoke-static {v0, v2}, Llyiahf/vczjk/pc7;->OooOo0O(Llyiahf/vczjk/pc7;I)V

    iget v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v4, 0x100

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_8

    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOoO0:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/oc7;->OooOoO0:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    and-int/lit16 v2, v2, -0x101

    iput v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_8
    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOoO0:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/pc7;->OooOo(Llyiahf/vczjk/pc7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v4, 0x200

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_9

    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOoO:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/oc7;->OooOoO:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    and-int/lit16 v2, v2, -0x201

    iput v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_9
    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOoO:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/pc7;->OooOoO(Llyiahf/vczjk/pc7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v4, 0x400

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_a

    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOoOO:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/oc7;->OooOoOO:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    and-int/lit16 v2, v2, -0x401

    iput v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_a
    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOoOO:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/pc7;->OooOoo0(Llyiahf/vczjk/pc7;Ljava/util/List;)V

    and-int/lit16 v2, v1, 0x800

    const/16 v4, 0x800

    if-ne v2, v4, :cond_b

    or-int/lit16 v3, v3, 0x80

    :cond_b
    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOoo0:Llyiahf/vczjk/nd7;

    invoke-static {v0, v2}, Llyiahf/vczjk/pc7;->OooOoo(Llyiahf/vczjk/pc7;Llyiahf/vczjk/nd7;)V

    iget v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v4, 0x1000

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_c

    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOoo:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/oc7;->OooOoo:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    and-int/lit16 v2, v2, -0x1001

    iput v2, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_c
    iget-object v2, p0, Llyiahf/vczjk/oc7;->OooOoo:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/pc7;->OooOooo(Llyiahf/vczjk/pc7;Ljava/util/List;)V

    const/16 v2, 0x2000

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_d

    or-int/lit16 v3, v3, 0x100

    :cond_d
    iget-object v1, p0, Llyiahf/vczjk/oc7;->OooOooO:Llyiahf/vczjk/ec7;

    invoke-static {v0, v1}, Llyiahf/vczjk/pc7;->Oooo000(Llyiahf/vczjk/pc7;Llyiahf/vczjk/ec7;)V

    iget v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    const/16 v2, 0x4000

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_e

    iget-object v1, p0, Llyiahf/vczjk/oc7;->OooOooo:Ljava/util/List;

    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/oc7;->OooOooo:Ljava/util/List;

    iget v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    and-int/lit16 v1, v1, -0x4001

    iput v1, p0, Llyiahf/vczjk/oc7;->OooOOOo:I

    :cond_e
    iget-object v1, p0, Llyiahf/vczjk/oc7;->OooOooo:Ljava/util/List;

    invoke-static {v0, v1}, Llyiahf/vczjk/pc7;->Oooo00o(Llyiahf/vczjk/pc7;Ljava/util/List;)V

    invoke-static {v0, v3}, Llyiahf/vczjk/pc7;->Oooo0(Llyiahf/vczjk/pc7;I)V

    return-object v0
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    invoke-static {}, Llyiahf/vczjk/oc7;->OooO0oo()Llyiahf/vczjk/oc7;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/oc7;->OooO0oO()Llyiahf/vczjk/pc7;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/oc7;->OooO(Llyiahf/vczjk/pc7;)V

    return-object v0
.end method
