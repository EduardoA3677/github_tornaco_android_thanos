.class public final Llyiahf/vczjk/xb7;
.super Llyiahf/vczjk/rg3;
.source "SourceFile"


# instance fields
.field public OooOOOo:I

.field public OooOOo:I

.field public OooOOo0:I

.field public OooOOoo:I

.field public OooOo:Ljava/util/List;

.field public OooOo0:Ljava/util/List;

.field public OooOo00:Ljava/util/List;

.field public OooOo0O:Ljava/util/List;

.field public OooOo0o:Ljava/util/List;

.field public OooOoO:Ljava/util/List;

.field public OooOoO0:Ljava/util/List;

.field public OooOoOO:Ljava/util/List;

.field public OooOoo:Ljava/util/List;

.field public OooOoo0:Ljava/util/List;

.field public OooOooO:Ljava/util/List;

.field public OooOooo:Ljava/util/List;

.field public Oooo0:Ljava/util/List;

.field public Oooo000:I

.field public Oooo00O:Llyiahf/vczjk/hd7;

.field public Oooo00o:I

.field public Oooo0O0:Ljava/util/List;

.field public Oooo0OO:Ljava/util/List;

.field public Oooo0o:Ljava/util/List;

.field public Oooo0o0:Llyiahf/vczjk/nd7;

.field public Oooo0oO:Llyiahf/vczjk/ud7;

.field public Oooo0oo:Ljava/util/List;


# direct methods
.method public static OooO0oo()Llyiahf/vczjk/xb7;
    .locals 3

    new-instance v0, Llyiahf/vczjk/xb7;

    invoke-direct {v0}, Llyiahf/vczjk/rg3;-><init>()V

    const/4 v1, 0x6

    iput v1, v0, Llyiahf/vczjk/xb7;->OooOOo0:I

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->OooOo00:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->OooOo0:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->OooOo0O:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->OooOo0o:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->OooOo:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->OooOoO0:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->OooOoO:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->OooOoOO:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->OooOoo0:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->OooOoo:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->OooOooO:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->OooOooo:Ljava/util/List;

    sget-object v2, Llyiahf/vczjk/hd7;->OooOOO0:Llyiahf/vczjk/hd7;

    iput-object v2, v0, Llyiahf/vczjk/xb7;->Oooo00O:Llyiahf/vczjk/hd7;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->Oooo0:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->Oooo0O0:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->Oooo0OO:Ljava/util/List;

    sget-object v2, Llyiahf/vczjk/nd7;->OooOOO0:Llyiahf/vczjk/nd7;

    iput-object v2, v0, Llyiahf/vczjk/xb7;->Oooo0o0:Llyiahf/vczjk/nd7;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->Oooo0o:Ljava/util/List;

    sget-object v2, Llyiahf/vczjk/ud7;->OooOOO0:Llyiahf/vczjk/ud7;

    iput-object v2, v0, Llyiahf/vczjk/xb7;->Oooo0oO:Llyiahf/vczjk/ud7;

    iput-object v1, v0, Llyiahf/vczjk/xb7;->Oooo0oo:Ljava/util/List;

    return-object v0
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/zb7;)V
    .locals 5

    sget-object v0, Llyiahf/vczjk/zb7;->OooOOO0:Llyiahf/vczjk/zb7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o000000o()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/lit8 v1, v1, 0x1

    iput v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOo0:I

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o00000()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o0OoOo0()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/lit8 v1, v1, 0x2

    iput v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOo:I

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o000000O()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->OooooOo()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/lit8 v1, v1, 0x4

    iput v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOoo:I

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/zb7;->Oooo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_6

    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOo00:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-static {p1}, Llyiahf/vczjk/zb7;->Oooo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOo00:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit8 v0, v0, -0x9

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_0

    :cond_4
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v1, 0x8

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_5

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo00:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOo00:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_5
    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOo00:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->Oooo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_6
    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/zb7;->OoooO0(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_9

    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOo0:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_7

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OoooO0(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOo0:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit8 v0, v0, -0x11

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_1

    :cond_7
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v1, 0x10

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_8

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo0:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOo0:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_8
    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOo0:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OoooO0(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_9
    :goto_1
    invoke-static {p1}, Llyiahf/vczjk/zb7;->OoooO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_c

    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOo0O:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_a

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OoooO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOo0O:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit8 v0, v0, -0x21

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_2

    :cond_a
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v1, 0x20

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_b

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo0O:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOo0O:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_b
    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOo0O:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OoooO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_c
    :goto_2
    invoke-static {p1}, Llyiahf/vczjk/zb7;->o000oOoO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_f

    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOo0o:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_d

    invoke-static {p1}, Llyiahf/vczjk/zb7;->o000oOoO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOo0o:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit8 v0, v0, -0x41

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_3

    :cond_d
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v1, 0x40

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_e

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo0o:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOo0o:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_e
    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOo0o:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->o000oOoO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_f
    :goto_3
    invoke-static {p1}, Llyiahf/vczjk/zb7;->OoooOOo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_12

    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_10

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OoooOOo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v0, v0, -0x81

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_4

    :cond_10
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v1, 0x80

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_11

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_11
    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OoooOOo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_12
    :goto_4
    invoke-static {p1}, Llyiahf/vczjk/zb7;->OoooOoO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_15

    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOoO0:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_13

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OoooOoO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOoO0:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v0, v0, -0x101

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_5

    :cond_13
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v1, 0x100

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_14

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoO0:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOoO0:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_14
    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOoO0:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OoooOoO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_15
    :goto_5
    invoke-static {p1}, Llyiahf/vczjk/zb7;->Ooooo00(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_18

    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOoO:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_16

    invoke-static {p1}, Llyiahf/vczjk/zb7;->Ooooo00(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOoO:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v0, v0, -0x201

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_6

    :cond_16
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v1, 0x200

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_17

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoO:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOoO:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_17
    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOoO:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->Ooooo00(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_18
    :goto_6
    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooooO0(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_1b

    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOoOO:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_19

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooooO0(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOoOO:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v0, v0, -0x401

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_7

    :cond_19
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v1, 0x400

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_1a

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoOO:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOoOO:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_1a
    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOoOO:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooooO0(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_1b
    :goto_7
    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOOO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_1e

    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOoo0:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1c

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOOO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOoo0:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v0, v0, -0x801

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_8

    :cond_1c
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v1, 0x800

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_1d

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoo0:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOoo0:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_1d
    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOoo0:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOOO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_1e
    :goto_8
    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOOOo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_21

    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOoo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1f

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOOOo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOoo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v0, v0, -0x1001

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_9

    :cond_1f
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v1, 0x1000

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_20

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOoo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_20
    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOoo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOOOo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_21
    :goto_9
    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOOo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_24

    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOooO:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_22

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOOo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOooO:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v0, v0, -0x2001

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_a

    :cond_22
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v1, 0x2000

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_23

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOooO:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOooO:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_23
    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOooO:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOOo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_24
    :goto_a
    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOo00(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_27

    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOooo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_25

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOo00(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOooo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v0, v0, -0x4001

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_b

    :cond_25
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v1, 0x4000

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_26

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOooo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->OooOooo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_26
    iget-object v0, p0, Llyiahf/vczjk/xb7;->OooOooo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOo00(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_27
    :goto_b
    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o00000O0()Z

    move-result v0

    if-eqz v0, :cond_28

    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o00O0O()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const v2, 0x8000

    or-int/2addr v1, v2

    iput v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/xb7;->Oooo000:I

    :cond_28
    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o00000O()Z

    move-result v0

    if-eqz v0, :cond_2a

    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o00Oo0()Llyiahf/vczjk/hd7;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/high16 v2, 0x10000

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_29

    iget-object v1, p0, Llyiahf/vczjk/xb7;->Oooo00O:Llyiahf/vczjk/hd7;

    sget-object v3, Llyiahf/vczjk/hd7;->OooOOO0:Llyiahf/vczjk/hd7;

    if-eq v1, v3, :cond_29

    invoke-static {v1}, Llyiahf/vczjk/hd7;->Oooooo0(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/gd7;->OooO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    invoke-virtual {v1}, Llyiahf/vczjk/gd7;->OooO0oO()Llyiahf/vczjk/hd7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo00O:Llyiahf/vczjk/hd7;

    goto :goto_c

    :cond_29
    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo00O:Llyiahf/vczjk/hd7;

    :goto_c
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_2a
    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o00000OO()Z

    move-result v0

    if-eqz v0, :cond_2b

    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o00Ooo()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/high16 v2, 0x20000

    or-int/2addr v1, v2

    iput v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/xb7;->Oooo00o:I

    :cond_2b
    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOoO0(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_2e

    iget-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_2c

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOoO0(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const v1, -0x40001

    and-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_d

    :cond_2c
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/high16 v1, 0x40000

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_2d

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_2d
    iget-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOoO0(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_2e
    :goto_d
    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOoOO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_31

    iget-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0O0:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_2f

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOoOO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0O0:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const v1, -0x80001

    and-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_e

    :cond_2f
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/high16 v1, 0x80000

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_30

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0O0:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0O0:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_30
    iget-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0O0:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOoOO(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_31
    :goto_e
    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOoo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_34

    iget-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0OO:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_32

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOoo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0OO:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const v1, -0x100001

    and-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_f

    :cond_32
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/high16 v1, 0x100000

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_33

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0OO:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0OO:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_33
    iget-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0OO:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->OooOoo(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_34
    :goto_f
    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o00000Oo()Z

    move-result v0

    if-eqz v0, :cond_36

    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o000OOo()Llyiahf/vczjk/nd7;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/high16 v2, 0x200000

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_35

    iget-object v1, p0, Llyiahf/vczjk/xb7;->Oooo0o0:Llyiahf/vczjk/nd7;

    sget-object v3, Llyiahf/vczjk/nd7;->OooOOO0:Llyiahf/vczjk/nd7;

    if-eq v1, v3, :cond_35

    invoke-static {v1}, Llyiahf/vczjk/nd7;->OooOO0o(Llyiahf/vczjk/nd7;)Llyiahf/vczjk/vb7;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/vb7;->OooOO0(Llyiahf/vczjk/nd7;)V

    invoke-virtual {v1}, Llyiahf/vczjk/vb7;->OooO0oO()Llyiahf/vczjk/nd7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0o0:Llyiahf/vczjk/nd7;

    goto :goto_10

    :cond_35
    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0o0:Llyiahf/vczjk/nd7;

    :goto_10
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_36
    invoke-static {p1}, Llyiahf/vczjk/zb7;->Oooo000(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_39

    iget-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0o:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_37

    invoke-static {p1}, Llyiahf/vczjk/zb7;->Oooo000(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0o:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const v1, -0x400001

    and-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_11

    :cond_37
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/high16 v1, 0x400000

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_38

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0o:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0o:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_38
    iget-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0o:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->Oooo000(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_39
    :goto_11
    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o00000o0()Z

    move-result v0

    if-eqz v0, :cond_3b

    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o000000()Llyiahf/vczjk/ud7;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/high16 v2, 0x800000

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_3a

    iget-object v1, p0, Llyiahf/vczjk/xb7;->Oooo0oO:Llyiahf/vczjk/ud7;

    sget-object v3, Llyiahf/vczjk/ud7;->OooOOO0:Llyiahf/vczjk/ud7;

    if-eq v1, v3, :cond_3a

    new-instance v3, Llyiahf/vczjk/dc7;

    const/4 v4, 0x2

    invoke-direct {v3, v4}, Llyiahf/vczjk/dc7;-><init>(I)V

    sget-object v4, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v4, v3, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/dc7;->OooOOO0(Llyiahf/vczjk/ud7;)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/dc7;->OooOOO0(Llyiahf/vczjk/ud7;)V

    invoke-virtual {v3}, Llyiahf/vczjk/dc7;->OooO()Llyiahf/vczjk/ud7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0oO:Llyiahf/vczjk/ud7;

    goto :goto_12

    :cond_3a
    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0oO:Llyiahf/vczjk/ud7;

    :goto_12
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_3b
    invoke-static {p1}, Llyiahf/vczjk/zb7;->Oooo0(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_3e

    iget-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0oo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_3c

    invoke-static {p1}, Llyiahf/vczjk/zb7;->Oooo0(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0oo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const v1, -0x1000001

    and-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    goto :goto_13

    :cond_3c
    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/high16 v1, 0x1000000

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_3d

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0oo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0oo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_3d
    iget-object v0, p0, Llyiahf/vczjk/xb7;->Oooo0oo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->Oooo0(Llyiahf/vczjk/zb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_3e
    :goto_13
    invoke-virtual {p0, p1}, Llyiahf/vczjk/rg3;->OooO0o0(Llyiahf/vczjk/sg3;)V

    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/zb7;->Oooo0o0(Llyiahf/vczjk/zb7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final OooO0O0()Llyiahf/vczjk/pi5;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/xb7;->OooO0oO()Llyiahf/vczjk/zb7;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/zb7;->isInitialized()Z

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
    sget-object v1, Llyiahf/vczjk/zb7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/zb7;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/zb7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v1}, Llyiahf/vczjk/xb7;->OooO(Llyiahf/vczjk/zb7;)V

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/zb7;
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

    invoke-virtual {p0, v0}, Llyiahf/vczjk/xb7;->OooO(Llyiahf/vczjk/zb7;)V

    :cond_0
    throw p1
.end method

.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/vg3;)Llyiahf/vczjk/og3;
    .locals 0

    check-cast p1, Llyiahf/vczjk/zb7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/xb7;->OooO(Llyiahf/vczjk/zb7;)V

    return-object p0
.end method

.method public final OooO0oO()Llyiahf/vczjk/zb7;
    .locals 5

    new-instance v0, Llyiahf/vczjk/zb7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/zb7;-><init>(Llyiahf/vczjk/xb7;)V

    iget v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit8 v2, v1, 0x1

    const/4 v3, 0x1

    if-ne v2, v3, :cond_0

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOo0:I

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->Oooo0o(Llyiahf/vczjk/zb7;I)V

    and-int/lit8 v2, v1, 0x2

    const/4 v4, 0x2

    if-ne v2, v4, :cond_1

    or-int/lit8 v3, v3, 0x2

    :cond_1
    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOo:I

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->Oooo0oO(Llyiahf/vczjk/zb7;I)V

    and-int/lit8 v2, v1, 0x4

    const/4 v4, 0x4

    if-ne v2, v4, :cond_2

    or-int/lit8 v3, v3, 0x4

    :cond_2
    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOoo:I

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->Oooo0oo(Llyiahf/vczjk/zb7;I)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v4, 0x8

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_3

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo00:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->OooOo00:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit8 v2, v2, -0x9

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_3
    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo00:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OoooO00(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v4, 0x10

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_4

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo0:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->OooOo0:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit8 v2, v2, -0x11

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_4
    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo0:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OoooO0O(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v4, 0x20

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_5

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo0O:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->OooOo0O:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit8 v2, v2, -0x21

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_5
    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo0O:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OoooOO0(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v4, 0x40

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_6

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo0o:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->OooOo0o:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit8 v2, v2, -0x41

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_6
    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo0o:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OoooOOO(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v4, 0x80

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_7

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->OooOo:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v2, v2, -0x81

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_7
    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOo:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OoooOo0(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v4, 0x100

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_8

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoO0:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->OooOoO0:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v2, v2, -0x101

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_8
    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoO0:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OoooOoo(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v4, 0x200

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_9

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoO:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->OooOoO:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v2, v2, -0x201

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_9
    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoO:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->Ooooo0o(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v4, 0x400

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_a

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoOO:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->OooOoOO:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v2, v2, -0x401

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_a
    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoOO:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OooooOO(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v4, 0x800

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_b

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoo0:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->OooOoo0:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v2, v2, -0x801

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_b
    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoo0:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OooOOOO(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v4, 0x1000

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_c

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoo:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->OooOoo:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v2, v2, -0x1001

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_c
    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOoo:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OooOOo0(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v4, 0x2000

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_d

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOooO:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->OooOooO:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v2, v2, -0x2001

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_d
    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOooO:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OooOOoo(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/16 v4, 0x4000

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_e

    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOooo:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->OooOooo:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    and-int/lit16 v2, v2, -0x4001

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_e
    iget-object v2, p0, Llyiahf/vczjk/xb7;->OooOooo:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OooOo0(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    const v2, 0x8000

    and-int v4, v1, v2

    if-ne v4, v2, :cond_f

    or-int/lit8 v3, v3, 0x8

    :cond_f
    iget v2, p0, Llyiahf/vczjk/xb7;->Oooo000:I

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OooOo0O(Llyiahf/vczjk/zb7;I)V

    const/high16 v2, 0x10000

    and-int v4, v1, v2

    if-ne v4, v2, :cond_10

    or-int/lit8 v3, v3, 0x10

    :cond_10
    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo00O:Llyiahf/vczjk/hd7;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OooOo0o(Llyiahf/vczjk/zb7;Llyiahf/vczjk/hd7;)V

    const/high16 v2, 0x20000

    and-int v4, v1, v2

    if-ne v4, v2, :cond_11

    or-int/lit8 v3, v3, 0x20

    :cond_11
    iget v2, p0, Llyiahf/vczjk/xb7;->Oooo00o:I

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OooOo(Llyiahf/vczjk/zb7;I)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/high16 v4, 0x40000

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_12

    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const v4, -0x40001

    and-int/2addr v2, v4

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_12
    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OooOoO(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/high16 v4, 0x80000

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_13

    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0O0:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0O0:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const v4, -0x80001

    and-int/2addr v2, v4

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_13
    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0O0:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OooOoo0(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/high16 v4, 0x100000

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_14

    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0OO:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0OO:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const v4, -0x100001

    and-int/2addr v2, v4

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_14
    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0OO:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OooOooO(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    const/high16 v2, 0x200000

    and-int v4, v1, v2

    if-ne v4, v2, :cond_15

    or-int/lit8 v3, v3, 0x40

    :cond_15
    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0o0:Llyiahf/vczjk/nd7;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->OooOooo(Llyiahf/vczjk/zb7;Llyiahf/vczjk/nd7;)V

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/high16 v4, 0x400000

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_16

    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0o:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0o:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const v4, -0x400001

    and-int/2addr v2, v4

    iput v2, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_16
    iget-object v2, p0, Llyiahf/vczjk/xb7;->Oooo0o:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/zb7;->Oooo00O(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    const/high16 v2, 0x800000

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_17

    or-int/lit16 v3, v3, 0x80

    :cond_17
    iget-object v1, p0, Llyiahf/vczjk/xb7;->Oooo0oO:Llyiahf/vczjk/ud7;

    invoke-static {v0, v1}, Llyiahf/vczjk/zb7;->Oooo00o(Llyiahf/vczjk/zb7;Llyiahf/vczjk/ud7;)V

    iget v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const/high16 v2, 0x1000000

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_18

    iget-object v1, p0, Llyiahf/vczjk/xb7;->Oooo0oo:Ljava/util/List;

    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/xb7;->Oooo0oo:Ljava/util/List;

    iget v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    const v2, -0x1000001

    and-int/2addr v1, v2

    iput v1, p0, Llyiahf/vczjk/xb7;->OooOOOo:I

    :cond_18
    iget-object v1, p0, Llyiahf/vczjk/xb7;->Oooo0oo:Ljava/util/List;

    invoke-static {v0, v1}, Llyiahf/vczjk/zb7;->Oooo0O0(Llyiahf/vczjk/zb7;Ljava/util/List;)V

    invoke-static {v0, v3}, Llyiahf/vczjk/zb7;->Oooo0OO(Llyiahf/vczjk/zb7;I)V

    return-object v0
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    invoke-static {}, Llyiahf/vczjk/xb7;->OooO0oo()Llyiahf/vczjk/xb7;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/xb7;->OooO0oO()Llyiahf/vczjk/zb7;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/xb7;->OooO(Llyiahf/vczjk/zb7;)V

    return-object v0
.end method
