.class public final Llyiahf/vczjk/re8;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/jl5;

.field public final OooO0O0:Z

.field public final OooO0OO:Llyiahf/vczjk/ro4;

.field public final OooO0Oo:Llyiahf/vczjk/je8;

.field public OooO0o:Llyiahf/vczjk/re8;

.field public OooO0o0:Z

.field public final OooO0oO:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jl5;ZLlyiahf/vczjk/ro4;Llyiahf/vczjk/je8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/re8;->OooO00o:Llyiahf/vczjk/jl5;

    iput-boolean p2, p0, Llyiahf/vczjk/re8;->OooO0O0:Z

    iput-object p3, p0, Llyiahf/vczjk/re8;->OooO0OO:Llyiahf/vczjk/ro4;

    iput-object p4, p0, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    iget p1, p3, Llyiahf/vczjk/ro4;->OooOOO:I

    iput p1, p0, Llyiahf/vczjk/re8;->OooO0oO:I

    return-void
.end method

.method public static synthetic OooO0oo(ILlyiahf/vczjk/re8;)Ljava/util/List;
    .locals 3

    and-int/lit8 v0, p0, 0x1

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-eqz v0, :cond_0

    iget-boolean v0, p1, Llyiahf/vczjk/re8;->OooO0O0:Z

    xor-int/2addr v0, v2

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    and-int/lit8 p0, p0, 0x2

    if-eqz p0, :cond_1

    goto :goto_1

    :cond_1
    move v1, v2

    :goto_1
    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/re8;->OooO0oO(ZZ)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/je8;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/re8;->OooOO0o()Z

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    if-eqz v0, :cond_0

    invoke-virtual {v1}, Llyiahf/vczjk/je8;->OooO00o()Llyiahf/vczjk/je8;

    move-result-object v0

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {p0, v1, v0}, Llyiahf/vczjk/re8;->OooOOO(Ljava/util/ArrayList;Llyiahf/vczjk/je8;)V

    return-object v0

    :cond_0
    return-object v1
.end method

.method public final OooO00o(Llyiahf/vczjk/gu7;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/re8;
    .locals 5

    new-instance v0, Llyiahf/vczjk/je8;

    invoke-direct {v0}, Llyiahf/vczjk/je8;-><init>()V

    const/4 v1, 0x0

    iput-boolean v1, v0, Llyiahf/vczjk/je8;->OooOOOO:Z

    iput-boolean v1, v0, Llyiahf/vczjk/je8;->OooOOOo:Z

    invoke-interface {p2, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v2, Llyiahf/vczjk/re8;

    new-instance v3, Llyiahf/vczjk/qe8;

    invoke-direct {v3, p2}, Llyiahf/vczjk/qe8;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance p2, Llyiahf/vczjk/ro4;

    iget v4, p0, Llyiahf/vczjk/re8;->OooO0oO:I

    if-eqz p1, :cond_0

    const p1, 0x3b9aca00

    :goto_0
    add-int/2addr v4, p1

    goto :goto_1

    :cond_0
    const p1, 0x77359400

    goto :goto_0

    :goto_1
    const/4 p1, 0x1

    invoke-direct {p2, p1, v4}, Llyiahf/vczjk/ro4;-><init>(ZI)V

    invoke-direct {v2, v3, v1, p2, v0}, Llyiahf/vczjk/re8;-><init>(Llyiahf/vczjk/jl5;ZLlyiahf/vczjk/ro4;Llyiahf/vczjk/je8;)V

    iput-boolean p1, v2, Llyiahf/vczjk/re8;->OooO0o0:Z

    iput-object p0, v2, Llyiahf/vczjk/re8;->OooO0o:Llyiahf/vczjk/re8;

    return-object v2
.end method

.method public final OooO0O0(Llyiahf/vczjk/ro4;Ljava/util/ArrayList;)V
    .locals 5

    invoke-virtual {p1}, Llyiahf/vczjk/ro4;->OooOoO0()Llyiahf/vczjk/ws5;

    move-result-object p1

    iget-object v0, p1, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget p1, p1, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v1, 0x0

    :goto_0
    if-ge v1, p1, :cond_2

    aget-object v2, v0, v1

    check-cast v2, Llyiahf/vczjk/ro4;

    invoke-virtual {v2}, Llyiahf/vczjk/ro4;->Oooo00o()Z

    move-result v3

    if-eqz v3, :cond_1

    iget-boolean v3, v2, Llyiahf/vczjk/ro4;->Ooooo00:Z

    if-nez v3, :cond_1

    iget-object v3, v2, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    const/16 v4, 0x8

    invoke-virtual {v3, v4}, Llyiahf/vczjk/jb0;->OooO0o0(I)Z

    move-result v3

    if-eqz v3, :cond_0

    iget-boolean v3, p0, Llyiahf/vczjk/re8;->OooO0O0:Z

    invoke-static {v2, v3}, Llyiahf/vczjk/rl6;->OooO0OO(Llyiahf/vczjk/ro4;Z)Llyiahf/vczjk/re8;

    move-result-object v2

    invoke-virtual {p2, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_0
    invoke-virtual {p0, v2, p2}, Llyiahf/vczjk/re8;->OooO0O0(Llyiahf/vczjk/ro4;Ljava/util/ArrayList;)V

    :cond_1
    :goto_1
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_2
    return-void
.end method

.method public final OooO0OO()Llyiahf/vczjk/v16;
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/re8;->OooO0o0:Z

    if-eqz v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/re8;->OooOO0()Llyiahf/vczjk/re8;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/re8;->OooO0OO()Llyiahf/vczjk/v16;

    move-result-object v0

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/re8;->OooO0OO:Llyiahf/vczjk/ro4;

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOOOo(Llyiahf/vczjk/ro4;)Llyiahf/vczjk/ne8;

    move-result-object v0

    if-eqz v0, :cond_2

    goto :goto_0

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/re8;->OooO00o:Llyiahf/vczjk/jl5;

    :goto_0
    const/16 v1, 0x8

    invoke-static {v0, v1}, Llyiahf/vczjk/yi4;->o00ooo(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/v16;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0Oo(Ljava/util/ArrayList;Ljava/util/ArrayList;)V
    .locals 4

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v0

    const/4 v1, 0x0

    invoke-virtual {p0, p1, v1}, Llyiahf/vczjk/re8;->OooOOOO(Ljava/util/ArrayList;Z)Ljava/util/List;

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v1

    :goto_0
    if-ge v0, v1, :cond_2

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/re8;

    invoke-virtual {v2}, Llyiahf/vczjk/re8;->OooOO0o()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-virtual {p2, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_0
    iget-object v3, v2, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    iget-boolean v3, v3, Llyiahf/vczjk/je8;->OooOOOo:Z

    if-nez v3, :cond_1

    invoke-virtual {v2, p1, p2}, Llyiahf/vczjk/re8;->OooO0Oo(Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    :cond_1
    :goto_1
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_2
    return-void
.end method

.method public final OooO0o()Llyiahf/vczjk/wj7;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/re8;->OooO0OO()Llyiahf/vczjk/v16;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->o000OO()Llyiahf/vczjk/jl5;

    move-result-object v1

    iget-boolean v1, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/ng0;->OooOO0o(Llyiahf/vczjk/xn4;)Llyiahf/vczjk/wj7;

    move-result-object v0

    return-object v0

    :cond_1
    sget-object v0, Llyiahf/vczjk/wj7;->OooO0o0:Llyiahf/vczjk/wj7;

    return-object v0
.end method

.method public final OooO0o0()Llyiahf/vczjk/wj7;
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/re8;->OooO0OO()Llyiahf/vczjk/v16;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->o000OO()Llyiahf/vczjk/jl5;

    move-result-object v1

    iget-boolean v1, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/ng0;->OooOo0o(Llyiahf/vczjk/xn4;)Llyiahf/vczjk/xn4;

    move-result-object v1

    const/4 v2, 0x1

    invoke-interface {v1, v0, v2}, Llyiahf/vczjk/xn4;->OooOOO0(Llyiahf/vczjk/xn4;Z)Llyiahf/vczjk/wj7;

    move-result-object v0

    return-object v0

    :cond_1
    sget-object v0, Llyiahf/vczjk/wj7;->OooO0o0:Llyiahf/vczjk/wj7;

    return-object v0
.end method

.method public final OooO0oO(ZZ)Ljava/util/List;
    .locals 1

    if-nez p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    iget-boolean p1, p1, Llyiahf/vczjk/je8;->OooOOOo:Z

    if-eqz p1, :cond_0

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1

    :cond_0
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {p0}, Llyiahf/vczjk/re8;->OooOO0o()Z

    move-result v0

    if-eqz v0, :cond_1

    new-instance p2, Ljava/util/ArrayList;

    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/re8;->OooO0Oo(Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    return-object p2

    :cond_1
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/re8;->OooOOOO(Ljava/util/ArrayList;Z)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0()Llyiahf/vczjk/re8;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/re8;->OooO0o:Llyiahf/vczjk/re8;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/re8;->OooO0OO:Llyiahf/vczjk/ro4;

    iget-boolean v1, p0, Llyiahf/vczjk/re8;->OooO0O0:Z

    const/4 v2, 0x0

    if-eqz v1, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v3

    :goto_0
    if-eqz v3, :cond_2

    invoke-virtual {v3}, Llyiahf/vczjk/ro4;->OooOo()Llyiahf/vczjk/je8;

    move-result-object v4

    if-eqz v4, :cond_1

    iget-boolean v4, v4, Llyiahf/vczjk/je8;->OooOOOO:Z

    const/4 v5, 0x1

    if-ne v4, v5, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v3}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v3

    goto :goto_0

    :cond_2
    move-object v3, v2

    :goto_1
    if-nez v3, :cond_5

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    :goto_2
    if-eqz v0, :cond_4

    iget-object v3, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    const/16 v4, 0x8

    invoke-virtual {v3, v4}, Llyiahf/vczjk/jb0;->OooO0o0(I)Z

    move-result v3

    if-eqz v3, :cond_3

    move-object v3, v0

    goto :goto_3

    :cond_3
    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    goto :goto_2

    :cond_4
    move-object v3, v2

    :cond_5
    :goto_3
    if-nez v3, :cond_6

    return-object v2

    :cond_6
    invoke-static {v3, v1}, Llyiahf/vczjk/rl6;->OooO0OO(Llyiahf/vczjk/ro4;Z)Llyiahf/vczjk/re8;

    move-result-object v0

    return-object v0
.end method

.method public final OooOO0O()Llyiahf/vczjk/je8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    return-object v0
.end method

.method public final OooOO0o()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/re8;->OooO0O0:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    iget-boolean v0, v0, Llyiahf/vczjk/je8;->OooOOOO:Z

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOO(Ljava/util/ArrayList;Llyiahf/vczjk/je8;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    iget-boolean v0, v0, Llyiahf/vczjk/je8;->OooOOOo:Z

    if-nez v0, :cond_1

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v0

    const/4 v1, 0x0

    invoke-virtual {p0, p1, v1}, Llyiahf/vczjk/re8;->OooOOOO(Ljava/util/ArrayList;Z)Ljava/util/List;

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v1

    :goto_0
    if-ge v0, v1, :cond_1

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/re8;

    invoke-virtual {v2}, Llyiahf/vczjk/re8;->OooOO0o()Z

    move-result v3

    if-nez v3, :cond_0

    iget-object v3, v2, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    invoke-virtual {p2, v3}, Llyiahf/vczjk/je8;->OooO0o(Llyiahf/vczjk/je8;)V

    invoke-virtual {v2, p1, p2}, Llyiahf/vczjk/re8;->OooOOO(Ljava/util/ArrayList;Llyiahf/vczjk/je8;)V

    :cond_0
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public final OooOOO0()Z
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/re8;->OooO0o0:Z

    if-nez v0, :cond_2

    const/4 v0, 0x4

    invoke-static {v0, p0}, Llyiahf/vczjk/re8;->OooO0oo(ILlyiahf/vczjk/re8;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/re8;->OooO0OO:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    :goto_0
    const/4 v1, 0x1

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo()Llyiahf/vczjk/je8;

    move-result-object v2

    if-eqz v2, :cond_0

    iget-boolean v2, v2, Llyiahf/vczjk/je8;->OooOOOO:Z

    if-ne v2, v1, :cond_0

    goto :goto_1

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_1
    if-nez v0, :cond_2

    return v1

    :cond_2
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOOO(Ljava/util/ArrayList;Z)Ljava/util/List;
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/re8;->OooO0o0:Z

    if-eqz v0, :cond_0

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/re8;->OooO0OO:Llyiahf/vczjk/ro4;

    invoke-virtual {p0, v0, p1}, Llyiahf/vczjk/re8;->OooO0O0(Llyiahf/vczjk/ro4;Ljava/util/ArrayList;)V

    if-eqz p2, :cond_5

    sget-object p2, Llyiahf/vczjk/ve8;->OooOo0o:Llyiahf/vczjk/ze8;

    iget-object v0, p0, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    iget-object v1, v0, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v1, p2}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    const/4 v2, 0x0

    if-nez p2, :cond_1

    move-object p2, v2

    :cond_1
    check-cast p2, Llyiahf/vczjk/gu7;

    if-eqz p2, :cond_2

    iget-boolean v3, v0, Llyiahf/vczjk/je8;->OooOOOO:Z

    if-eqz v3, :cond_2

    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v3

    if-nez v3, :cond_2

    new-instance v3, Llyiahf/vczjk/oe8;

    invoke-direct {v3, p2}, Llyiahf/vczjk/oe8;-><init>(Llyiahf/vczjk/gu7;)V

    invoke-virtual {p0, p2, v3}, Llyiahf/vczjk/re8;->OooO00o(Llyiahf/vczjk/gu7;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/re8;

    move-result-object p2

    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_2
    sget-object p2, Llyiahf/vczjk/ve8;->OooO00o:Llyiahf/vczjk/ze8;

    invoke-virtual {v1, p2}, Llyiahf/vczjk/js5;->OooO0OO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v3

    if-nez v3, :cond_5

    iget-boolean v0, v0, Llyiahf/vczjk/je8;->OooOOOO:Z

    if-eqz v0, :cond_5

    invoke-virtual {v1, p2}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    if-nez p2, :cond_3

    move-object p2, v2

    :cond_3
    check-cast p2, Ljava/util/List;

    if-eqz p2, :cond_4

    invoke-static {p2}, Llyiahf/vczjk/d21;->oo000o(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/String;

    goto :goto_0

    :cond_4
    move-object p2, v2

    :goto_0
    if-eqz p2, :cond_5

    new-instance v0, Llyiahf/vczjk/pe8;

    invoke-direct {v0, p2}, Llyiahf/vczjk/pe8;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v2, v0}, Llyiahf/vczjk/re8;->OooO00o(Llyiahf/vczjk/gu7;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/re8;

    move-result-object p2

    const/4 v0, 0x0

    invoke-virtual {p1, v0, p2}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    :cond_5
    return-object p1
.end method
