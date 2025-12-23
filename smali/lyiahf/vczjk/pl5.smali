.class public final Llyiahf/vczjk/pl5;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/xa;

.field public final OooO0O0:Llyiahf/vczjk/ws5;

.field public final OooO0OO:Llyiahf/vczjk/ws5;

.field public final OooO0Oo:Llyiahf/vczjk/ws5;

.field public OooO0o:Z

.field public final OooO0o0:Llyiahf/vczjk/ws5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xa;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/pl5;->OooO00o:Llyiahf/vczjk/xa;

    new-instance p1, Llyiahf/vczjk/ws5;

    const/16 v0, 0x10

    new-array v1, v0, [Llyiahf/vczjk/f50;

    invoke-direct {p1, v1}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/pl5;->OooO0O0:Llyiahf/vczjk/ws5;

    new-instance p1, Llyiahf/vczjk/ws5;

    new-array v1, v0, [Llyiahf/vczjk/ie7;

    invoke-direct {p1, v1}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/pl5;->OooO0OO:Llyiahf/vczjk/ws5;

    new-instance p1, Llyiahf/vczjk/ws5;

    new-array v1, v0, [Llyiahf/vczjk/ro4;

    invoke-direct {p1, v1}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/pl5;->OooO0Oo:Llyiahf/vczjk/ws5;

    new-instance p1, Llyiahf/vczjk/ws5;

    new-array v0, v0, [Llyiahf/vczjk/ie7;

    invoke-direct {p1, v0}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/pl5;->OooO0o0:Llyiahf/vczjk/ws5;

    return-void
.end method

.method public static OooO0O0(Llyiahf/vczjk/jl5;Llyiahf/vczjk/ie7;Ljava/util/HashSet;)V
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v0, v0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    const-string v0, "visitSubtreeIf called on an unattached node"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    new-instance v0, Llyiahf/vczjk/ws5;

    const/16 v1, 0x10

    new-array v2, v1, [Llyiahf/vczjk/jl5;

    invoke-direct {v0, v2}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iget-object p0, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-object v2, p0, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    if-nez v2, :cond_1

    invoke-static {v0, p0}, Llyiahf/vczjk/yi4;->OooOOoo(Llyiahf/vczjk/ws5;Llyiahf/vczjk/jl5;)V

    goto :goto_0

    :cond_1
    invoke-virtual {v0, v2}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :goto_0
    iget p0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    if-eqz p0, :cond_c

    add-int/lit8 p0, p0, -0x1

    invoke-virtual {v0, p0}, Llyiahf/vczjk/ws5;->OooOO0O(I)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/jl5;

    iget v2, p0, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit8 v2, v2, 0x20

    if-eqz v2, :cond_b

    move-object v2, p0

    :goto_1
    if-eqz v2, :cond_b

    iget v3, v2, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v3, v3, 0x20

    if-eqz v3, :cond_a

    const/4 v3, 0x0

    move-object v4, v2

    move-object v5, v3

    :goto_2
    if-eqz v4, :cond_a

    instance-of v6, v4, Llyiahf/vczjk/ql5;

    if-eqz v6, :cond_3

    check-cast v4, Llyiahf/vczjk/ql5;

    instance-of v6, v4, Llyiahf/vczjk/f50;

    if-eqz v6, :cond_2

    move-object v6, v4

    check-cast v6, Llyiahf/vczjk/f50;

    iget-object v7, v6, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    instance-of v7, v7, Llyiahf/vczjk/nl5;

    if-eqz v7, :cond_2

    iget-object v6, v6, Llyiahf/vczjk/f50;->OooOoo:Ljava/util/HashSet;

    invoke-virtual {v6, p1}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_2

    invoke-virtual {p2, v4}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    :cond_2
    invoke-interface {v4}, Llyiahf/vczjk/ql5;->OoooO0O()Llyiahf/vczjk/e16;

    move-result-object v4

    invoke-virtual {v4, p1}, Llyiahf/vczjk/e16;->OooOOo0(Llyiahf/vczjk/ie7;)Z

    move-result v4

    if-eqz v4, :cond_9

    goto :goto_0

    :cond_3
    iget v6, v4, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v6, v6, 0x20

    if-eqz v6, :cond_9

    instance-of v6, v4, Llyiahf/vczjk/m52;

    if-eqz v6, :cond_9

    move-object v6, v4

    check-cast v6, Llyiahf/vczjk/m52;

    iget-object v6, v6, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    const/4 v7, 0x0

    :goto_3
    const/4 v8, 0x1

    if-eqz v6, :cond_8

    iget v9, v6, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v9, v9, 0x20

    if-eqz v9, :cond_7

    add-int/lit8 v7, v7, 0x1

    if-ne v7, v8, :cond_4

    move-object v4, v6

    goto :goto_4

    :cond_4
    if-nez v5, :cond_5

    new-instance v5, Llyiahf/vczjk/ws5;

    new-array v8, v1, [Llyiahf/vczjk/jl5;

    invoke-direct {v5, v8}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_5
    if-eqz v4, :cond_6

    invoke-virtual {v5, v4}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v4, v3

    :cond_6
    invoke-virtual {v5, v6}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_7
    :goto_4
    iget-object v6, v6, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_3

    :cond_8
    if-ne v7, v8, :cond_9

    goto :goto_2

    :cond_9
    invoke-static {v5}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v4

    goto :goto_2

    :cond_a
    iget-object v2, v2, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_b
    invoke-static {v0, p0}, Llyiahf/vczjk/yi4;->OooOOoo(Llyiahf/vczjk/ws5;Llyiahf/vczjk/jl5;)V

    goto/16 :goto_0

    :cond_c
    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/pl5;->OooO0o:Z

    if-nez v0, :cond_1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/pl5;->OooO0o:Z

    new-instance v0, Llyiahf/vczjk/ol5;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ol5;-><init>(Llyiahf/vczjk/pl5;)V

    iget-object v1, p0, Llyiahf/vczjk/pl5;->OooO00o:Llyiahf/vczjk/xa;

    iget-object v1, v1, Llyiahf/vczjk/xa;->o000000:Llyiahf/vczjk/as5;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/c76;->OooO0OO(Ljava/lang/Object;)I

    move-result v2

    if-ltz v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1, v0}, Llyiahf/vczjk/as5;->OooO0oO(Ljava/lang/Object;)V

    :cond_1
    :goto_0
    return-void
.end method
