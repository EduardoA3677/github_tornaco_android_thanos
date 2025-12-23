.class public final Landroidx/compose/runtime/OooO00o;
.super Llyiahf/vczjk/lg1;
.source "SourceFile"


# instance fields
.field public final OooO00o:I

.field public final OooO0O0:Z

.field public final OooO0OO:Z

.field public OooO0Oo:Ljava/util/HashSet;

.field public final OooO0o:Llyiahf/vczjk/qs5;

.field public final OooO0o0:Ljava/util/LinkedHashSet;

.field public final synthetic OooO0oO:Llyiahf/vczjk/zf1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zf1;IZZLlyiahf/vczjk/vp3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/compose/runtime/OooO00o;->OooO0oO:Llyiahf/vczjk/zf1;

    iput p2, p0, Landroidx/compose/runtime/OooO00o;->OooO00o:I

    iput-boolean p3, p0, Landroidx/compose/runtime/OooO00o;->OooO0O0:Z

    iput-boolean p4, p0, Landroidx/compose/runtime/OooO00o;->OooO0OO:Z

    new-instance p1, Ljava/util/LinkedHashSet;

    invoke-direct {p1}, Ljava/util/LinkedHashSet;-><init>()V

    iput-object p1, p0, Landroidx/compose/runtime/OooO00o;->OooO0o0:Ljava/util/LinkedHashSet;

    sget-object p1, Llyiahf/vczjk/os6;->OooOOOo:Llyiahf/vczjk/os6;

    sget-object p2, Llyiahf/vczjk/pp3;->OooOo00:Llyiahf/vczjk/pp3;

    new-instance p3, Landroidx/compose/runtime/ParcelableSnapshotMutableState;

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/fw8;-><init>(Ljava/lang/Object;Llyiahf/vczjk/gw8;)V

    iput-object p3, p0, Landroidx/compose/runtime/OooO00o;->OooO0o:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/sg1;)V
    .locals 3

    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0oO:Llyiahf/vczjk/zf1;

    iget-object v1, v0, Llyiahf/vczjk/zf1;->OooO0O0:Llyiahf/vczjk/lg1;

    iget-object v2, v0, Llyiahf/vczjk/zf1;->OooO0oO:Llyiahf/vczjk/sg1;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/lg1;->OooO(Llyiahf/vczjk/sg1;)V

    iget-object v0, v0, Llyiahf/vczjk/zf1;->OooO0O0:Llyiahf/vczjk/lg1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/lg1;->OooO(Llyiahf/vczjk/sg1;)V

    return-void
.end method

.method public final OooO00o(Llyiahf/vczjk/sg1;Llyiahf/vczjk/a91;)V
    .locals 1

    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0oO:Llyiahf/vczjk/zf1;

    iget-object v0, v0, Llyiahf/vczjk/zf1;->OooO0O0:Llyiahf/vczjk/lg1;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/lg1;->OooO00o(Llyiahf/vczjk/sg1;Llyiahf/vczjk/a91;)V

    return-void
.end method

.method public final OooO0O0()V
    .locals 2

    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0oO:Llyiahf/vczjk/zf1;

    iget v1, v0, Llyiahf/vczjk/zf1;->OooOoO:I

    add-int/lit8 v1, v1, -0x1

    iput v1, v0, Llyiahf/vczjk/zf1;->OooOoO:I

    return-void
.end method

.method public final OooO0OO()Z
    .locals 1

    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0oO:Llyiahf/vczjk/zf1;

    iget-object v0, v0, Llyiahf/vczjk/zf1;->OooO0O0:Llyiahf/vczjk/lg1;

    invoke-virtual {v0}, Llyiahf/vczjk/lg1;->OooO0OO()Z

    move-result v0

    return v0
.end method

.method public final OooO0Oo()Z
    .locals 1

    iget-boolean v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0O0:Z

    return v0
.end method

.method public final OooO0o()Llyiahf/vczjk/ps6;
    .locals 1

    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0o:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ps6;

    return-object v0
.end method

.method public final OooO0o0()Z
    .locals 1

    iget-boolean v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0OO:Z

    return v0
.end method

.method public final OooO0oO()I
    .locals 1

    iget v0, p0, Landroidx/compose/runtime/OooO00o;->OooO00o:I

    return v0
.end method

.method public final OooO0oo()Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0oO:Llyiahf/vczjk/zf1;

    iget-object v0, v0, Llyiahf/vczjk/zf1;->OooO0O0:Llyiahf/vczjk/lg1;

    invoke-virtual {v0}, Llyiahf/vczjk/lg1;->OooO0oo()Llyiahf/vczjk/or1;

    move-result-object v0

    return-object v0
.end method

.method public final OooOO0(Llyiahf/vczjk/wp5;)Llyiahf/vczjk/vp5;
    .locals 1

    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0oO:Llyiahf/vczjk/zf1;

    iget-object v0, v0, Llyiahf/vczjk/zf1;->OooO0O0:Llyiahf/vczjk/lg1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/lg1;->OooOO0(Llyiahf/vczjk/wp5;)Llyiahf/vczjk/vp5;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0O(Ljava/util/Set;)V
    .locals 1

    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0Oo:Ljava/util/HashSet;

    if-nez v0, :cond_0

    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    iput-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0Oo:Ljava/util/HashSet;

    :cond_0
    invoke-interface {v0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public final OooOO0o(Llyiahf/vczjk/zf1;)V
    .locals 1

    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0o0:Ljava/util/LinkedHashSet;

    invoke-interface {v0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public final OooOOO()V
    .locals 2

    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0oO:Llyiahf/vczjk/zf1;

    iget v1, v0, Llyiahf/vczjk/zf1;->OooOoO:I

    add-int/lit8 v1, v1, 0x1

    iput v1, v0, Llyiahf/vczjk/zf1;->OooOoO:I

    return-void
.end method

.method public final OooOOO0(Llyiahf/vczjk/sg1;)V
    .locals 1

    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0oO:Llyiahf/vczjk/zf1;

    iget-object v0, v0, Llyiahf/vczjk/zf1;->OooO0O0:Llyiahf/vczjk/lg1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/lg1;->OooOOO0(Llyiahf/vczjk/sg1;)V

    return-void
.end method

.method public final OooOOOO(Llyiahf/vczjk/rf1;)V
    .locals 3

    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0Oo:Ljava/util/HashSet;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Set;

    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.ComposerImpl"

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/zf1;

    iget-object v2, v2, Llyiahf/vczjk/zf1;->OooO0OO:Llyiahf/vczjk/js8;

    invoke-interface {v1, v2}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0o0:Ljava/util/LinkedHashSet;

    instance-of v1, v0, Llyiahf/vczjk/cg4;

    if-eqz v1, :cond_2

    instance-of v1, v0, Llyiahf/vczjk/dg4;

    if-eqz v1, :cond_1

    goto :goto_1

    :cond_1
    const-string p1, "kotlin.collections.MutableCollection"

    invoke-static {v0, p1}, Llyiahf/vczjk/l4a;->Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1

    :cond_2
    :goto_1
    invoke-interface {v0, p1}, Ljava/util/Collection;->remove(Ljava/lang/Object;)Z

    return-void
.end method

.method public final OooOOOo(Llyiahf/vczjk/sg1;)V
    .locals 1

    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0oO:Llyiahf/vczjk/zf1;

    iget-object v0, v0, Llyiahf/vczjk/zf1;->OooO0O0:Llyiahf/vczjk/lg1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/lg1;->OooOOOo(Llyiahf/vczjk/sg1;)V

    return-void
.end method

.method public final OooOOo0()V
    .locals 7

    iget-object v0, p0, Landroidx/compose/runtime/OooO00o;->OooO0o0:Ljava/util/LinkedHashSet;

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_2

    iget-object v1, p0, Landroidx/compose/runtime/OooO00o;->OooO0Oo:Ljava/util/HashSet;

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_0

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/Set;

    iget-object v6, v3, Llyiahf/vczjk/zf1;->OooO0OO:Llyiahf/vczjk/js8;

    invoke-interface {v5, v6}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    invoke-interface {v0}, Ljava/util/Set;->clear()V

    :cond_2
    return-void
.end method
