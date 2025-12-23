.class public final Llyiahf/vczjk/ol5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/pl5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/pl5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ol5;->this$0:Llyiahf/vczjk/pl5;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/ol5;->this$0:Llyiahf/vczjk/pl5;

    const/4 v1, 0x0

    iput-boolean v1, v0, Llyiahf/vczjk/pl5;->OooO0o:Z

    new-instance v2, Ljava/util/HashSet;

    invoke-direct {v2}, Ljava/util/HashSet;-><init>()V

    iget-object v3, v0, Llyiahf/vczjk/pl5;->OooO0Oo:Llyiahf/vczjk/ws5;

    iget-object v4, v3, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v5, v3, Llyiahf/vczjk/ws5;->OooOOOO:I

    move v6, v1

    :goto_0
    iget-object v7, v0, Llyiahf/vczjk/pl5;->OooO0o0:Llyiahf/vczjk/ws5;

    if-ge v6, v5, :cond_1

    aget-object v8, v4, v6

    check-cast v8, Llyiahf/vczjk/ro4;

    iget-object v7, v7, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v7, v7, v6

    check-cast v7, Llyiahf/vczjk/ie7;

    iget-object v8, v8, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v8, v8, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/jl5;

    iget-boolean v9, v8, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v9, :cond_0

    invoke-static {v8, v7, v2}, Llyiahf/vczjk/pl5;->OooO0O0(Llyiahf/vczjk/jl5;Llyiahf/vczjk/ie7;Ljava/util/HashSet;)V

    :cond_0
    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    :cond_1
    invoke-virtual {v3}, Llyiahf/vczjk/ws5;->OooO0oO()V

    invoke-virtual {v7}, Llyiahf/vczjk/ws5;->OooO0oO()V

    iget-object v3, v0, Llyiahf/vczjk/pl5;->OooO0O0:Llyiahf/vczjk/ws5;

    iget-object v4, v3, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v5, v3, Llyiahf/vczjk/ws5;->OooOOOO:I

    :goto_1
    iget-object v6, v0, Llyiahf/vczjk/pl5;->OooO0OO:Llyiahf/vczjk/ws5;

    if-ge v1, v5, :cond_3

    aget-object v7, v4, v1

    check-cast v7, Llyiahf/vczjk/f50;

    iget-object v6, v6, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v6, v6, v1

    check-cast v6, Llyiahf/vczjk/ie7;

    iget-boolean v8, v7, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v8, :cond_2

    invoke-static {v7, v6, v2}, Llyiahf/vczjk/pl5;->OooO0O0(Llyiahf/vczjk/jl5;Llyiahf/vczjk/ie7;Ljava/util/HashSet;)V

    :cond_2
    add-int/lit8 v1, v1, 0x1

    goto :goto_1

    :cond_3
    invoke-virtual {v3}, Llyiahf/vczjk/ws5;->OooO0oO()V

    invoke-virtual {v6}, Llyiahf/vczjk/ws5;->OooO0oO()V

    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/f50;

    invoke-virtual {v1}, Llyiahf/vczjk/f50;->o00000o0()V

    goto :goto_2

    :cond_4
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
