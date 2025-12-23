.class public abstract Llyiahf/vczjk/pg3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Cloneable;


# instance fields
.field public OooOOO:Llyiahf/vczjk/wg3;

.field public final OooOOO0:Llyiahf/vczjk/wg3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wg3;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/pg3;->OooOOO0:Llyiahf/vczjk/wg3;

    invoke-virtual {p1}, Llyiahf/vczjk/wg3;->OooO0o()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/wg3;->OooO0oo()Llyiahf/vczjk/wg3;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/pg3;->OooOOO:Llyiahf/vczjk/wg3;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Default instance must be immutable."

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/wg3;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/pg3;->OooO0O0()Llyiahf/vczjk/wg3;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x1

    invoke-static {v0, v1}, Llyiahf/vczjk/wg3;->OooO0o0(Llyiahf/vczjk/wg3;Z)Z

    move-result v1

    if-eqz v1, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Llyiahf/vczjk/w8a;

    invoke-direct {v0}, Llyiahf/vczjk/w8a;-><init>()V

    throw v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/wg3;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/pg3;->OooOOO:Llyiahf/vczjk/wg3;

    invoke-virtual {v0}, Llyiahf/vczjk/wg3;->OooO0o()Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/pg3;->OooOOO:Llyiahf/vczjk/wg3;

    return-object v0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/pg3;->OooOOO:Llyiahf/vczjk/wg3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/de7;->OooO0OO:Llyiahf/vczjk/de7;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/de7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/u88;

    move-result-object v1

    invoke-interface {v1, v0}, Llyiahf/vczjk/u88;->makeImmutable(Ljava/lang/Object;)V

    invoke-virtual {v0}, Llyiahf/vczjk/wg3;->OooO0oO()V

    iget-object v0, p0, Llyiahf/vczjk/pg3;->OooOOO:Llyiahf/vczjk/wg3;

    return-object v0
.end method

.method public final OooO0OO()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/pg3;->OooOOO:Llyiahf/vczjk/wg3;

    invoke-virtual {v0}, Llyiahf/vczjk/wg3;->OooO0o()Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/pg3;->OooOOO0:Llyiahf/vczjk/wg3;

    invoke-virtual {v0}, Llyiahf/vczjk/wg3;->OooO0oo()Llyiahf/vczjk/wg3;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/pg3;->OooOOO:Llyiahf/vczjk/wg3;

    sget-object v2, Llyiahf/vczjk/de7;->OooO0OO:Llyiahf/vczjk/de7;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v2, v3}, Llyiahf/vczjk/de7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/u88;

    move-result-object v2

    invoke-interface {v2, v0, v1}, Llyiahf/vczjk/u88;->mergeFrom(Ljava/lang/Object;Ljava/lang/Object;)V

    iput-object v0, p0, Llyiahf/vczjk/pg3;->OooOOO:Llyiahf/vczjk/wg3;

    :cond_0
    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    const/4 v0, 0x5

    iget-object v1, p0, Llyiahf/vczjk/pg3;->OooOOO0:Llyiahf/vczjk/wg3;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/wg3;->OooO0O0(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/pg3;

    invoke-virtual {p0}, Llyiahf/vczjk/pg3;->OooO0O0()Llyiahf/vczjk/wg3;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/pg3;->OooOOO:Llyiahf/vczjk/wg3;

    return-object v0
.end method
