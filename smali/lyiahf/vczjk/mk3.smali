.class public Llyiahf/vczjk/mk3;
.super Llyiahf/vczjk/hg8;
.source "SourceFile"


# instance fields
.field public OooO00o:Llyiahf/vczjk/r1a;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/hg8;-><init>()V

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/mk3;->OooO00o:Llyiahf/vczjk/r1a;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/qb4;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mk3;->OooO00o:Llyiahf/vczjk/r1a;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r1a;->OooO0O0(Llyiahf/vczjk/qb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Adapter for type with cyclic dependency has been used before dependency has been resolved"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/zc4;Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mk3;->OooO00o:Llyiahf/vczjk/r1a;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/r1a;->OooO0OO(Llyiahf/vczjk/zc4;Ljava/lang/Object;)V

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "Adapter for type with cyclic dependency has been used before dependency has been resolved"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0Oo()Llyiahf/vczjk/r1a;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/mk3;->OooO00o:Llyiahf/vczjk/r1a;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Adapter for type with cyclic dependency has been used before dependency has been resolved"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
