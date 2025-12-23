.class public final Llyiahf/vczjk/nj8;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:Llyiahf/vczjk/nj8;

.field public final OooO0O0:Llyiahf/vczjk/rga;

.field public final OooO0OO:Ljava/util/ArrayList;

.field public final OooO0Oo:Llyiahf/vczjk/vy;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nj8;Llyiahf/vczjk/rga;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/nj8;->OooO00o:Llyiahf/vczjk/nj8;

    iput-object p2, p0, Llyiahf/vczjk/nj8;->OooO0O0:Llyiahf/vczjk/rga;

    iget-object p1, p2, Llyiahf/vczjk/rga;->OooO0o0:Ljava/util/ArrayList;

    new-instance p2, Ljava/util/ArrayList;

    const/16 v0, 0xa

    invoke-static {p1, v0}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v0

    invoke-direct {p2, v0}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/rga;

    new-instance v1, Llyiahf/vczjk/nj8;

    invoke-direct {v1, p0, v0}, Llyiahf/vczjk/nj8;-><init>(Llyiahf/vczjk/nj8;Llyiahf/vczjk/rga;)V

    invoke-virtual {p2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    invoke-static {p2}, Llyiahf/vczjk/d21;->o0000OO0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/nj8;->OooO0OO:Ljava/util/ArrayList;

    new-instance p1, Llyiahf/vczjk/mj8;

    const/4 p2, 0x0

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/mj8;-><init>(Llyiahf/vczjk/nj8;Llyiahf/vczjk/yo1;)V

    new-instance p2, Llyiahf/vczjk/vy;

    invoke-direct {p2, p1}, Llyiahf/vczjk/vy;-><init>(Llyiahf/vczjk/ze3;)V

    iput-object p2, p0, Llyiahf/vczjk/nj8;->OooO0Oo:Llyiahf/vczjk/vy;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/nj8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nj8;->OooO00o:Llyiahf/vczjk/nj8;

    if-nez v0, :cond_0

    return-object p0

    :cond_0
    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v0}, Llyiahf/vczjk/nj8;->OooO00o()Llyiahf/vczjk/nj8;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/rga;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/nj8;->OooO0O0:Llyiahf/vczjk/rga;

    iget-object v2, v0, Llyiahf/vczjk/rga;->OooO00o:Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/nj8;->OooO0OO:Ljava/util/ArrayList;

    new-instance v6, Ljava/util/ArrayList;

    const/16 v3, 0xa

    invoke-static {v1, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v6, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/nj8;

    invoke-virtual {v3}, Llyiahf/vczjk/nj8;->OooO0O0()Llyiahf/vczjk/rga;

    move-result-object v3

    invoke-virtual {v6, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    new-instance v1, Llyiahf/vczjk/rga;

    iget v3, v0, Llyiahf/vczjk/rga;->OooO0O0:I

    iget-object v4, v0, Llyiahf/vczjk/rga;->OooO0OO:Llyiahf/vczjk/y14;

    iget-object v5, v0, Llyiahf/vczjk/rga;->OooO0Oo:Llyiahf/vczjk/yx8;

    iget-object v7, v0, Llyiahf/vczjk/rga;->OooO0o:Llyiahf/vczjk/bo4;

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/rga;-><init>(Ljava/lang/String;ILlyiahf/vczjk/y14;Llyiahf/vczjk/yx8;Ljava/util/ArrayList;Llyiahf/vczjk/bo4;)V

    return-object v1
.end method
