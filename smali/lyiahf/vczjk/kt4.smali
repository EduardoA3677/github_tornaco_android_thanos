.class public final Llyiahf/vczjk/kt4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/o58;

.field public final OooO0O0:Llyiahf/vczjk/qt4;

.field public final OooO0OO:Llyiahf/vczjk/js5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/o58;Llyiahf/vczjk/qt4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/kt4;->OooO00o:Llyiahf/vczjk/o58;

    iput-object p2, p0, Llyiahf/vczjk/kt4;->OooO0O0:Llyiahf/vczjk/qt4;

    sget-object p1, Llyiahf/vczjk/y78;->OooO00o:[J

    new-instance p1, Llyiahf/vczjk/js5;

    invoke-direct {p1}, Llyiahf/vczjk/js5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/kt4;->OooO0OO:Llyiahf/vczjk/js5;

    return-void
.end method


# virtual methods
.method public final OooO00o(ILjava/lang/Object;Ljava/lang/Object;)Llyiahf/vczjk/ze3;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/kt4;->OooO0OO:Llyiahf/vczjk/js5;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/jt4;

    const/4 v2, 0x1

    const v3, 0x53af4291

    if-eqz v1, :cond_1

    iget v4, v1, Llyiahf/vczjk/jt4;->OooO0OO:I

    if-ne v4, p1, :cond_1

    iget-object v4, v1, Llyiahf/vczjk/jt4;->OooO0O0:Ljava/lang/Object;

    invoke-static {v4, p3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1

    iget-object p1, v1, Llyiahf/vczjk/jt4;->OooO0Oo:Llyiahf/vczjk/a91;

    if-nez p1, :cond_0

    new-instance p1, Llyiahf/vczjk/it4;

    iget-object p2, v1, Llyiahf/vczjk/jt4;->OooO0o0:Llyiahf/vczjk/kt4;

    invoke-direct {p1, p2, v1}, Llyiahf/vczjk/it4;-><init>(Llyiahf/vczjk/kt4;Llyiahf/vczjk/jt4;)V

    new-instance p2, Llyiahf/vczjk/a91;

    invoke-direct {p2, v3, p1, v2}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    iput-object p2, v1, Llyiahf/vczjk/jt4;->OooO0Oo:Llyiahf/vczjk/a91;

    return-object p2

    :cond_0
    return-object p1

    :cond_1
    new-instance v1, Llyiahf/vczjk/jt4;

    invoke-direct {v1, p0, p1, p2, p3}, Llyiahf/vczjk/jt4;-><init>(Llyiahf/vczjk/kt4;ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v0, p2, v1}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object p1, v1, Llyiahf/vczjk/jt4;->OooO0Oo:Llyiahf/vczjk/a91;

    if-nez p1, :cond_2

    new-instance p1, Llyiahf/vczjk/it4;

    invoke-direct {p1, p0, v1}, Llyiahf/vczjk/it4;-><init>(Llyiahf/vczjk/kt4;Llyiahf/vczjk/jt4;)V

    new-instance p2, Llyiahf/vczjk/a91;

    invoke-direct {p2, v3, p1, v2}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    iput-object p2, v1, Llyiahf/vczjk/jt4;->OooO0Oo:Llyiahf/vczjk/a91;

    return-object p2

    :cond_2
    return-object p1
.end method

.method public final OooO0O0(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/kt4;->OooO0OO:Llyiahf/vczjk/js5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/jt4;

    if-eqz v0, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/jt4;->OooO0O0:Ljava/lang/Object;

    return-object p1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/kt4;->OooO0O0:Llyiahf/vczjk/qt4;

    invoke-virtual {v0}, Llyiahf/vczjk/qt4;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nt4;

    invoke-interface {v0, p1}, Llyiahf/vczjk/nt4;->OooO0Oo(Ljava/lang/Object;)I

    move-result p1

    const/4 v1, -0x1

    if-eq p1, v1, :cond_2

    invoke-interface {v0, p1}, Llyiahf/vczjk/nt4;->OooO0OO(I)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_2
    :goto_0
    const/4 p1, 0x0

    return-object p1
.end method
