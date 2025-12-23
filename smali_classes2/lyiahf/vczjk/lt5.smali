.class public final Llyiahf/vczjk/lt5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wp0;
.implements Llyiahf/vczjk/nka;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/mt5;

.field public final OooOOO0:Llyiahf/vczjk/yp0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mt5;Llyiahf/vczjk/yp0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/lt5;->OooOOO:Llyiahf/vczjk/mt5;

    iput-object p2, p0, Llyiahf/vczjk/lt5;->OooOOO0:Llyiahf/vczjk/yp0;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/zc8;I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/lt5;->OooOOO0:Llyiahf/vczjk/yp0;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/yp0;->OooO00o(Llyiahf/vczjk/zc8;I)V

    return-void
.end method

.method public final OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/h87;
    .locals 2

    check-cast p1, Llyiahf/vczjk/z8a;

    new-instance p2, Llyiahf/vczjk/kt5;

    iget-object v0, p0, Llyiahf/vczjk/lt5;->OooOOO:Llyiahf/vczjk/mt5;

    invoke-direct {p2, v0, p0}, Llyiahf/vczjk/kt5;-><init>(Llyiahf/vczjk/mt5;Llyiahf/vczjk/lt5;)V

    iget-object v1, p0, Llyiahf/vczjk/lt5;->OooOOO0:Llyiahf/vczjk/yp0;

    invoke-virtual {v1, p1, p2}, Llyiahf/vczjk/yp0;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/h87;

    move-result-object p1

    if-eqz p1, :cond_0

    sget-object p2, Llyiahf/vczjk/mt5;->OooOo00:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    const/4 v1, 0x0

    invoke-virtual {p2, v0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_0
    return-object p1
.end method

.method public final OooOO0o(Ljava/lang/Throwable;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/lt5;->OooOOO0:Llyiahf/vczjk/yp0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yp0;->OooOO0o(Ljava/lang/Throwable;)Z

    move-result p1

    return p1
.end method

.method public final OooOOO0(Ljava/lang/Object;Llyiahf/vczjk/bf3;)V
    .locals 4

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    sget-object p2, Llyiahf/vczjk/mt5;->OooOo00:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/lt5;->OooOOO:Llyiahf/vczjk/mt5;

    invoke-virtual {p2, v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance p2, Llyiahf/vczjk/o0OO000o;

    const/16 v0, 0x16

    invoke-direct {p2, v0, v1, p0}, Llyiahf/vczjk/o0OO000o;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/lt5;->OooOOO0:Llyiahf/vczjk/yp0;

    iget v1, v0, Llyiahf/vczjk/hc2;->OooOOOO:I

    new-instance v2, Llyiahf/vczjk/xp0;

    const/4 v3, 0x0

    invoke-direct {v2, p2, v3}, Llyiahf/vczjk/xp0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v0, p1, v1, v2}, Llyiahf/vczjk/yp0;->OooOoo(Ljava/lang/Object;ILlyiahf/vczjk/bf3;)V

    return-void
.end method

.method public final OooOOOo(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/lt5;->OooOOO0:Llyiahf/vczjk/yp0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yp0;->OooOOOo(Ljava/lang/Object;)V

    return-void
.end method

.method public final getContext()Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/lt5;->OooOOO0:Llyiahf/vczjk/yp0;

    iget-object v0, v0, Llyiahf/vczjk/yp0;->OooOOo0:Llyiahf/vczjk/or1;

    return-object v0
.end method

.method public final resumeWith(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/lt5;->OooOOO0:Llyiahf/vczjk/yp0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method
