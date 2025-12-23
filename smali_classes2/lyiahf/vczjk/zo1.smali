.class public abstract Llyiahf/vczjk/zo1;
.super Llyiahf/vczjk/p70;
.source "SourceFile"


# instance fields
.field private final _context:Llyiahf/vczjk/or1;

.field private transient intercepted:Llyiahf/vczjk/yo1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/yo1<",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;)V
    .locals 1

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/or1;)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/or1;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/p70;-><init>(Llyiahf/vczjk/yo1;)V

    iput-object p2, p0, Llyiahf/vczjk/zo1;->_context:Llyiahf/vczjk/or1;

    return-void
.end method


# virtual methods
.method public getContext()Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zo1;->_context:Llyiahf/vczjk/or1;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object v0
.end method

.method public final intercepted()Llyiahf/vczjk/yo1;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Llyiahf/vczjk/yo1<",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation

    iget-object v0, p0, Llyiahf/vczjk/zo1;->intercepted:Llyiahf/vczjk/yo1;

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/zo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/vp3;->OooOOOO:Llyiahf/vczjk/vp3;

    invoke-interface {v0, v1}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ap1;

    if-eqz v0, :cond_0

    check-cast v0, Llyiahf/vczjk/qr1;

    new-instance v1, Llyiahf/vczjk/fc2;

    invoke-direct {v1, v0, p0}, Llyiahf/vczjk/fc2;-><init>(Llyiahf/vczjk/qr1;Llyiahf/vczjk/zo1;)V

    goto :goto_0

    :cond_0
    move-object v1, p0

    :goto_0
    iput-object v1, p0, Llyiahf/vczjk/zo1;->intercepted:Llyiahf/vczjk/yo1;

    return-object v1

    :cond_1
    return-object v0
.end method

.method public releaseIntercepted()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/zo1;->intercepted:Llyiahf/vczjk/yo1;

    if-eqz v0, :cond_2

    if-eq v0, p0, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/zo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/vp3;->OooOOOO:Llyiahf/vczjk/vp3;

    invoke-interface {v1, v2}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v1, Llyiahf/vczjk/ap1;

    check-cast v0, Llyiahf/vczjk/fc2;

    :cond_0
    sget-object v1, Llyiahf/vczjk/fc2;->OooOo00:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/dn8;->OooOOo:Llyiahf/vczjk/h87;

    if-eq v2, v3, :cond_0

    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/yp0;

    if-eqz v1, :cond_1

    check-cast v0, Llyiahf/vczjk/yp0;

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/yp0;->OooOOO()V

    :cond_2
    sget-object v0, Llyiahf/vczjk/i61;->OooOOO:Llyiahf/vczjk/i61;

    iput-object v0, p0, Llyiahf/vczjk/zo1;->intercepted:Llyiahf/vczjk/yo1;

    return-void
.end method
