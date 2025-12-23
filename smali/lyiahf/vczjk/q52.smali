.class public final Llyiahf/vczjk/q52;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/dx8;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/tl9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tl9;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/q52;->OooO00o:Llyiahf/vczjk/tl9;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q52;->OooO00o:Llyiahf/vczjk/tl9;

    iget-object v0, v0, Llyiahf/vczjk/tl9;->OooO00o:Llyiahf/vczjk/tx6;

    invoke-interface {v0}, Llyiahf/vczjk/tx6;->OooO0oO()V

    return-void
.end method

.method public final OooO0O0()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/q52;->OooO00o:Llyiahf/vczjk/tl9;

    iget-object v1, v0, Llyiahf/vczjk/tl9;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/yl9;

    if-eqz v1, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/tl9;->OooO00o:Llyiahf/vczjk/tx6;

    invoke-interface {v0}, Llyiahf/vczjk/tx6;->OooO0Oo()V

    :cond_0
    return-void
.end method
