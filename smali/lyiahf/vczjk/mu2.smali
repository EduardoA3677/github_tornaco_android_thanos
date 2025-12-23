.class public final Llyiahf/vczjk/mu2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/uma;


# virtual methods
.method public final OooO00o(Landroid/content/Context;Ljava/util/concurrent/Executor;Llyiahf/vczjk/ol1;)V
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/oO0O00o0;

    const/16 v0, 0x19

    invoke-direct {p1, p3, v0}, Llyiahf/vczjk/oO0O00o0;-><init>(Ljava/lang/Object;I)V

    invoke-interface {p2, p1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/ol1;)V
    .locals 1

    const-string v0, "callback"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method
