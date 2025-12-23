.class public final Llyiahf/vczjk/ic2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/concurrent/Executor;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/qr1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qr1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ic2;->OooOOO0:Llyiahf/vczjk/qr1;

    return-void
.end method


# virtual methods
.method public final execute(Ljava/lang/Runnable;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    iget-object v1, p0, Llyiahf/vczjk/ic2;->OooOOO0:Llyiahf/vczjk/qr1;

    invoke-static {v1, v0}, Llyiahf/vczjk/dn8;->o0ooOOo(Llyiahf/vczjk/qr1;Llyiahf/vczjk/or1;)Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-static {v1, v0, p1}, Llyiahf/vczjk/dn8;->o0ooOO0(Llyiahf/vczjk/qr1;Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    return-void

    :cond_0
    invoke-interface {p1}, Ljava/lang/Runnable;->run()V

    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ic2;->OooOOO0:Llyiahf/vczjk/qr1;

    invoke-virtual {v0}, Llyiahf/vczjk/qr1;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
