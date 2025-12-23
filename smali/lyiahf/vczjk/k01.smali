.class public final Llyiahf/vczjk/k01;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/AutoCloseable;
.implements Llyiahf/vczjk/xr1;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/or1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/or1;)V
    .locals 1

    const-string v0, "coroutineContext"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/k01;->OooOOO0:Llyiahf/vczjk/or1;

    return-void
.end method


# virtual methods
.method public final OoooOO0()Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/k01;->OooOOO0:Llyiahf/vczjk/or1;

    return-object v0
.end method

.method public final close()V
    .locals 2

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/k01;->OooOOO0:Llyiahf/vczjk/or1;

    invoke-static {v1, v0}, Llyiahf/vczjk/zsa;->OooOoOO(Llyiahf/vczjk/or1;Ljava/util/concurrent/CancellationException;)V

    return-void
.end method
