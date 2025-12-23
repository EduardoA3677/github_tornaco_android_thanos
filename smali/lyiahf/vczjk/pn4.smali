.class public final Llyiahf/vczjk/pn4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/no7;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/to1;

.field public final OooOOO0:Llyiahf/vczjk/ze3;

.field public OooOOOO:Llyiahf/vczjk/r09;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/pn4;->OooOOO0:Llyiahf/vczjk/ze3;

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/pn4;->OooOOO:Llyiahf/vczjk/to1;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/pn4;->OooOOOO:Llyiahf/vczjk/r09;

    if-eqz v0, :cond_0

    new-instance v1, Llyiahf/vczjk/tb3;

    const/4 v2, 0x1

    invoke-direct {v1, v2}, Llyiahf/vczjk/tb3;-><init>(I)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/k84;->OooOOoo(Ljava/util/concurrent/CancellationException;)V

    :cond_0
    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/pn4;->OooOOOO:Llyiahf/vczjk/r09;

    return-void
.end method

.method public final OooO0O0()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/pn4;->OooOOOO:Llyiahf/vczjk/r09;

    if-eqz v0, :cond_0

    new-instance v1, Llyiahf/vczjk/tb3;

    const/4 v2, 0x1

    invoke-direct {v1, v2}, Llyiahf/vczjk/tb3;-><init>(I)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/k84;->OooOOoo(Ljava/util/concurrent/CancellationException;)V

    :cond_0
    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/pn4;->OooOOOO:Llyiahf/vczjk/r09;

    return-void
.end method

.method public final OooO0OO()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/pn4;->OooOOOO:Llyiahf/vczjk/r09;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    new-instance v2, Ljava/util/concurrent/CancellationException;

    const-string v3, "Old job was still running!"

    invoke-direct {v2, v3}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v1}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/k84;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_0
    const/4 v0, 0x3

    iget-object v2, p0, Llyiahf/vczjk/pn4;->OooOOO0:Llyiahf/vczjk/ze3;

    iget-object v3, p0, Llyiahf/vczjk/pn4;->OooOOO:Llyiahf/vczjk/to1;

    invoke-static {v3, v1, v1, v2, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/pn4;->OooOOOO:Llyiahf/vczjk/r09;

    return-void
.end method
