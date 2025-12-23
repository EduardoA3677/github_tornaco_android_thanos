.class public final Llyiahf/vczjk/dh1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/no7;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/xr1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/dh1;->OooOOO0:Llyiahf/vczjk/xr1;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/dh1;->OooOOO0:Llyiahf/vczjk/xr1;

    instance-of v1, v0, Llyiahf/vczjk/to7;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/to7;

    invoke-virtual {v0}, Llyiahf/vczjk/to7;->OooO0Oo()V

    return-void

    :cond_0
    new-instance v1, Llyiahf/vczjk/tb3;

    const/4 v2, 0x1

    invoke-direct {v1, v2}, Llyiahf/vczjk/tb3;-><init>(I)V

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo0(Llyiahf/vczjk/xr1;Ljava/util/concurrent/CancellationException;)V

    return-void
.end method

.method public final OooO0O0()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/dh1;->OooOOO0:Llyiahf/vczjk/xr1;

    instance-of v1, v0, Llyiahf/vczjk/to7;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/to7;

    invoke-virtual {v0}, Llyiahf/vczjk/to7;->OooO0Oo()V

    return-void

    :cond_0
    new-instance v1, Llyiahf/vczjk/tb3;

    const/4 v2, 0x1

    invoke-direct {v1, v2}, Llyiahf/vczjk/tb3;-><init>(I)V

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo0(Llyiahf/vczjk/xr1;Ljava/util/concurrent/CancellationException;)V

    return-void
.end method

.method public final OooO0OO()V
    .locals 0

    return-void
.end method
