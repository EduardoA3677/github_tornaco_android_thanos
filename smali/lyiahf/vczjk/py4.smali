.class public final Llyiahf/vczjk/py4;
.super Llyiahf/vczjk/ny4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sy4;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/or1;

.field public final OooOOO0:Llyiahf/vczjk/ky4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ky4;Llyiahf/vczjk/or1;)V
    .locals 1

    const-string v0, "coroutineContext"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/py4;->OooOOO0:Llyiahf/vczjk/ky4;

    iput-object p2, p0, Llyiahf/vczjk/py4;->OooOOO:Llyiahf/vczjk/or1;

    invoke-virtual {p1}, Llyiahf/vczjk/ky4;->OooO0O0()Llyiahf/vczjk/jy4;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/jy4;->OooOOO0:Llyiahf/vczjk/jy4;

    if-ne p1, v0, :cond_0

    const/4 p1, 0x0

    invoke-static {p2, p1}, Llyiahf/vczjk/zsa;->OooOoOO(Llyiahf/vczjk/or1;Ljava/util/concurrent/CancellationException;)V

    :cond_0
    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/uy4;Llyiahf/vczjk/iy4;)V
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/py4;->OooOOO0:Llyiahf/vczjk/ky4;

    invoke-virtual {p1}, Llyiahf/vczjk/ky4;->OooO0O0()Llyiahf/vczjk/jy4;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/jy4;->OooOOO0:Llyiahf/vczjk/jy4;

    invoke-virtual {p2, v0}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    move-result p2

    if-gtz p2, :cond_0

    invoke-virtual {p1, p0}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    const/4 p1, 0x0

    iget-object p2, p0, Llyiahf/vczjk/py4;->OooOOO:Llyiahf/vczjk/or1;

    invoke-static {p2, p1}, Llyiahf/vczjk/zsa;->OooOoOO(Llyiahf/vczjk/or1;Ljava/util/concurrent/CancellationException;)V

    :cond_0
    return-void
.end method

.method public final OoooOO0()Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/py4;->OooOOO:Llyiahf/vczjk/or1;

    return-object v0
.end method
