.class public final Llyiahf/vczjk/um2;
.super Ljava/util/concurrent/atomic/AtomicReference;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/d61;
.implements Llyiahf/vczjk/nc2;


# static fields
.field private static final serialVersionUID:J = -0x68b5a82715a81b26L


# virtual methods
.method public final OooO00o()V
    .locals 0

    invoke-static {p0}, Llyiahf/vczjk/tc2;->OooO0O0(Ljava/util/concurrent/atomic/AtomicReference;)V

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tc2;->OooO0Oo(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void
.end method

.method public final OooO0OO(Ljava/lang/Throwable;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    invoke-virtual {p0, v0}, Ljava/util/concurrent/atomic/AtomicReference;->lazySet(Ljava/lang/Object;)V

    new-instance v0, Llyiahf/vczjk/ta6;

    invoke-direct {v0, p1}, Llyiahf/vczjk/ta6;-><init>(Ljava/lang/Throwable;)V

    invoke-static {v0}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    return-void
.end method

.method public final OooO0Oo()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    invoke-virtual {p0, v0}, Ljava/util/concurrent/atomic/AtomicReference;->lazySet(Ljava/lang/Object;)V

    return-void
.end method
