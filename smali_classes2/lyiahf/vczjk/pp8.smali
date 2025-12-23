.class public final Llyiahf/vczjk/pp8;
.super Ljava/util/concurrent/atomic/AtomicReference;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/j86;
.implements Llyiahf/vczjk/tp8;
.implements Llyiahf/vczjk/nc2;


# static fields
.field private static final serialVersionUID:J = -0x7c2e9f0a46fa84b0L


# instance fields
.field final downstream:Llyiahf/vczjk/j86;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/j86;"
        }
    .end annotation
.end field

.field final mapper:Llyiahf/vczjk/af3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/af3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/j86;Llyiahf/vczjk/af3;)V
    .locals 0

    invoke-direct {p0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/pp8;->downstream:Llyiahf/vczjk/j86;

    iput-object p2, p0, Llyiahf/vczjk/pp8;->mapper:Llyiahf/vczjk/af3;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 0

    invoke-static {p0}, Llyiahf/vczjk/tc2;->OooO0O0(Ljava/util/concurrent/atomic/AtomicReference;)V

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tc2;->OooO0OO(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void
.end method

.method public final OooO0OO(Ljava/lang/Throwable;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pp8;->downstream:Llyiahf/vczjk/j86;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooO0OO(Ljava/lang/Throwable;)V

    return-void
.end method

.method public final OooO0Oo()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pp8;->downstream:Llyiahf/vczjk/j86;

    invoke-interface {v0}, Llyiahf/vczjk/j86;->OooO0Oo()V

    return-void
.end method

.method public final OooO0o0(Ljava/lang/Object;)V
    .locals 1

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/pp8;->mapper:Llyiahf/vczjk/af3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/af3;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    const-string v0, "The mapper returned a null Publisher"

    invoke-static {p1, v0}, Llyiahf/vczjk/nqa;->Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/o76;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p1, p0}, Llyiahf/vczjk/o76;->OooO0Oo(Llyiahf/vczjk/j86;)V

    return-void

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    iget-object v0, p0, Llyiahf/vczjk/pp8;->downstream:Llyiahf/vczjk/j86;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooO0OO(Ljava/lang/Throwable;)V

    return-void
.end method

.method public final OooOO0O(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pp8;->downstream:Llyiahf/vczjk/j86;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooOO0O(Ljava/lang/Object;)V

    return-void
.end method
