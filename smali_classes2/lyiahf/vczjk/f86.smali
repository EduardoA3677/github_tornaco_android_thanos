.class public final Llyiahf/vczjk/f86;
.super Ljava/util/concurrent/atomic/AtomicReference;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/j86;
.implements Llyiahf/vczjk/nc2;


# static fields
.field private static final serialVersionUID:J = 0x70559c6a66be0138L


# instance fields
.field final downstream:Llyiahf/vczjk/j86;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/j86;"
        }
    .end annotation
.end field

.field final upstream:Ljava/util/concurrent/atomic/AtomicReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicReference<",
            "Llyiahf/vczjk/nc2;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/j86;)V
    .locals 0

    invoke-direct {p0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/f86;->downstream:Llyiahf/vczjk/j86;

    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-direct {p1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/f86;->upstream:Ljava/util/concurrent/atomic/AtomicReference;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f86;->upstream:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-static {v0}, Llyiahf/vczjk/tc2;->OooO0O0(Ljava/util/concurrent/atomic/AtomicReference;)V

    invoke-static {p0}, Llyiahf/vczjk/tc2;->OooO0O0(Ljava/util/concurrent/atomic/AtomicReference;)V

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f86;->upstream:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-static {v0, p1}, Llyiahf/vczjk/tc2;->OooO0Oo(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void
.end method

.method public final OooO0OO(Ljava/lang/Throwable;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f86;->downstream:Llyiahf/vczjk/j86;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooO0OO(Ljava/lang/Throwable;)V

    return-void
.end method

.method public final OooO0Oo()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f86;->downstream:Llyiahf/vczjk/j86;

    invoke-interface {v0}, Llyiahf/vczjk/j86;->OooO0Oo()V

    return-void
.end method

.method public final OooOO0O(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f86;->downstream:Llyiahf/vczjk/j86;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooOO0O(Ljava/lang/Object;)V

    return-void
.end method
