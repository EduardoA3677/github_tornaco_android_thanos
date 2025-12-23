.class public final Llyiahf/vczjk/kq8;
.super Ljava/util/concurrent/atomic/AtomicReference;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/tp8;
.implements Llyiahf/vczjk/nc2;
.implements Ljava/lang/Runnable;


# static fields
.field private static final serialVersionUID:J = 0x61283b9e254a3eafL


# instance fields
.field final downstream:Llyiahf/vczjk/tp8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/tp8;"
        }
    .end annotation
.end field

.field final source:Llyiahf/vczjk/jq8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/jq8;"
        }
    .end annotation
.end field

.field final task:Llyiahf/vczjk/eg8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tp8;Llyiahf/vczjk/jp8;)V
    .locals 0

    invoke-direct {p0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/kq8;->downstream:Llyiahf/vczjk/tp8;

    iput-object p2, p0, Llyiahf/vczjk/kq8;->source:Llyiahf/vczjk/jq8;

    new-instance p1, Llyiahf/vczjk/eg8;

    invoke-direct {p1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/kq8;->task:Llyiahf/vczjk/eg8;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    invoke-static {p0}, Llyiahf/vczjk/tc2;->OooO0O0(Ljava/util/concurrent/atomic/AtomicReference;)V

    iget-object v0, p0, Llyiahf/vczjk/kq8;->task:Llyiahf/vczjk/eg8;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/tc2;->OooO0O0(Ljava/util/concurrent/atomic/AtomicReference;)V

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tc2;->OooO0Oo(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void
.end method

.method public final OooO0OO(Ljava/lang/Throwable;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kq8;->downstream:Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0OO(Ljava/lang/Throwable;)V

    return-void
.end method

.method public final OooO0o0(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kq8;->downstream:Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0o0(Ljava/lang/Object;)V

    return-void
.end method

.method public final run()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kq8;->source:Llyiahf/vczjk/jq8;

    invoke-interface {v0, p0}, Llyiahf/vczjk/jq8;->OooO0Oo(Llyiahf/vczjk/tp8;)V

    return-void
.end method
