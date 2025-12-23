.class public final Llyiahf/vczjk/mq8;
.super Ljava/util/concurrent/atomic/AtomicReference;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/tp8;


# static fields
.field private static final serialVersionUID:J = 0x1cbf0c2cc84a0325L


# instance fields
.field final downstream:Llyiahf/vczjk/tp8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/tp8;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tp8;)V
    .locals 0

    invoke-direct {p0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/mq8;->downstream:Llyiahf/vczjk/tp8;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tc2;->OooO0Oo(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void
.end method

.method public final OooO0OO(Ljava/lang/Throwable;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mq8;->downstream:Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0OO(Ljava/lang/Throwable;)V

    return-void
.end method

.method public final OooO0o0(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mq8;->downstream:Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0o0(Ljava/lang/Object;)V

    return-void
.end method
