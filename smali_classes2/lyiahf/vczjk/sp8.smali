.class public final Llyiahf/vczjk/sp8;
.super Ljava/util/concurrent/atomic/AtomicReference;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/tp8;
.implements Llyiahf/vczjk/nc2;
.implements Ljava/lang/Runnable;


# static fields
.field private static final serialVersionUID:J = 0x30f5fcccee5fcf85L


# instance fields
.field final downstream:Llyiahf/vczjk/tp8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/tp8;"
        }
    .end annotation
.end field

.field error:Ljava/lang/Throwable;

.field final scheduler:Llyiahf/vczjk/i88;

.field value:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tp8;Llyiahf/vczjk/i88;)V
    .locals 0

    invoke-direct {p0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/sp8;->downstream:Llyiahf/vczjk/tp8;

    iput-object p2, p0, Llyiahf/vczjk/sp8;->scheduler:Llyiahf/vczjk/i88;

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

    invoke-static {p0, p1}, Llyiahf/vczjk/tc2;->OooO0Oo(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/sp8;->downstream:Llyiahf/vczjk/tp8;

    invoke-interface {p1, p0}, Llyiahf/vczjk/tp8;->OooO0O0(Llyiahf/vczjk/nc2;)V

    :cond_0
    return-void
.end method

.method public final OooO0OO(Ljava/lang/Throwable;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sp8;->error:Ljava/lang/Throwable;

    iget-object p1, p0, Llyiahf/vczjk/sp8;->scheduler:Llyiahf/vczjk/i88;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/i88;->OooO0O0(Ljava/lang/Runnable;)Llyiahf/vczjk/nc2;

    move-result-object p1

    invoke-static {p0, p1}, Llyiahf/vczjk/tc2;->OooO0OO(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void
.end method

.method public final OooO0o0(Ljava/lang/Object;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sp8;->value:Ljava/lang/Object;

    iget-object p1, p0, Llyiahf/vczjk/sp8;->scheduler:Llyiahf/vczjk/i88;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/i88;->OooO0O0(Ljava/lang/Runnable;)Llyiahf/vczjk/nc2;

    move-result-object p1

    invoke-static {p0, p1}, Llyiahf/vczjk/tc2;->OooO0OO(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void
.end method

.method public final run()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/sp8;->error:Ljava/lang/Throwable;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/sp8;->downstream:Llyiahf/vczjk/tp8;

    invoke-interface {v1, v0}, Llyiahf/vczjk/tp8;->OooO0OO(Ljava/lang/Throwable;)V

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/sp8;->downstream:Llyiahf/vczjk/tp8;

    iget-object v1, p0, Llyiahf/vczjk/sp8;->value:Ljava/lang/Object;

    invoke-interface {v0, v1}, Llyiahf/vczjk/tp8;->OooO0o0(Ljava/lang/Object;)V

    return-void
.end method
