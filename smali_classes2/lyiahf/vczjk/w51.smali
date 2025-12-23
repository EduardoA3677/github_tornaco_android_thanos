.class public final Llyiahf/vczjk/w51;
.super Ljava/util/concurrent/atomic/AtomicReference;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/d61;
.implements Ljava/lang/Runnable;
.implements Llyiahf/vczjk/nc2;


# static fields
.field private static final serialVersionUID:J = 0x67777c1e4b8e28eL


# instance fields
.field final delay:J

.field final delayError:Z

.field final downstream:Llyiahf/vczjk/d61;

.field error:Ljava/lang/Throwable;

.field final scheduler:Llyiahf/vczjk/i88;

.field final unit:Ljava/util/concurrent/TimeUnit;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/d61;JLlyiahf/vczjk/i88;)V
    .locals 1

    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-direct {p0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/w51;->downstream:Llyiahf/vczjk/d61;

    iput-wide p2, p0, Llyiahf/vczjk/w51;->delay:J

    iput-object v0, p0, Llyiahf/vczjk/w51;->unit:Ljava/util/concurrent/TimeUnit;

    iput-object p4, p0, Llyiahf/vczjk/w51;->scheduler:Llyiahf/vczjk/i88;

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/w51;->delayError:Z

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

    iget-object p1, p0, Llyiahf/vczjk/w51;->downstream:Llyiahf/vczjk/d61;

    invoke-interface {p1, p0}, Llyiahf/vczjk/d61;->OooO0O0(Llyiahf/vczjk/nc2;)V

    :cond_0
    return-void
.end method

.method public final OooO0OO(Ljava/lang/Throwable;)V
    .locals 3

    iput-object p1, p0, Llyiahf/vczjk/w51;->error:Ljava/lang/Throwable;

    iget-object p1, p0, Llyiahf/vczjk/w51;->scheduler:Llyiahf/vczjk/i88;

    iget-boolean v0, p0, Llyiahf/vczjk/w51;->delayError:Z

    if-eqz v0, :cond_0

    iget-wide v0, p0, Llyiahf/vczjk/w51;->delay:J

    goto :goto_0

    :cond_0
    const-wide/16 v0, 0x0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/w51;->unit:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {p1, p0, v0, v1, v2}, Llyiahf/vczjk/i88;->OooO0OO(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Llyiahf/vczjk/nc2;

    move-result-object p1

    invoke-static {p0, p1}, Llyiahf/vczjk/tc2;->OooO0OO(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void
.end method

.method public final OooO0Oo()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/w51;->scheduler:Llyiahf/vczjk/i88;

    iget-wide v1, p0, Llyiahf/vczjk/w51;->delay:J

    iget-object v3, p0, Llyiahf/vczjk/w51;->unit:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {v0, p0, v1, v2, v3}, Llyiahf/vczjk/i88;->OooO0OO(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Llyiahf/vczjk/nc2;

    move-result-object v0

    invoke-static {p0, v0}, Llyiahf/vczjk/tc2;->OooO0OO(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void
.end method

.method public final run()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/w51;->error:Ljava/lang/Throwable;

    const/4 v1, 0x0

    iput-object v1, p0, Llyiahf/vczjk/w51;->error:Ljava/lang/Throwable;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/w51;->downstream:Llyiahf/vczjk/d61;

    invoke-interface {v1, v0}, Llyiahf/vczjk/d61;->OooO0OO(Ljava/lang/Throwable;)V

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/w51;->downstream:Llyiahf/vczjk/d61;

    invoke-interface {v0}, Llyiahf/vczjk/d61;->OooO0Oo()V

    return-void
.end method
