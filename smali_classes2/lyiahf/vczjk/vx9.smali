.class public final Llyiahf/vczjk/vx9;
.super Llyiahf/vczjk/i88;
.source "SourceFile"


# static fields
.field public static final OooO0O0:Llyiahf/vczjk/vx9;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/vx9;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/vx9;->OooO0O0:Llyiahf/vczjk/vx9;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/h88;
    .locals 1

    new-instance v0, Llyiahf/vczjk/ux9;

    invoke-direct {v0}, Llyiahf/vczjk/ux9;-><init>()V

    return-object v0
.end method

.method public final OooO0O0(Ljava/lang/Runnable;)Llyiahf/vczjk/nc2;
    .locals 0

    invoke-interface {p1}, Ljava/lang/Runnable;->run()V

    sget-object p1, Llyiahf/vczjk/xm2;->OooOOO0:Llyiahf/vczjk/xm2;

    return-object p1
.end method

.method public final OooO0OO(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Llyiahf/vczjk/nc2;
    .locals 0

    :try_start_0
    invoke-virtual {p4, p2, p3}, Ljava/util/concurrent/TimeUnit;->sleep(J)V

    invoke-interface {p1}, Ljava/lang/Runnable;->run()V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/Thread;->interrupt()V

    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    :goto_0
    sget-object p1, Llyiahf/vczjk/xm2;->OooOOO0:Llyiahf/vczjk/xm2;

    return-object p1
.end method
