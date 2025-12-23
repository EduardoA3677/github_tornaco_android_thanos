.class public final Llyiahf/vczjk/ura;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $isTracingEnabled:Z

.field final synthetic $traceTag:Ljava/lang/String;

.field final synthetic $worker:Llyiahf/vczjk/b25;

.field final synthetic this$0:Llyiahf/vczjk/wra;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/b25;ZLjava/lang/String;Llyiahf/vczjk/wra;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ura;->$worker:Llyiahf/vczjk/b25;

    iput-boolean p2, p0, Llyiahf/vczjk/ura;->$isTracingEnabled:Z

    iput-object p3, p0, Llyiahf/vczjk/ura;->$traceTag:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/ura;->this$0:Llyiahf/vczjk/wra;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Ljava/lang/Throwable;

    instance-of v0, p1, Llyiahf/vczjk/lra;

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ura;->$worker:Llyiahf/vczjk/b25;

    check-cast p1, Llyiahf/vczjk/lra;

    invoke-virtual {p1}, Llyiahf/vczjk/lra;->OooO00o()I

    move-result p1

    iget-object v0, v0, Llyiahf/vczjk/b25;->OooO0OO:Ljava/util/concurrent/atomic/AtomicInteger;

    const/16 v1, -0x100

    invoke-virtual {v0, v1, p1}, Ljava/util/concurrent/atomic/AtomicInteger;->compareAndSet(II)Z

    :cond_0
    iget-boolean p1, p0, Llyiahf/vczjk/ura;->$isTracingEnabled:Z

    if-eqz p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/ura;->$traceTag:Ljava/lang/String;

    if-eqz p1, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/ura;->this$0:Llyiahf/vczjk/wra;

    iget-object v1, v0, Llyiahf/vczjk/wra;->OooO0o0:Llyiahf/vczjk/wh1;

    iget-object v0, v0, Llyiahf/vczjk/wra;->OooO00o:Llyiahf/vczjk/ara;

    invoke-virtual {v0}, Llyiahf/vczjk/ara;->hashCode()I

    move-result v0

    iget-object v1, v1, Llyiahf/vczjk/wh1;->OooOOO0:Llyiahf/vczjk/e86;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v2, 0x1d

    if-lt v1, v2, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/ll6;->OooOOo0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/ox9;->OooO0O0(ILjava/lang/String;)V

    goto :goto_2

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/ll6;->OooOOo0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    const-string v1, "asyncTraceEnd"

    :try_start_0
    sget-object v2, Llyiahf/vczjk/ll6;->OooO0oO:Ljava/lang/reflect/Method;

    if-nez v2, :cond_2

    const-class v2, Landroid/os/Trace;

    sget-object v3, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    const-class v4, Ljava/lang/String;

    sget-object v5, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    filled-new-array {v3, v4, v5}, [Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v2, v1, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v2

    sput-object v2, Llyiahf/vczjk/ll6;->OooO0oO:Ljava/lang/reflect/Method;

    goto :goto_0

    :catch_0
    move-exception p1

    goto :goto_1

    :cond_2
    :goto_0
    sget-object v2, Llyiahf/vczjk/ll6;->OooO0oO:Ljava/lang/reflect/Method;

    sget-wide v3, Llyiahf/vczjk/ll6;->OooO0Oo:J

    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v3

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    filled-new-array {v3, p1, v0}, [Ljava/lang/Object;

    move-result-object p1

    const/4 v0, 0x0

    invoke-virtual {v2, v0, p1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_2

    :goto_1
    invoke-static {v1, p1}, Llyiahf/vczjk/ll6;->OooO0oO(Ljava/lang/String;Ljava/lang/Exception;)V

    :cond_3
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
