.class public final Llyiahf/vczjk/cj7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/oj7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oj7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cj7;->this$0:Llyiahf/vczjk/oj7;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/cj7;->this$0:Llyiahf/vczjk/oj7;

    iget-object v1, v0, Llyiahf/vczjk/oj7;->OooO0O0:Ljava/lang/Object;

    monitor-enter v1

    :try_start_0
    invoke-virtual {v0}, Llyiahf/vczjk/oj7;->OooOo0()Llyiahf/vczjk/wp0;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/oj7;->OooOo00:Llyiahf/vczjk/s29;

    invoke-virtual {v3}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/bj7;

    sget-object v4, Llyiahf/vczjk/bj7;->OooOOO:Llyiahf/vczjk/bj7;

    invoke-virtual {v3, v4}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    move-result v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-lez v3, :cond_1

    monitor-exit v1

    if-eqz v2, :cond_0

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    check-cast v2, Llyiahf/vczjk/yp0;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    :cond_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :cond_1
    :try_start_1
    const-string v2, "Recomposer shutdown; frame clock awaiter will never resume"

    iget-object v0, v0, Llyiahf/vczjk/oj7;->OooO0Oo:Ljava/lang/Throwable;

    new-instance v3, Ljava/util/concurrent/CancellationException;

    invoke-direct {v3, v2}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v0}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    throw v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :catchall_0
    move-exception v0

    monitor-exit v1

    throw v0
.end method
