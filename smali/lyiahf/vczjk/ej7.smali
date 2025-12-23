.class public final Llyiahf/vczjk/ej7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/oj7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oj7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ej7;->this$0:Llyiahf/vczjk/oj7;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Ljava/lang/Throwable;

    const-string v0, "Recomposer effect job completed"

    new-instance v1, Ljava/util/concurrent/CancellationException;

    invoke-direct {v1, v0}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    iget-object v0, p0, Llyiahf/vczjk/ej7;->this$0:Llyiahf/vczjk/oj7;

    iget-object v2, v0, Llyiahf/vczjk/oj7;->OooO0O0:Ljava/lang/Object;

    monitor-enter v2

    :try_start_0
    iget-object v3, v0, Llyiahf/vczjk/oj7;->OooO0OO:Llyiahf/vczjk/v74;

    const/4 v4, 0x0

    if-eqz v3, :cond_0

    iget-object v5, v0, Llyiahf/vczjk/oj7;->OooOo00:Llyiahf/vczjk/s29;

    sget-object v6, Llyiahf/vczjk/bj7;->OooOOO:Llyiahf/vczjk/bj7;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v5, v4, v6}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    sget-object v5, Llyiahf/vczjk/oj7;->OooOo:Llyiahf/vczjk/s29;

    invoke-interface {v3, v1}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    iput-object v4, v0, Llyiahf/vczjk/oj7;->OooOOo0:Llyiahf/vczjk/yp0;

    new-instance v1, Llyiahf/vczjk/dj7;

    invoke-direct {v1, v0, p1}, Llyiahf/vczjk/dj7;-><init>(Llyiahf/vczjk/oj7;Ljava/lang/Throwable;)V

    invoke-interface {v3, v1}, Llyiahf/vczjk/v74;->OoooO00(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/sc2;

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    iput-object v1, v0, Llyiahf/vczjk/oj7;->OooO0Oo:Ljava/lang/Throwable;

    iget-object p1, v0, Llyiahf/vczjk/oj7;->OooOo00:Llyiahf/vczjk/s29;

    sget-object v0, Llyiahf/vczjk/bj7;->OooOOO0:Llyiahf/vczjk/bj7;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1, v4, v0}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :goto_0
    monitor-exit v2

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :goto_1
    monitor-exit v2

    throw p1
.end method
