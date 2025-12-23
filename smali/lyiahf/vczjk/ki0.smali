.class public final Llyiahf/vczjk/ki0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $awaiter:Llyiahf/vczjk/ji0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ji0;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/li0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/li0;Llyiahf/vczjk/ji0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ki0;->this$0:Llyiahf/vczjk/li0;

    iput-object p2, p0, Llyiahf/vczjk/ki0;->$awaiter:Llyiahf/vczjk/ji0;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Ljava/lang/Throwable;

    iget-object p1, p0, Llyiahf/vczjk/ki0;->this$0:Llyiahf/vczjk/li0;

    iget-object v0, p1, Llyiahf/vczjk/li0;->OooOOO:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/ki0;->$awaiter:Llyiahf/vczjk/ji0;

    monitor-enter v0

    :try_start_0
    iget-object v2, p1, Llyiahf/vczjk/li0;->OooOOOo:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    iget-object v1, p1, Llyiahf/vczjk/li0;->OooOOOo:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/li0;->OooOOo:Llyiahf/vczjk/g10;

    const/4 v1, 0x0

    invoke-virtual {p1, v1}, Ljava/util/concurrent/atomic/AtomicInteger;->set(I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit v0

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :goto_1
    monitor-exit v0

    throw p1
.end method
