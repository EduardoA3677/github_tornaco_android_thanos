.class public final Llyiahf/vczjk/bn4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $co:Llyiahf/vczjk/wp0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/wp0;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/cn4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cn4;Llyiahf/vczjk/yp0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bn4;->this$0:Llyiahf/vczjk/cn4;

    iput-object p2, p0, Llyiahf/vczjk/bn4;->$co:Llyiahf/vczjk/wp0;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Ljava/lang/Throwable;

    iget-object p1, p0, Llyiahf/vczjk/bn4;->this$0:Llyiahf/vczjk/cn4;

    iget-object v0, p1, Llyiahf/vczjk/cn4;->OooO00o:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/bn4;->$co:Llyiahf/vczjk/wp0;

    monitor-enter v0

    :try_start_0
    iget-object p1, p1, Llyiahf/vczjk/cn4;->OooO0O0:Ljava/util/ArrayList;

    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :catchall_0
    move-exception p1

    monitor-exit v0

    throw p1
.end method
