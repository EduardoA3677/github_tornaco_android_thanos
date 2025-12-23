.class public final Llyiahf/vczjk/uv8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $block:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/uv8;->$block:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/rv8;

    iget-object v0, p0, Llyiahf/vczjk/uv8;->$block:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/nv8;

    sget-object v0, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    sget-object v1, Llyiahf/vczjk/vv8;->OooO0OO:Llyiahf/vczjk/rv8;

    invoke-virtual {p1}, Llyiahf/vczjk/nv8;->OooO0oO()J

    move-result-wide v2

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/rv8;->OooO(J)Llyiahf/vczjk/rv8;

    move-result-object v1

    sput-object v1, Llyiahf/vczjk/vv8;->OooO0OO:Llyiahf/vczjk/rv8;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    return-object p1

    :catchall_0
    move-exception p1

    monitor-exit v0

    throw p1
.end method
