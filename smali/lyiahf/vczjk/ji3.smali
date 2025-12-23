.class public final Llyiahf/vczjk/ji3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $actualReadObserver:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $actualWriteObserver:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ji3;->$actualReadObserver:Llyiahf/vczjk/oe3;

    iput-object p2, p0, Llyiahf/vczjk/ji3;->$actualWriteObserver:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/rv8;

    sget-object p1, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter p1

    :try_start_0
    sget-wide v1, Llyiahf/vczjk/vv8;->OooO0Oo:J

    const-wide/16 v4, 0x1

    add-long/2addr v4, v1

    sput-wide v4, Llyiahf/vczjk/vv8;->OooO0Oo:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p1

    iget-object v4, p0, Llyiahf/vczjk/ji3;->$actualReadObserver:Llyiahf/vczjk/oe3;

    iget-object v5, p0, Llyiahf/vczjk/ji3;->$actualWriteObserver:Llyiahf/vczjk/oe3;

    new-instance v0, Llyiahf/vczjk/ps5;

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/ps5;-><init>(JLlyiahf/vczjk/rv8;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    return-object v0

    :catchall_0
    move-exception v0

    monitor-exit p1

    throw v0
.end method
