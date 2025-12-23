.class public final Llyiahf/vczjk/jx;
.super Llyiahf/vczjk/ls6;
.source "SourceFile"


# static fields
.field public static volatile OooO0Oo:Llyiahf/vczjk/jx;

.field public static final OooO0o0:Llyiahf/vczjk/ix;


# instance fields
.field public final OooO0OO:Llyiahf/vczjk/m42;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/ix;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/ix;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/jx;->OooO0o0:Llyiahf/vczjk/ix;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/m42;

    invoke-direct {v0}, Llyiahf/vczjk/m42;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/jx;->OooO0OO:Llyiahf/vczjk/m42;

    return-void
.end method

.method public static OooOo00()Llyiahf/vczjk/jx;
    .locals 2

    sget-object v0, Llyiahf/vczjk/jx;->OooO0Oo:Llyiahf/vczjk/jx;

    if-eqz v0, :cond_0

    sget-object v0, Llyiahf/vczjk/jx;->OooO0Oo:Llyiahf/vczjk/jx;

    return-object v0

    :cond_0
    const-class v0, Llyiahf/vczjk/jx;

    monitor-enter v0

    :try_start_0
    sget-object v1, Llyiahf/vczjk/jx;->OooO0Oo:Llyiahf/vczjk/jx;

    if-nez v1, :cond_1

    new-instance v1, Llyiahf/vczjk/jx;

    invoke-direct {v1}, Llyiahf/vczjk/jx;-><init>()V

    sput-object v1, Llyiahf/vczjk/jx;->OooO0Oo:Llyiahf/vczjk/jx;

    goto :goto_0

    :catchall_0
    move-exception v1

    goto :goto_1

    :cond_1
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    sget-object v0, Llyiahf/vczjk/jx;->OooO0Oo:Llyiahf/vczjk/jx;

    return-object v0

    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v1
.end method
