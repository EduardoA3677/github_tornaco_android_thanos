.class public final Llyiahf/vczjk/fc2;
.super Llyiahf/vczjk/hc2;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/zr1;
.implements Llyiahf/vczjk/yo1;


# static fields
.field public static final synthetic OooOo00:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;


# instance fields
.field public final OooOOOo:Llyiahf/vczjk/qr1;

.field public OooOOo:Ljava/lang/Object;

.field public final OooOOo0:Llyiahf/vczjk/zo1;

.field public final OooOOoo:Ljava/lang/Object;

.field private volatile synthetic _reusableCancellableContinuation$volatile:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const-class v0, Ljava/lang/Object;

    const-string v1, "_reusableCancellableContinuation$volatile"

    const-class v2, Llyiahf/vczjk/fc2;

    invoke-static {v2, v0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/fc2;->OooOo00:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/qr1;Llyiahf/vczjk/zo1;)V
    .locals 1

    const/4 v0, -0x1

    invoke-direct {p0, v0}, Llyiahf/vczjk/hc2;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/fc2;->OooOOOo:Llyiahf/vczjk/qr1;

    iput-object p2, p0, Llyiahf/vczjk/fc2;->OooOOo0:Llyiahf/vczjk/zo1;

    sget-object p1, Llyiahf/vczjk/dn8;->OooOOo0:Llyiahf/vczjk/h87;

    iput-object p1, p0, Llyiahf/vczjk/fc2;->OooOOo:Ljava/lang/Object;

    invoke-interface {p2}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/jp8;->OoooOo0(Llyiahf/vczjk/or1;)Ljava/lang/Object;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/fc2;->OooOOoo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO0OO()Llyiahf/vczjk/yo1;
    .locals 0

    return-object p0
.end method

.method public final OooO0oO()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/fc2;->OooOOo:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/dn8;->OooOOo0:Llyiahf/vczjk/h87;

    iput-object v1, p0, Llyiahf/vczjk/fc2;->OooOOo:Ljava/lang/Object;

    return-object v0
.end method

.method public final getCallerFrame()Llyiahf/vczjk/zr1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fc2;->OooOOo0:Llyiahf/vczjk/zo1;

    return-object v0
.end method

.method public final getContext()Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fc2;->OooOOo0:Llyiahf/vczjk/zo1;

    invoke-interface {v0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v0

    return-object v0
.end method

.method public final resumeWith(Ljava/lang/Object;)V
    .locals 8

    invoke-static {p1}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    move-object v2, p1

    goto :goto_0

    :cond_0
    new-instance v2, Llyiahf/vczjk/j61;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/j61;-><init>(Ljava/lang/Throwable;Z)V

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/fc2;->OooOOo0:Llyiahf/vczjk/zo1;

    invoke-interface {v0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v3

    iget-object v4, p0, Llyiahf/vczjk/fc2;->OooOOOo:Llyiahf/vczjk/qr1;

    invoke-static {v4, v3}, Llyiahf/vczjk/dn8;->o0ooOOo(Llyiahf/vczjk/qr1;Llyiahf/vczjk/or1;)Z

    move-result v3

    if-eqz v3, :cond_1

    iput-object v2, p0, Llyiahf/vczjk/fc2;->OooOOo:Ljava/lang/Object;

    iput v1, p0, Llyiahf/vczjk/hc2;->OooOOOO:I

    invoke-interface {v0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object p1

    invoke-static {v4, p1, p0}, Llyiahf/vczjk/dn8;->o0ooOO0(Llyiahf/vczjk/qr1;Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    return-void

    :cond_1
    invoke-static {}, Llyiahf/vczjk/vq9;->OooO00o()Llyiahf/vczjk/pr2;

    move-result-object v3

    iget-wide v4, v3, Llyiahf/vczjk/pr2;->OooOOOO:J

    const-wide v6, 0x100000000L

    cmp-long v4, v4, v6

    if-ltz v4, :cond_2

    iput-object v2, p0, Llyiahf/vczjk/fc2;->OooOOo:Ljava/lang/Object;

    iput v1, p0, Llyiahf/vczjk/hc2;->OooOOOO:I

    invoke-virtual {v3, p0}, Llyiahf/vczjk/pr2;->o0000O00(Llyiahf/vczjk/hc2;)V

    return-void

    :cond_2
    const/4 v1, 0x1

    invoke-virtual {v3, v1}, Llyiahf/vczjk/pr2;->o0000oO(Z)V

    :try_start_0
    invoke-interface {v0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v2

    iget-object v4, p0, Llyiahf/vczjk/fc2;->OooOOoo:Ljava/lang/Object;

    invoke-static {v2, v4}, Llyiahf/vczjk/jp8;->OooooO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :try_start_1
    invoke-interface {v0, p1}, Llyiahf/vczjk/yo1;->resumeWith(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :try_start_2
    invoke-static {v2, v4}, Llyiahf/vczjk/jp8;->OoooOO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)V

    :cond_3
    invoke-virtual {v3}, Llyiahf/vczjk/pr2;->o0000O0O()Z

    move-result p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    if-nez p1, :cond_3

    :goto_1
    invoke-virtual {v3, v1}, Llyiahf/vczjk/pr2;->o0000(Z)V

    goto :goto_3

    :catchall_0
    move-exception p1

    goto :goto_2

    :catchall_1
    move-exception p1

    :try_start_3
    invoke-static {v2, v4}, Llyiahf/vczjk/jp8;->OoooOO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)V

    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    :goto_2
    :try_start_4
    invoke-virtual {p0, p1}, Llyiahf/vczjk/hc2;->OooO0o(Ljava/lang/Throwable;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    goto :goto_1

    :goto_3
    return-void

    :catchall_2
    move-exception p1

    invoke-virtual {v3, v1}, Llyiahf/vczjk/pr2;->o0000(Z)V

    throw p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "DispatchedContinuation["

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/fc2;->OooOOOo:Llyiahf/vczjk/qr1;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/fc2;->OooOOo0:Llyiahf/vczjk/zo1;

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOooO(Llyiahf/vczjk/yo1;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x5d

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
