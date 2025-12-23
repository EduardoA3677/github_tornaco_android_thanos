.class public final Llyiahf/vczjk/hr2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/u41;


# instance fields
.field public final OooO00o:[Ljava/lang/Object;

.field public final OooO0O0:Ljava/util/concurrent/ExecutorService;

.field public final OooO0OO:Landroid/os/RemoteCallbackList;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/u41;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Llyiahf/vczjk/u41;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/hr2;->OooO0Oo:Llyiahf/vczjk/u41;

    return-void
.end method

.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    iput-object v0, p0, Llyiahf/vczjk/hr2;->OooO00o:[Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/gr2;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/gr2;-><init>(I)V

    invoke-static {v0}, Ljava/util/concurrent/Executors;->newSingleThreadExecutor(Ljava/util/concurrent/ThreadFactory;)Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/hr2;->OooO0O0:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Landroid/os/RemoteCallbackList;

    invoke-direct {v0}, Landroid/os/RemoteCallbackList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/hr2;->OooO0OO:Landroid/os/RemoteCallbackList;

    return-void
.end method

.method public static OooO00o()Llyiahf/vczjk/hr2;
    .locals 1

    sget-object v0, Llyiahf/vczjk/hr2;->OooO0Oo:Llyiahf/vczjk/u41;

    invoke-virtual {v0}, Lutil/Singleton;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/hr2;

    return-object v0
.end method


# virtual methods
.method public final OooO0O0(Lgithub/tornaco/android/thanos/core/app/event/ThanosEvent;)V
    .locals 2

    new-instance v0, Llyiahf/vczjk/oO0oO000;

    const/16 v1, 0x1b

    invoke-direct {v0, v1, p0, p1}, Llyiahf/vczjk/oO0oO000;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/y51;

    const/4 v1, 0x1

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/y51;-><init>(Ljava/lang/Object;I)V

    sget-object v0, Llyiahf/vczjk/s88;->OooO00o:Llyiahf/vczjk/i88;

    new-instance v0, Llyiahf/vczjk/ns2;

    iget-object v1, p0, Llyiahf/vczjk/hr2;->OooO0O0:Ljava/util/concurrent/ExecutorService;

    invoke-direct {v0, v1}, Llyiahf/vczjk/ns2;-><init>(Ljava/util/concurrent/ExecutorService;)V

    invoke-virtual {p1, v0}, Llyiahf/vczjk/t51;->OooooO0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/g61;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/t51;->OoooOoo()Llyiahf/vczjk/um2;

    return-void
.end method

.method public final OooO0OO(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V
    .locals 2

    const-string v0, "subscriber is null"

    invoke-static {p2, v0}, Lutil/PreconditionUtils;->checkNotNull(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const-string v0, "filter is null"

    invoke-static {p1, v0}, Lutil/PreconditionUtils;->checkNotNull(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v0, p0, Llyiahf/vczjk/hr2;->OooO0OO:Landroid/os/RemoteCallbackList;

    new-instance v1, Llyiahf/vczjk/qr2;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/qr2;-><init>(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V

    invoke-virtual {v0, v1}, Landroid/os/RemoteCallbackList;->register(Landroid/os/IInterface;)Z

    return-void
.end method

.method public final OooO0Oo(Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V
    .locals 3

    const-string v0, "subscriber is null"

    invoke-static {p1, v0}, Lutil/PreconditionUtils;->checkNotNull(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v0, p0, Llyiahf/vczjk/hr2;->OooO0OO:Landroid/os/RemoteCallbackList;

    new-instance v1, Llyiahf/vczjk/qr2;

    const/4 v2, 0x0

    invoke-direct {v1, v2, p1}, Llyiahf/vczjk/qr2;-><init>(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V

    invoke-virtual {v0, v1}, Landroid/os/RemoteCallbackList;->unregister(Landroid/os/IInterface;)Z

    return-void
.end method
