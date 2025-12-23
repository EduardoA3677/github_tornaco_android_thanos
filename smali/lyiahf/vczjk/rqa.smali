.class public final Llyiahf/vczjk/rqa;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/vq;

.field public final OooO0O0:Llyiahf/vczjk/qr1;

.field public final OooO0OO:Landroid/os/Handler;

.field public final OooO0Oo:Llyiahf/vczjk/wd;


# direct methods
.method public constructor <init>(Ljava/util/concurrent/ExecutorService;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v1

    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    iput-object v0, p0, Llyiahf/vczjk/rqa;->OooO0OO:Landroid/os/Handler;

    new-instance v0, Llyiahf/vczjk/wd;

    const/4 v1, 0x5

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/wd;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Llyiahf/vczjk/rqa;->OooO0Oo:Llyiahf/vczjk/wd;

    new-instance v0, Llyiahf/vczjk/vq;

    invoke-direct {v0, p1}, Llyiahf/vczjk/vq;-><init>(Ljava/util/concurrent/ExecutorService;)V

    iput-object v0, p0, Llyiahf/vczjk/rqa;->OooO00o:Llyiahf/vczjk/vq;

    invoke-static {v0}, Llyiahf/vczjk/dn8;->OoooOo0(Ljava/util/concurrent/Executor;)Llyiahf/vczjk/qr1;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/rqa;->OooO0O0:Llyiahf/vczjk/qr1;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Runnable;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rqa;->OooO00o:Llyiahf/vczjk/vq;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/vq;->execute(Ljava/lang/Runnable;)V

    return-void
.end method
