.class public abstract Landroidx/work/CoroutineWorker;
.super Llyiahf/vczjk/b25;
.source "SourceFile"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008&\u0018\u00002\u00020\u0001:\u0001\u0008B\u0017\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u0006\u0010\u0007\u00a8\u0006\t"
    }
    d2 = {
        "Landroidx/work/CoroutineWorker;",
        "Llyiahf/vczjk/b25;",
        "Landroid/content/Context;",
        "appContext",
        "Landroidx/work/WorkerParameters;",
        "params",
        "<init>",
        "(Landroid/content/Context;Landroidx/work/WorkerParameters;)V",
        "lyiahf/vczjk/bs1",
        "work-runtime_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x8,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final OooO0o:Llyiahf/vczjk/bs1;

.field public final OooO0o0:Landroidx/work/WorkerParameters;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroidx/work/WorkerParameters;)V
    .locals 1

    const-string v0, "appContext"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "params"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/b25;-><init>(Landroid/content/Context;Landroidx/work/WorkerParameters;)V

    iput-object p2, p0, Landroidx/work/CoroutineWorker;->OooO0o0:Landroidx/work/WorkerParameters;

    sget-object p1, Llyiahf/vczjk/bs1;->OooOOOO:Llyiahf/vczjk/bs1;

    iput-object p1, p0, Landroidx/work/CoroutineWorker;->OooO0o:Llyiahf/vczjk/bs1;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/qo0;
    .locals 3

    invoke-static {}, Llyiahf/vczjk/zsa;->OooO0oO()Llyiahf/vczjk/x74;

    move-result-object v0

    iget-object v1, p0, Landroidx/work/CoroutineWorker;->OooO0o:Llyiahf/vczjk/bs1;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1, v0}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/cs1;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/cs1;-><init>(Landroidx/work/CoroutineWorker;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/cp7;->OooOooo(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/qo0;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/qo0;
    .locals 3

    sget-object v0, Llyiahf/vczjk/bs1;->OooOOOO:Llyiahf/vczjk/bs1;

    iget-object v1, p0, Landroidx/work/CoroutineWorker;->OooO0o:Llyiahf/vczjk/bs1;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Landroidx/work/CoroutineWorker;->OooO0o0:Landroidx/work/WorkerParameters;

    iget-object v1, v0, Landroidx/work/WorkerParameters;->OooO0Oo:Llyiahf/vczjk/qr1;

    :goto_0
    const-string v0, "if (coroutineContext != \u2026rkerContext\n            }"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/zsa;->OooO0oO()Llyiahf/vczjk/x74;

    move-result-object v0

    invoke-static {v1, v0}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/ds1;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/ds1;-><init>(Landroidx/work/CoroutineWorker;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/cp7;->OooOooo(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/qo0;

    move-result-object v0

    return-object v0
.end method

.method public abstract OooO0OO(Llyiahf/vczjk/ds1;)Ljava/lang/Object;
.end method
