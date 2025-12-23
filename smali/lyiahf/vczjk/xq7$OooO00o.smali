.class public final Llyiahf/vczjk/xq7$OooO00o;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/app/Application$ActivityLifecycleCallbacks;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Llyiahf/vczjk/xq7;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "OooO00o"
.end annotation


# static fields
.field public static final Companion:Llyiahf/vczjk/wq7;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/wq7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/xq7$OooO00o;->Companion:Llyiahf/vczjk/wq7;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static final registerIn(Landroid/app/Activity;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/xq7$OooO00o;->Companion:Llyiahf/vczjk/wq7;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "activity"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/xq7$OooO00o;

    invoke-direct {v0}, Llyiahf/vczjk/xq7$OooO00o;-><init>()V

    invoke-static {p0, v0}, Llyiahf/vczjk/hp7;->OooOOO0(Landroid/app/Activity;Llyiahf/vczjk/xq7$OooO00o;)V

    return-void
.end method


# virtual methods
.method public onActivityCreated(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 0

    const-string p2, "activity"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method

.method public onActivityDestroyed(Landroid/app/Activity;)V
    .locals 1

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method

.method public onActivityPaused(Landroid/app/Activity;)V
    .locals 1

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method

.method public onActivityPostCreated(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 0

    const-string p2, "activity"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget p2, Llyiahf/vczjk/xq7;->OooOOO:I

    sget-object p2, Llyiahf/vczjk/iy4;->ON_CREATE:Llyiahf/vczjk/iy4;

    invoke-static {p1, p2}, Llyiahf/vczjk/vq7;->OooO00o(Landroid/app/Activity;Llyiahf/vczjk/iy4;)V

    return-void
.end method

.method public onActivityPostResumed(Landroid/app/Activity;)V
    .locals 1

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Llyiahf/vczjk/xq7;->OooOOO:I

    sget-object v0, Llyiahf/vczjk/iy4;->ON_RESUME:Llyiahf/vczjk/iy4;

    invoke-static {p1, v0}, Llyiahf/vczjk/vq7;->OooO00o(Landroid/app/Activity;Llyiahf/vczjk/iy4;)V

    return-void
.end method

.method public onActivityPostStarted(Landroid/app/Activity;)V
    .locals 1

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Llyiahf/vczjk/xq7;->OooOOO:I

    sget-object v0, Llyiahf/vczjk/iy4;->ON_START:Llyiahf/vczjk/iy4;

    invoke-static {p1, v0}, Llyiahf/vczjk/vq7;->OooO00o(Landroid/app/Activity;Llyiahf/vczjk/iy4;)V

    return-void
.end method

.method public onActivityPreDestroyed(Landroid/app/Activity;)V
    .locals 1

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Llyiahf/vczjk/xq7;->OooOOO:I

    sget-object v0, Llyiahf/vczjk/iy4;->ON_DESTROY:Llyiahf/vczjk/iy4;

    invoke-static {p1, v0}, Llyiahf/vczjk/vq7;->OooO00o(Landroid/app/Activity;Llyiahf/vczjk/iy4;)V

    return-void
.end method

.method public onActivityPrePaused(Landroid/app/Activity;)V
    .locals 1

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Llyiahf/vczjk/xq7;->OooOOO:I

    sget-object v0, Llyiahf/vczjk/iy4;->ON_PAUSE:Llyiahf/vczjk/iy4;

    invoke-static {p1, v0}, Llyiahf/vczjk/vq7;->OooO00o(Landroid/app/Activity;Llyiahf/vczjk/iy4;)V

    return-void
.end method

.method public onActivityPreStopped(Landroid/app/Activity;)V
    .locals 1

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Llyiahf/vczjk/xq7;->OooOOO:I

    sget-object v0, Llyiahf/vczjk/iy4;->ON_STOP:Llyiahf/vczjk/iy4;

    invoke-static {p1, v0}, Llyiahf/vczjk/vq7;->OooO00o(Landroid/app/Activity;Llyiahf/vczjk/iy4;)V

    return-void
.end method

.method public onActivityResumed(Landroid/app/Activity;)V
    .locals 1

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method

.method public onActivitySaveInstanceState(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 1

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "bundle"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method

.method public onActivityStarted(Landroid/app/Activity;)V
    .locals 1

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method

.method public onActivityStopped(Landroid/app/Activity;)V
    .locals 1

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method
