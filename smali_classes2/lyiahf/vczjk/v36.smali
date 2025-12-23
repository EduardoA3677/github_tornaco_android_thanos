.class public final Llyiahf/vczjk/v36;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $extrasProducer:Llyiahf/vczjk/le3;

.field final synthetic $this_viewModels:Landroidx/activity/ComponentActivity;


# direct methods
.method public constructor <init>(Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;)V
    .locals 1

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/v36;->$extrasProducer:Llyiahf/vczjk/le3;

    iput-object p1, p0, Llyiahf/vczjk/v36;->$this_viewModels:Landroidx/activity/ComponentActivity;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v36;->$extrasProducer:Llyiahf/vczjk/le3;

    if-eqz v0, :cond_1

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/os1;

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    return-object v0

    :cond_1
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/v36;->$this_viewModels:Landroidx/activity/ComponentActivity;

    invoke-virtual {v0}, Landroidx/activity/ComponentActivity;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v0

    return-object v0
.end method
