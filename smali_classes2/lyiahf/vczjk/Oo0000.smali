.class public final Llyiahf/vczjk/Oo0000;
.super Lgithub/tornaco/android/thanos/core/n/INotificationObserver$Stub;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o0:Llyiahf/vczjk/a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/a;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/Oo0000;->OooO0o0:Llyiahf/vczjk/a;

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/n/INotificationObserver$Stub;-><init>()V

    return-void
.end method


# virtual methods
.method public final onNewNotification(Lgithub/tornaco/android/thanos/core/n/NotificationRecord;)V
    .locals 0

    return-void
.end method

.method public final onNotificationClicked(Lgithub/tornaco/android/thanos/core/n/NotificationRecord;)V
    .locals 0

    return-void
.end method

.method public final onNotificationRemoved(Lgithub/tornaco/android/thanos/core/n/NotificationRecord;)V
    .locals 2

    if-nez p1, :cond_0

    return-void

    :cond_0
    new-instance v0, Llyiahf/vczjk/oO0oO000;

    const/4 v1, 0x7

    invoke-direct {v0, v1, p0, p1}, Llyiahf/vczjk/oO0oO000;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/Oo0000;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/td9;->OooO0o(Ljava/lang/Runnable;)V

    return-void
.end method

.method public final onNotificationUpdated(Lgithub/tornaco/android/thanos/core/n/NotificationRecord;)V
    .locals 0

    return-void
.end method
