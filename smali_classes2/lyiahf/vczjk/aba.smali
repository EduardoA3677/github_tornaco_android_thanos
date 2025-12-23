.class public final Llyiahf/vczjk/aba;
.super Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber$Stub;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o0:Llyiahf/vczjk/bba;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bba;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/aba;->OooO0o0:Llyiahf/vczjk/bba;

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber$Stub;-><init>()V

    return-void
.end method


# virtual methods
.method public final onEvent(Lgithub/tornaco/android/thanos/core/app/event/ThanosEvent;)V
    .locals 3

    const-string v0, "e"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/app/event/ThanosEvent;->getIntent()Landroid/content/Intent;

    move-result-object v0

    if-nez v0, :cond_0

    return-void

    :cond_0
    new-instance v0, Llyiahf/vczjk/yx9;

    iget-object v1, p0, Llyiahf/vczjk/aba;->OooO0o0:Llyiahf/vczjk/bba;

    const/4 v2, 0x2

    invoke-direct {v0, v2, p1, v1}, Llyiahf/vczjk/yx9;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/td9;->OooO0o(Ljava/lang/Runnable;)V

    return-void
.end method
