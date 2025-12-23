.class public final Llyiahf/vczjk/lf7;
.super Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber$Stub;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o0:Llyiahf/vczjk/mf7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mf7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/lf7;->OooO0o0:Llyiahf/vczjk/mf7;

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber$Stub;-><init>()V

    return-void
.end method


# virtual methods
.method public final onEvent(Lgithub/tornaco/android/thanos/core/app/event/ThanosEvent;)V
    .locals 3

    const-string v0, "e"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/app/event/ThanosEvent;->getIntent()Landroid/content/Intent;

    move-result-object p1

    const-string v0, "getIntent(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/lf7;->OooO0o0:Llyiahf/vczjk/mf7;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/tm4;

    const/16 v2, 0x11

    invoke-direct {v1, v2, v0, p1}, Llyiahf/vczjk/tm4;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/td9;->OooO0o(Ljava/lang/Runnable;)V

    return-void
.end method
