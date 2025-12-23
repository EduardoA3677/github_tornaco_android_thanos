.class public final Llyiahf/vczjk/j07;
.super Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber$Stub;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o0:Llyiahf/vczjk/k07;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k07;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/j07;->OooO0o0:Llyiahf/vczjk/k07;

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber$Stub;-><init>()V

    return-void
.end method


# virtual methods
.method public final onEvent(Lgithub/tornaco/android/thanos/core/app/event/ThanosEvent;)V
    .locals 1

    const-string v0, "e"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "Reboot action received!!!"

    invoke-static {p1}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/j07;->OooO0o0:Llyiahf/vczjk/k07;

    invoke-virtual {p1}, Llyiahf/vczjk/k07;->reboot()V

    return-void
.end method
