.class public final Llyiahf/vczjk/tv6;
.super Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber$Stub;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o0:Llyiahf/vczjk/uv6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/uv6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tv6;->OooO0o0:Llyiahf/vczjk/uv6;

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber$Stub;-><init>()V

    return-void
.end method


# virtual methods
.method public final onEvent(Lgithub/tornaco/android/thanos/core/app/event/ThanosEvent;)V
    .locals 2

    new-instance v0, Llyiahf/vczjk/tm4;

    const/16 v1, 0x9

    invoke-direct {v0, v1, p0, p1}, Llyiahf/vczjk/tm4;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/tv6;->OooO0o0:Llyiahf/vczjk/uv6;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/td9;->OooO0o(Ljava/lang/Runnable;)V

    return-void
.end method
