.class public abstract Llyiahf/vczjk/vo1;
.super Llyiahf/vczjk/g39;
.source "SourceFile"


# instance fields
.field public final OooO0o:Landroid/content/Context;

.field public final OooO0oO:Lgithub/tornaco/android/thanos/core/Logger;


# direct methods
.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/le3;)V
    .locals 0

    invoke-direct {p0, p2}, Llyiahf/vczjk/g39;-><init>(Llyiahf/vczjk/le3;)V

    iput-object p1, p0, Llyiahf/vczjk/vo1;->OooO0o:Landroid/content/Context;

    new-instance p1, Lgithub/tornaco/android/thanos/core/Logger;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/vo1;->OooO0oO:Lgithub/tornaco/android/thanos/core/Logger;

    return-void
.end method
