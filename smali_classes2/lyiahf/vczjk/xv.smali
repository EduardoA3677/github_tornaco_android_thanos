.class public final Llyiahf/vczjk/xv;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lutil/Consumer;


# instance fields
.field public final synthetic OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field public final synthetic OooO0O0:I

.field public final synthetic OooO0OO:Llyiahf/vczjk/bw;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bw;Lgithub/tornaco/android/thanos/core/pm/AppInfo;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xv;->OooO0OO:Llyiahf/vczjk/bw;

    iput-object p2, p0, Llyiahf/vczjk/xv;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iput p3, p0, Llyiahf/vczjk/xv;->OooO0O0:I

    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 2

    check-cast p1, Llyiahf/vczjk/oc6;

    iget-object p1, p1, Llyiahf/vczjk/oc6;->OooOOO:Ljava/util/ArrayList;

    new-instance v0, Llyiahf/vczjk/wv;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/wv;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1, v0}, Lutil/CollectionUtils;->consumeRemaining(Ljava/util/Collection;Lutil/Consumer;)V

    return-void
.end method
