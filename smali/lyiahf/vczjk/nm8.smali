.class public final Llyiahf/vczjk/nm8;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Lgithub/tornaco/android/thanos/core/Logger;

.field public OooO0O0:Lgithub/tornaco/android/thanos/core/IThanosLite;

.field public final OooO0OO:Llyiahf/vczjk/lm8;

.field public final OooO0Oo:Llyiahf/vczjk/yw;


# direct methods
.method public constructor <init>()V
    .locals 4

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v1, "ServiceBinder"

    invoke-direct {v0, v1}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    iput-object v0, p0, Llyiahf/vczjk/nm8;->OooO00o:Lgithub/tornaco/android/thanos/core/Logger;

    new-instance v0, Llyiahf/vczjk/lm8;

    invoke-direct {v0, p0}, Llyiahf/vczjk/lm8;-><init>(Llyiahf/vczjk/nm8;)V

    iput-object v0, p0, Llyiahf/vczjk/nm8;->OooO0OO:Llyiahf/vczjk/lm8;

    new-instance v0, Llyiahf/vczjk/yw;

    new-instance v1, Landroid/content/ComponentName;

    const-class v2, Ltornaco/app/thanox/lite/service/api/ShizukuServiceStub;

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    const-string v3, "github.tornaco.android.thanos"

    invoke-direct {v1, v3, v2}, Landroid/content/ComponentName;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/yw;-><init>(Landroid/content/ComponentName;)V

    const-string v1, "service"

    iput-object v1, v0, Llyiahf/vczjk/yw;->OooO0Oo:Ljava/lang/Object;

    const v1, 0x332f00

    iput v1, v0, Llyiahf/vczjk/yw;->OooO0O0:I

    iput-object v0, p0, Llyiahf/vczjk/nm8;->OooO0Oo:Llyiahf/vczjk/yw;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 4

    sget-object v0, Llyiahf/vczjk/gm8;->OooO00o:Landroid/os/IBinder;

    sget-object v0, Llyiahf/vczjk/pm8;->OooO00o:Ljava/util/Map;

    iget-object v0, p0, Llyiahf/vczjk/nm8;->OooO0Oo:Llyiahf/vczjk/yw;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, v0, Llyiahf/vczjk/yw;->OooO0OO:Ljava/lang/Object;

    check-cast v1, Landroid/content/ComponentName;

    invoke-virtual {v1}, Landroid/content/ComponentName;->getClassName()Ljava/lang/String;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/pm8;->OooO00o:Ljava/util/Map;

    invoke-interface {v2, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/om8;

    if-nez v3, :cond_0

    new-instance v3, Llyiahf/vczjk/om8;

    invoke-direct {v3, v0}, Llyiahf/vczjk/om8;-><init>(Llyiahf/vczjk/yw;)V

    invoke-interface {v2, v1, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/nm8;->OooO0OO:Llyiahf/vczjk/lm8;

    if-eqz v1, :cond_1

    iget-object v2, v3, Llyiahf/vczjk/om8;->OooO0o0:Ljava/util/HashSet;

    invoke-virtual {v2, v1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    :cond_1
    :try_start_0
    invoke-static {}, Llyiahf/vczjk/gm8;->OooO0o0()Llyiahf/vczjk/jt3;

    move-result-object v1

    invoke-static {v0}, Llyiahf/vczjk/yw;->OooO00o(Llyiahf/vczjk/yw;)Landroid/os/Bundle;

    move-result-object v0

    check-cast v1, Llyiahf/vczjk/ht3;

    invoke-virtual {v1, v3, v0}, Llyiahf/vczjk/ht3;->OooO0o(Llyiahf/vczjk/om8;Landroid/os/Bundle;)I
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    new-instance v1, Ljava/lang/RuntimeException;

    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v1
.end method

.method public final OooO0O0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 6

    instance-of v0, p1, Llyiahf/vczjk/mm8;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/mm8;

    iget v1, v0, Llyiahf/vczjk/mm8;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/mm8;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/mm8;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/mm8;-><init>(Llyiahf/vczjk/nm8;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/mm8;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/mm8;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    :goto_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/nm8;->OooO0O0:Lgithub/tornaco/android/thanos/core/IThanosLite;

    if-nez p1, :cond_4

    iput v3, v0, Llyiahf/vczjk/mm8;->label:I

    const-wide/16 v4, 0x64

    invoke-static {v4, v5, v0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
