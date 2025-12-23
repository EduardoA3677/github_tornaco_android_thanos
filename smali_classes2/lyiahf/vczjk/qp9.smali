.class public final Llyiahf/vczjk/qp9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $taskId:I

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/yp9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yp9;ILlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qp9;->this$0:Llyiahf/vczjk/yp9;

    iput p2, p0, Llyiahf/vczjk/qp9;->$taskId:I

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/qp9;

    iget-object v0, p0, Llyiahf/vczjk/qp9;->this$0:Llyiahf/vczjk/yp9;

    iget v1, p0, Llyiahf/vczjk/qp9;->$taskId:I

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/qp9;-><init>(Llyiahf/vczjk/yp9;ILlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/qp9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/qp9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/qp9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/qp9;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/qp9;->this$0:Llyiahf/vczjk/yp9;

    invoke-virtual {p1}, Llyiahf/vczjk/sd9;->OooO0oO()Lgithub/tornaco/android/thanos/core/Logger;

    iput v2, p0, Llyiahf/vczjk/qp9;->label:I

    const-wide/16 v3, 0xc8

    invoke-static {v3, v4, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/rg9;->OooO0O0:Ljava/util/LinkedHashMap;

    iget v0, p0, Llyiahf/vczjk/qp9;->$taskId:I

    iget-object v1, p0, Llyiahf/vczjk/qp9;->this$0:Llyiahf/vczjk/yp9;

    monitor-enter p1

    :try_start_0
    new-instance v3, Ljava/lang/Integer;

    invoke-direct {v3, v0}, Ljava/lang/Integer;-><init>(I)V

    invoke-virtual {p1, v3}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-virtual {v1}, Llyiahf/vczjk/sd9;->OooO0oO()Lgithub/tornaco/android/thanos/core/Logger;

    invoke-static {v0}, Ljava/util/Objects;->toString(Ljava/lang/Object;)Ljava/lang/String;

    if-eqz v0, :cond_4

    iget-object v3, v1, Llyiahf/vczjk/yp9;->OooOO0:Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;

    invoke-virtual {v3}, Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;->getIsTaskRemoveFreezeEnabled()Z

    move-result v3

    if-eqz v3, :cond_3

    iget-object v3, v1, Llyiahf/vczjk/yp9;->OooOO0:Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;

    invoke-static {v3, v0}, Lgithub/tornaco/android/thanos/core/ExtensionsKt;->containsPkg(Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-static {v1, v0}, Llyiahf/vczjk/yp9;->OooO0oo(Llyiahf/vczjk/yp9;Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v3

    if-nez v3, :cond_3

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/yp9;->freezePkgs(Ljava/util/List;Z)V

    goto :goto_1

    :catchall_0
    move-exception v0

    goto :goto_2

    :cond_3
    :goto_1
    iget-object v2, v1, Llyiahf/vczjk/yp9;->OooOO0O:Ltornaco/apps/thanox/core/proto/common/BgCleanSettings;

    invoke-virtual {v2}, Ltornaco/apps/thanox/core/proto/common/BgCleanSettings;->getIsTaskRemoveCleanEnabled()Z

    move-result v2

    if-eqz v2, :cond_4

    iget-object v2, v1, Llyiahf/vczjk/yp9;->OooOO0O:Ltornaco/apps/thanox/core/proto/common/BgCleanSettings;

    invoke-static {v2, v0}, Lgithub/tornaco/android/thanos/core/ExtensionsKt;->containsPkg(Ltornaco/apps/thanox/core/proto/common/BgCleanSettings;Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v2

    if-eqz v2, :cond_4

    invoke-static {v1, v0}, Llyiahf/vczjk/yp9;->OooO0oo(Llyiahf/vczjk/yp9;Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v2

    if-nez v2, :cond_4

    const-string v2, "onTaskRemoved"

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/yp9;->forceStopPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_4
    monitor-exit p1

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :goto_2
    monitor-exit p1

    throw v0
.end method
