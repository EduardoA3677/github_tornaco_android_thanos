.class public final Llyiahf/vczjk/p2;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $am:Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

.field synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Lnow/fortuitous/thanos/apps/AioAppListActivity;


# direct methods
.method public constructor <init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/p2;->this$0:Lnow/fortuitous/thanos/apps/AioAppListActivity;

    iput-object p2, p0, Llyiahf/vczjk/p2;->$am:Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Landroid/content/Context;

    check-cast p2, Ljava/lang/String;

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/p2;

    iget-object v1, p0, Llyiahf/vczjk/p2;->this$0:Lnow/fortuitous/thanos/apps/AioAppListActivity;

    iget-object v2, p0, Llyiahf/vczjk/p2;->$am:Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    invoke-direct {v0, v1, v2, p3}, Llyiahf/vczjk/p2;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/p2;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/p2;->L$1:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/p2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/p2;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/p2;->L$0:Ljava/lang/Object;

    check-cast p1, Landroid/content/Context;

    iget-object v0, p0, Llyiahf/vczjk/p2;->L$1:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/p2;->this$0:Lnow/fortuitous/thanos/apps/AioAppListActivity;

    iget-object v2, p0, Llyiahf/vczjk/p2;->$am:Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    new-instance v3, Llyiahf/vczjk/x1;

    const/4 v4, 0x1

    invoke-direct {v3, v2, v4}, Llyiahf/vczjk/x1;-><init>(Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;I)V

    invoke-static {v1, p1, v0, v3}, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OooOooO(Lnow/fortuitous/thanos/apps/AioAppListActivity;Landroid/content/Context;Ljava/lang/String;Llyiahf/vczjk/ze3;)Ljava/util/List;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
