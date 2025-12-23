.class public final Llyiahf/vczjk/pp9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $taskInfo:Landroid/app/ActivityManager$RunningTaskInfo;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/yp9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yp9;Landroid/app/ActivityManager$RunningTaskInfo;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pp9;->this$0:Llyiahf/vczjk/yp9;

    iput-object p2, p0, Llyiahf/vczjk/pp9;->$taskInfo:Landroid/app/ActivityManager$RunningTaskInfo;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/pp9;

    iget-object v0, p0, Llyiahf/vczjk/pp9;->this$0:Llyiahf/vczjk/yp9;

    iget-object v1, p0, Llyiahf/vczjk/pp9;->$taskInfo:Landroid/app/ActivityManager$RunningTaskInfo;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/pp9;-><init>(Llyiahf/vczjk/yp9;Landroid/app/ActivityManager$RunningTaskInfo;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/pp9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/pp9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/pp9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/pp9;->label:I

    if-nez v0, :cond_3

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/pp9;->this$0:Llyiahf/vczjk/yp9;

    invoke-virtual {p1}, Llyiahf/vczjk/sd9;->OooO0oO()Lgithub/tornaco/android/thanos/core/Logger;

    iget-object p1, p0, Llyiahf/vczjk/pp9;->$taskInfo:Landroid/app/ActivityManager$RunningTaskInfo;

    if-eqz p1, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/fz7;->OooO00o(Landroid/app/ActivityManager$RunningTaskInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    invoke-static {p1}, Ljava/util/Objects;->toString(Ljava/lang/Object;)Ljava/lang/String;

    iget-object p1, p0, Llyiahf/vczjk/pp9;->$taskInfo:Landroid/app/ActivityManager$RunningTaskInfo;

    if-eqz p1, :cond_2

    invoke-static {p1}, Llyiahf/vczjk/fz7;->OooO00o(Landroid/app/ActivityManager$RunningTaskInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object p1

    if-eqz p1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/pp9;->this$0:Llyiahf/vczjk/yp9;

    iget-object v1, v0, Llyiahf/vczjk/yp9;->OooOOo0:Llyiahf/vczjk/s29;

    :cond_1
    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-virtual {v1, v2, p1}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/sd9;->OooO0oO()Lgithub/tornaco/android/thanos/core/Logger;

    iget-object v1, v0, Llyiahf/vczjk/yp9;->OooOOo0:Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v1}, Ljava/util/Objects;->toString(Ljava/lang/Object;)Ljava/lang/String;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getUserId()I

    move-result v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/yp9;->OooOO0o(I)Llyiahf/vczjk/jw6;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/jw6;->OooO00o(Ljava/lang/String;)V

    :cond_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
