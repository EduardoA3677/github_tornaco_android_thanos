.class public abstract Llyiahf/vczjk/fz7;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static OooO00o(Landroid/app/ActivityManager$RunningTaskInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :try_start_0
    iget v0, p0, Landroid/app/ActivityManager$RunningTaskInfo;->userId:I

    invoke-static {p0}, Llyiahf/vczjk/hp7;->OooO0o0(Landroid/app/ActivityManager$RunningTaskInfo;)Landroid/content/ComponentName;

    move-result-object p0

    invoke-virtual {p0}, Landroid/content/ComponentName;->getPackageName()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, v0}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->newPkg(Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    invoke-static {p0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p0

    :goto_0
    invoke-static {p0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    const/4 p0, 0x0

    :goto_1
    check-cast p0, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    return-object p0
.end method
