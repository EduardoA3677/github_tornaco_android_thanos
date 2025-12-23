.class public final synthetic Llyiahf/vczjk/oOO00OO;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Lgithub/tornaco/android/thanos/core/pm/Pkg;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a;Lgithub/tornaco/android/thanos/core/pm/Pkg;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/oOO00OO;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/oOO00OO;->OooOOO:Llyiahf/vczjk/a;

    iput-object p2, p0, Llyiahf/vczjk/oOO00OO;->OooOOOO:Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    iget v0, p0, Llyiahf/vczjk/oOO00OO;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/oOO00OO;->OooOOO:Llyiahf/vczjk/a;

    iget-object v1, p0, Llyiahf/vczjk/oOO00OO;->OooOOOO:Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/a;->OoooO(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/oOO00OO;->OooOOO:Llyiahf/vczjk/a;

    iget-object v1, p0, Llyiahf/vczjk/oOO00OO;->OooOOOO:Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/a;->OooOoo0(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    return-void

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/oOO00OO;->OooOOO:Llyiahf/vczjk/a;

    iget-object v1, p0, Llyiahf/vczjk/oOO00OO;->OooOOOO:Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/a;->OooOooO(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    return-void

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/oOO00OO;->OooOOO:Llyiahf/vczjk/a;

    iget-object v1, p0, Llyiahf/vczjk/oOO00OO;->OooOOOO:Lgithub/tornaco/android/thanos/core/pm/Pkg;

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v2

    const-string v3, "addAppInternal: %s"

    invoke-static {v3, v2}, Llyiahf/vczjk/zsa;->o0ooOoO(Ljava/lang/String;[Ljava/lang/Object;)V

    :try_start_0
    iget-object v2, v0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getUserId()I

    move-result v1

    invoke-static {v2, v3, v1}, Lgithub/tornaco/android/thanos/core/util/PkgUtils;->getApplicationInfoAsUser(Landroid/content/Context;Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;

    move-result-object v1

    if-eqz v1, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOO:Llyiahf/vczjk/kg;

    iget-object v0, v0, Llyiahf/vczjk/kg;->OooOOO0:Llyiahf/vczjk/era;

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/oO00o000;

    const-string v2, "ActivityManagerServiceProxy is null."

    invoke-static {v0, v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/oO00o000;->o0000oo(Landroid/content/pm/ApplicationInfo;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    invoke-static {v0}, Landroid/util/Log;->getStackTraceString(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "Error addApp: "

    invoke-static {v1, v0}, Llyiahf/vczjk/ix8;->OooOo0(Ljava/lang/String;Ljava/lang/String;)V

    :cond_0
    :goto_0
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
