.class public final synthetic Llyiahf/vczjk/gv6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/uv6;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Lgithub/tornaco/android/thanos/core/pm/Pkg;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/uv6;Lgithub/tornaco/android/thanos/core/pm/Pkg;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/gv6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/gv6;->OooOOO:Llyiahf/vczjk/uv6;

    iput-object p2, p0, Llyiahf/vczjk/gv6;->OooOOOO:Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/gv6;->OooOOOO:Lgithub/tornaco/android/thanos/core/pm/Pkg;

    iget-object v1, p0, Llyiahf/vczjk/gv6;->OooOOO:Llyiahf/vczjk/uv6;

    iget v2, p0, Llyiahf/vczjk/gv6;->OooOOO0:I

    packed-switch v2, :pswitch_data_0

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/ku;->OooO00o(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    iget-boolean v2, v1, Llyiahf/vczjk/uv6;->OooOOO0:Z

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/uv6;->OooOoo(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    const-string v2, "launchSmartFreezePkgInternal: %s"

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2, v3}, Llyiahf/vczjk/zsa;->o0ooOoO(Ljava/lang/String;[Ljava/lang/Object;)V

    sget-object v2, Llyiahf/vczjk/sl3;->OooOOO0:Llyiahf/vczjk/il3;

    iget-object v2, v1, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    new-instance v3, Llyiahf/vczjk/oO0O0O0o;

    iget-object v1, v1, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    invoke-direct {v3, v2, v1}, Llyiahf/vczjk/oO0O0O0o;-><init>(Landroid/content/Context;Llyiahf/vczjk/fo9;)V

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getUserId()I

    move-result v0

    invoke-virtual {v3, v1, v0}, Llyiahf/vczjk/oO0O0O0o;->launchMainActivityForPackageForUser(Ljava/lang/String;I)Z

    return-void

    :pswitch_0
    const/4 v2, 0x0

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/uv6;->OooOoo(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
