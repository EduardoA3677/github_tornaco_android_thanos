.class public final Llyiahf/vczjk/p08;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field public final synthetic OooOOO0:Llyiahf/vczjk/h48;

.field public final synthetic OooOOOO:Llyiahf/vczjk/p29;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h48;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/p29;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/p08;->OooOOO0:Llyiahf/vczjk/h48;

    iput-object p2, p0, Llyiahf/vczjk/p08;->OooOOO:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iput-object p3, p0, Llyiahf/vczjk/p08;->OooOOOO:Llyiahf/vczjk/p29;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/p08;->OooOOOO:Llyiahf/vczjk/p29;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/i28;

    iget-boolean v0, v0, Llyiahf/vczjk/i28;->OooO00o:Z

    iget-object v1, p0, Llyiahf/vczjk/p08;->OooOOO0:Llyiahf/vczjk/h48;

    iget-object v2, p0, Llyiahf/vczjk/p08;->OooOOO:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    if-eqz v0, :cond_0

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "app"

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/h48;->OooOO0(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    goto :goto_0

    :cond_0
    invoke-static {}, Ltornaco/apps/thanox/core/proto/common/AppPkg;->newBuilder()Ltornaco/apps/thanox/core/proto/common/AppPkg$Builder;

    move-result-object v0

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v0, v3}, Ltornaco/apps/thanox/core/proto/common/AppPkg$Builder;->setPkgName(Ljava/lang/String;)Ltornaco/apps/thanox/core/proto/common/AppPkg$Builder;

    move-result-object v0

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v2

    invoke-virtual {v0, v2}, Ltornaco/apps/thanox/core/proto/common/AppPkg$Builder;->setUserId(I)Ltornaco/apps/thanox/core/proto/common/AppPkg$Builder;

    move-result-object v0

    invoke-virtual {v0}, Ltornaco/apps/thanox/core/proto/common/AppPkg$Builder;->build()Ltornaco/apps/thanox/core/proto/common/AppPkg;

    move-result-object v0

    const-string v2, "build(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/f38;

    const/4 v3, 0x0

    invoke-direct {v2, v0, v3}, Llyiahf/vczjk/f38;-><init>(Ltornaco/apps/thanox/core/proto/common/AppPkg;Llyiahf/vczjk/yo1;)V

    const/4 v0, 0x3

    invoke-static {v1, v3, v3, v2, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :goto_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
