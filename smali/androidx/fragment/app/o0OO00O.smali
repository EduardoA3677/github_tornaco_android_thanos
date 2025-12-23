.class public final Landroidx/fragment/app/o0OO00O;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/om3;
.implements Llyiahf/vczjk/h68;
.implements Llyiahf/vczjk/lha;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/kha;

.field public final OooOOO0:Landroidx/fragment/app/Oooo0;

.field public final OooOOOO:Landroidx/fragment/app/OooOOOO;

.field public OooOOOo:Llyiahf/vczjk/hha;

.field public OooOOo:Llyiahf/vczjk/f68;

.field public OooOOo0:Llyiahf/vczjk/wy4;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/Oooo0;Llyiahf/vczjk/kha;Landroidx/fragment/app/OooOOOO;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-object v0, p0, Landroidx/fragment/app/o0OO00O;->OooOOo0:Llyiahf/vczjk/wy4;

    iput-object v0, p0, Landroidx/fragment/app/o0OO00O;->OooOOo:Llyiahf/vczjk/f68;

    iput-object p1, p0, Landroidx/fragment/app/o0OO00O;->OooOOO0:Landroidx/fragment/app/Oooo0;

    iput-object p2, p0, Landroidx/fragment/app/o0OO00O;->OooOOO:Llyiahf/vczjk/kha;

    iput-object p3, p0, Landroidx/fragment/app/o0OO00O;->OooOOOO:Landroidx/fragment/app/OooOOOO;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/iy4;)V
    .locals 1

    iget-object v0, p0, Landroidx/fragment/app/o0OO00O;->OooOOo0:Llyiahf/vczjk/wy4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/wy4;->OooO0o(Llyiahf/vczjk/iy4;)V

    return-void
.end method

.method public final OooO0OO()V
    .locals 3

    iget-object v0, p0, Landroidx/fragment/app/o0OO00O;->OooOOo0:Llyiahf/vczjk/wy4;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/wy4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/wy4;-><init>(Llyiahf/vczjk/uy4;)V

    iput-object v0, p0, Landroidx/fragment/app/o0OO00O;->OooOOo0:Llyiahf/vczjk/wy4;

    new-instance v0, Llyiahf/vczjk/g68;

    new-instance v1, Llyiahf/vczjk/ku7;

    const/4 v2, 0x4

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/ku7;-><init>(Ljava/lang/Object;I)V

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/g68;-><init>(Llyiahf/vczjk/h68;Llyiahf/vczjk/ku7;)V

    new-instance v1, Llyiahf/vczjk/f68;

    invoke-direct {v1, v0}, Llyiahf/vczjk/f68;-><init>(Llyiahf/vczjk/g68;)V

    iput-object v1, p0, Landroidx/fragment/app/o0OO00O;->OooOOo:Llyiahf/vczjk/f68;

    invoke-virtual {v0}, Llyiahf/vczjk/g68;->OooO00o()V

    iget-object v0, p0, Landroidx/fragment/app/o0OO00O;->OooOOOO:Landroidx/fragment/app/OooOOOO;

    invoke-virtual {v0}, Landroidx/fragment/app/OooOOOO;->run()V

    :cond_0
    return-void
.end method

.method public final getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;
    .locals 5

    iget-object v0, p0, Landroidx/fragment/app/o0OO00O;->OooOOO0:Landroidx/fragment/app/Oooo0;

    invoke-virtual {v0}, Landroidx/fragment/app/Oooo0;->requireContext()Landroid/content/Context;

    move-result-object v1

    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    :goto_0
    instance-of v2, v1, Landroid/content/ContextWrapper;

    if-eqz v2, :cond_1

    instance-of v2, v1, Landroid/app/Application;

    if-eqz v2, :cond_0

    check-cast v1, Landroid/app/Application;

    goto :goto_1

    :cond_0
    check-cast v1, Landroid/content/ContextWrapper;

    invoke-virtual {v1}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    move-result-object v1

    goto :goto_0

    :cond_1
    const/4 v1, 0x0

    :goto_1
    new-instance v2, Llyiahf/vczjk/ir5;

    const/4 v3, 0x0

    invoke-direct {v2, v3}, Llyiahf/vczjk/ir5;-><init>(I)V

    iget-object v3, v2, Llyiahf/vczjk/os1;->OooO00o:Ljava/util/LinkedHashMap;

    if-eqz v1, :cond_2

    sget-object v4, Llyiahf/vczjk/gha;->OooO0Oo:Llyiahf/vczjk/xj0;

    invoke-interface {v3, v4, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_2
    sget-object v1, Llyiahf/vczjk/jp8;->OooOOOO:Llyiahf/vczjk/xj0;

    invoke-interface {v3, v1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/jp8;->OooOOOo:Llyiahf/vczjk/uk2;

    invoke-interface {v3, v1, p0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v0}, Landroidx/fragment/app/Oooo0;->getArguments()Landroid/os/Bundle;

    move-result-object v1

    if-eqz v1, :cond_3

    sget-object v1, Llyiahf/vczjk/jp8;->OooOOo0:Llyiahf/vczjk/op3;

    invoke-virtual {v0}, Landroidx/fragment/app/Oooo0;->getArguments()Landroid/os/Bundle;

    move-result-object v0

    invoke-interface {v3, v1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_3
    return-object v2
.end method

.method public final getDefaultViewModelProviderFactory()Llyiahf/vczjk/hha;
    .locals 4

    iget-object v0, p0, Landroidx/fragment/app/o0OO00O;->OooOOO0:Landroidx/fragment/app/Oooo0;

    invoke-virtual {v0}, Landroidx/fragment/app/Oooo0;->getDefaultViewModelProviderFactory()Llyiahf/vczjk/hha;

    move-result-object v1

    iget-object v2, v0, Landroidx/fragment/app/Oooo0;->mDefaultFactory:Llyiahf/vczjk/hha;

    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_0

    iput-object v1, p0, Landroidx/fragment/app/o0OO00O;->OooOOOo:Llyiahf/vczjk/hha;

    return-object v1

    :cond_0
    iget-object v1, p0, Landroidx/fragment/app/o0OO00O;->OooOOOo:Llyiahf/vczjk/hha;

    if-nez v1, :cond_3

    invoke-virtual {v0}, Landroidx/fragment/app/Oooo0;->requireContext()Landroid/content/Context;

    move-result-object v1

    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    :goto_0
    instance-of v2, v1, Landroid/content/ContextWrapper;

    if-eqz v2, :cond_2

    instance-of v2, v1, Landroid/app/Application;

    if-eqz v2, :cond_1

    check-cast v1, Landroid/app/Application;

    goto :goto_1

    :cond_1
    check-cast v1, Landroid/content/ContextWrapper;

    invoke-virtual {v1}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    move-result-object v1

    goto :goto_0

    :cond_2
    const/4 v1, 0x0

    :goto_1
    new-instance v2, Llyiahf/vczjk/i68;

    invoke-virtual {v0}, Landroidx/fragment/app/Oooo0;->getArguments()Landroid/os/Bundle;

    move-result-object v3

    invoke-direct {v2, v1, v0, v3}, Llyiahf/vczjk/i68;-><init>(Landroid/app/Application;Llyiahf/vczjk/h68;Landroid/os/Bundle;)V

    iput-object v2, p0, Landroidx/fragment/app/o0OO00O;->OooOOOo:Llyiahf/vczjk/hha;

    :cond_3
    iget-object v0, p0, Landroidx/fragment/app/o0OO00O;->OooOOOo:Llyiahf/vczjk/hha;

    return-object v0
.end method

.method public final getLifecycle()Llyiahf/vczjk/ky4;
    .locals 1

    invoke-virtual {p0}, Landroidx/fragment/app/o0OO00O;->OooO0OO()V

    iget-object v0, p0, Landroidx/fragment/app/o0OO00O;->OooOOo0:Llyiahf/vczjk/wy4;

    return-object v0
.end method

.method public final getSavedStateRegistry()Llyiahf/vczjk/e68;
    .locals 1

    invoke-virtual {p0}, Landroidx/fragment/app/o0OO00O;->OooO0OO()V

    iget-object v0, p0, Landroidx/fragment/app/o0OO00O;->OooOOo:Llyiahf/vczjk/f68;

    iget-object v0, v0, Llyiahf/vczjk/f68;->OooO0O0:Llyiahf/vczjk/e68;

    return-object v0
.end method

.method public final getViewModelStore()Llyiahf/vczjk/kha;
    .locals 1

    invoke-virtual {p0}, Landroidx/fragment/app/o0OO00O;->OooO0OO()V

    iget-object v0, p0, Landroidx/fragment/app/o0OO00O;->OooOOO:Llyiahf/vczjk/kha;

    return-object v0
.end method
