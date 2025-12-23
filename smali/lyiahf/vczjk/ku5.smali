.class public final Llyiahf/vczjk/ku5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/uy4;
.implements Llyiahf/vczjk/lha;
.implements Llyiahf/vczjk/om3;
.implements Llyiahf/vczjk/h68;


# instance fields
.field public OooOOO:Llyiahf/vczjk/av5;

.field public final OooOOO0:Llyiahf/vczjk/ax;

.field public final OooOOOO:Landroid/os/Bundle;

.field public final OooOOOo:Llyiahf/vczjk/jy4;

.field public final OooOOo:Ljava/lang/String;

.field public final OooOOo0:Llyiahf/vczjk/tu5;

.field public final OooOOoo:Landroid/os/Bundle;

.field public final OooOo00:Llyiahf/vczjk/mu5;


# direct methods
.method static constructor <clinit>()V
    .locals 0

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ax;Llyiahf/vczjk/av5;Landroid/os/Bundle;Llyiahf/vczjk/jy4;Llyiahf/vczjk/tu5;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ku5;->OooOOO0:Llyiahf/vczjk/ax;

    iput-object p2, p0, Llyiahf/vczjk/ku5;->OooOOO:Llyiahf/vczjk/av5;

    iput-object p3, p0, Llyiahf/vczjk/ku5;->OooOOOO:Landroid/os/Bundle;

    iput-object p4, p0, Llyiahf/vczjk/ku5;->OooOOOo:Llyiahf/vczjk/jy4;

    iput-object p5, p0, Llyiahf/vczjk/ku5;->OooOOo0:Llyiahf/vczjk/tu5;

    iput-object p6, p0, Llyiahf/vczjk/ku5;->OooOOo:Ljava/lang/String;

    iput-object p7, p0, Llyiahf/vczjk/ku5;->OooOOoo:Landroid/os/Bundle;

    new-instance p1, Llyiahf/vczjk/mu5;

    invoke-direct {p1, p0}, Llyiahf/vczjk/mu5;-><init>(Llyiahf/vczjk/ku5;)V

    iput-object p1, p0, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    new-instance p1, Llyiahf/vczjk/fz3;

    const/16 p2, 0xa

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/fz3;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/jy4;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iput-object p1, v0, Llyiahf/vczjk/mu5;->OooOO0O:Llyiahf/vczjk/jy4;

    invoke-virtual {v0}, Llyiahf/vczjk/mu5;->OooO0O0()V

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 5

    const/4 v0, 0x0

    if-eqz p1, :cond_5

    instance-of v1, p1, Llyiahf/vczjk/ku5;

    if-nez v1, :cond_0

    goto/16 :goto_2

    :cond_0
    check-cast p1, Llyiahf/vczjk/ku5;

    iget-object v1, p1, Llyiahf/vczjk/ku5;->OooOOo:Ljava/lang/String;

    iget-object v2, p0, Llyiahf/vczjk/ku5;->OooOOo:Ljava/lang/String;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_5

    iget-object v1, p0, Llyiahf/vczjk/ku5;->OooOOO:Llyiahf/vczjk/av5;

    iget-object v2, p1, Llyiahf/vczjk/ku5;->OooOOO:Llyiahf/vczjk/av5;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_5

    iget-object v1, p0, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    iget-object v1, v1, Llyiahf/vczjk/mu5;->OooOO0:Llyiahf/vczjk/wy4;

    iget-object v2, p1, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    iget-object v2, v2, Llyiahf/vczjk/mu5;->OooOO0:Llyiahf/vczjk/wy4;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_5

    invoke-virtual {p0}, Llyiahf/vczjk/ku5;->getSavedStateRegistry()Llyiahf/vczjk/e68;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/ku5;->getSavedStateRegistry()Llyiahf/vczjk/e68;

    move-result-object v2

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_5

    iget-object v1, p0, Llyiahf/vczjk/ku5;->OooOOOO:Landroid/os/Bundle;

    iget-object p1, p1, Llyiahf/vczjk/ku5;->OooOOOO:Landroid/os/Bundle;

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_4

    if-eqz v1, :cond_5

    invoke-virtual {v1}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    move-result-object v2

    if-eqz v2, :cond_5

    check-cast v2, Ljava/lang/Iterable;

    instance-of v3, v2, Ljava/util/Collection;

    if-eqz v3, :cond_1

    move-object v3, v2

    check-cast v3, Ljava/util/Collection;

    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_1

    goto :goto_1

    :cond_1
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    invoke-virtual {v1, v3}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v4

    if-eqz p1, :cond_3

    invoke-virtual {p1, v3}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v3

    goto :goto_0

    :cond_3
    const/4 v3, 0x0

    :goto_0
    invoke-static {v4, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_2

    goto :goto_2

    :cond_4
    :goto_1
    const/4 p1, 0x1

    return p1

    :cond_5
    :goto_2
    return v0
.end method

.method public final getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/ir5;

    const/4 v2, 0x0

    invoke-direct {v1, v2}, Llyiahf/vczjk/ir5;-><init>(I)V

    sget-object v2, Llyiahf/vczjk/jp8;->OooOOOO:Llyiahf/vczjk/xj0;

    iget-object v3, v1, Llyiahf/vczjk/os1;->OooO00o:Ljava/util/LinkedHashMap;

    iget-object v4, v0, Llyiahf/vczjk/mu5;->OooO00o:Llyiahf/vczjk/ku5;

    invoke-interface {v3, v2, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v2, Llyiahf/vczjk/jp8;->OooOOOo:Llyiahf/vczjk/uk2;

    invoke-interface {v3, v2, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v0}, Llyiahf/vczjk/mu5;->OooO00o()Landroid/os/Bundle;

    move-result-object v0

    if-eqz v0, :cond_0

    sget-object v2, Llyiahf/vczjk/jp8;->OooOOo0:Llyiahf/vczjk/op3;

    invoke-interface {v3, v2, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    const/4 v0, 0x0

    iget-object v2, p0, Llyiahf/vczjk/ku5;->OooOOO0:Llyiahf/vczjk/ax;

    if-eqz v2, :cond_2

    iget-object v2, v2, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    if-eqz v2, :cond_1

    invoke-virtual {v2}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v2

    goto :goto_0

    :cond_1
    move-object v2, v0

    :goto_0
    instance-of v4, v2, Landroid/app/Application;

    if-eqz v4, :cond_2

    check-cast v2, Landroid/app/Application;

    goto :goto_1

    :cond_2
    move-object v2, v0

    :goto_1
    if-eqz v2, :cond_3

    move-object v0, v2

    :cond_3
    if-eqz v0, :cond_4

    sget-object v2, Llyiahf/vczjk/gha;->OooO0Oo:Llyiahf/vczjk/xj0;

    invoke-interface {v3, v2, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_4
    return-object v1
.end method

.method public final getDefaultViewModelProviderFactory()Llyiahf/vczjk/hha;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    iget-object v0, v0, Llyiahf/vczjk/mu5;->OooOO0o:Llyiahf/vczjk/i68;

    return-object v0
.end method

.method public final getLifecycle()Llyiahf/vczjk/ky4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    iget-object v0, v0, Llyiahf/vczjk/mu5;->OooOO0:Llyiahf/vczjk/wy4;

    return-object v0
.end method

.method public final getSavedStateRegistry()Llyiahf/vczjk/e68;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    iget-object v0, v0, Llyiahf/vczjk/mu5;->OooO0oo:Llyiahf/vczjk/f68;

    iget-object v0, v0, Llyiahf/vczjk/f68;->OooO0O0:Llyiahf/vczjk/e68;

    return-object v0
.end method

.method public final getViewModelStore()Llyiahf/vczjk/kha;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    iget-boolean v1, v0, Llyiahf/vczjk/mu5;->OooO:Z

    if-eqz v1, :cond_3

    iget-object v1, v0, Llyiahf/vczjk/mu5;->OooOO0:Llyiahf/vczjk/wy4;

    iget-object v1, v1, Llyiahf/vczjk/wy4;->OooO0Oo:Llyiahf/vczjk/jy4;

    sget-object v2, Llyiahf/vczjk/jy4;->OooOOO0:Llyiahf/vczjk/jy4;

    if-eq v1, v2, :cond_2

    iget-object v1, v0, Llyiahf/vczjk/mu5;->OooO0o0:Llyiahf/vczjk/tu5;

    if-eqz v1, :cond_1

    const-string v2, "backStackEntryId"

    iget-object v0, v0, Llyiahf/vczjk/mu5;->OooO0o:Ljava/lang/String;

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, v1, Llyiahf/vczjk/tu5;->OooO0O0:Ljava/util/LinkedHashMap;

    invoke-virtual {v1, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/kha;

    if-nez v2, :cond_0

    new-instance v2, Llyiahf/vczjk/kha;

    invoke-direct {v2}, Llyiahf/vczjk/kha;-><init>()V

    invoke-interface {v1, v0, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-object v2

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "You must call setViewModelStore() on your NavHostController before accessing the ViewModelStore of a navigation graph."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "You cannot access the NavBackStackEntry\'s ViewModels after the NavBackStackEntry is destroyed."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "You cannot access the NavBackStackEntry\'s ViewModels until it is added to the NavController\'s back stack (i.e., the Lifecycle of the NavBackStackEntry reaches the CREATED state)."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final hashCode()I
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ku5;->OooOOo:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    iget-object v1, p0, Llyiahf/vczjk/ku5;->OooOOO:Llyiahf/vczjk/av5;

    invoke-virtual {v1}, Llyiahf/vczjk/av5;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    iget-object v0, p0, Llyiahf/vczjk/ku5;->OooOOOO:Landroid/os/Bundle;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    move-result-object v2

    if-eqz v2, :cond_1

    check-cast v2, Ljava/lang/Iterable;

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    mul-int/lit8 v1, v1, 0x1f

    invoke-virtual {v0, v3}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v3

    if-eqz v3, :cond_0

    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    move-result v3

    goto :goto_1

    :cond_0
    const/4 v3, 0x0

    :goto_1
    add-int/2addr v1, v3

    goto :goto_0

    :cond_1
    mul-int/lit8 v1, v1, 0x1f

    iget-object v0, p0, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    iget-object v0, v0, Llyiahf/vczjk/mu5;->OooOO0:Llyiahf/vczjk/wy4;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    add-int/2addr v0, v1

    mul-int/lit8 v0, v0, 0x1f

    invoke-virtual {p0}, Llyiahf/vczjk/ku5;->getSavedStateRegistry()Llyiahf/vczjk/e68;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    invoke-virtual {v0}, Llyiahf/vczjk/mu5;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
