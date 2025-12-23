.class public final Llyiahf/vczjk/i68;
.super Llyiahf/vczjk/jha;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/hha;


# instance fields
.field public final OooO00o:Landroid/app/Application;

.field public final OooO0O0:Llyiahf/vczjk/gha;

.field public final OooO0OO:Landroid/os/Bundle;

.field public final OooO0Oo:Llyiahf/vczjk/ky4;

.field public final OooO0o0:Llyiahf/vczjk/e68;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/gha;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/gha;-><init>(Landroid/app/Application;)V

    iput-object v0, p0, Llyiahf/vczjk/i68;->OooO0O0:Llyiahf/vczjk/gha;

    return-void
.end method

.method public constructor <init>(Landroid/app/Application;Llyiahf/vczjk/h68;Landroid/os/Bundle;)V
    .locals 1

    const-string v0, "owner"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-interface {p2}, Llyiahf/vczjk/h68;->getSavedStateRegistry()Llyiahf/vczjk/e68;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/i68;->OooO0o0:Llyiahf/vczjk/e68;

    invoke-interface {p2}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/i68;->OooO0Oo:Llyiahf/vczjk/ky4;

    iput-object p3, p0, Llyiahf/vczjk/i68;->OooO0OO:Landroid/os/Bundle;

    iput-object p1, p0, Llyiahf/vczjk/i68;->OooO00o:Landroid/app/Application;

    if-eqz p1, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/vo6;->OooO0o(Landroid/app/Application;)Llyiahf/vczjk/gha;

    move-result-object p1

    goto :goto_0

    :cond_0
    new-instance p1, Llyiahf/vczjk/gha;

    const/4 p2, 0x0

    invoke-direct {p1, p2}, Llyiahf/vczjk/gha;-><init>(Landroid/app/Application;)V

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/i68;->OooO0O0:Llyiahf/vczjk/gha;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/dha;
    .locals 1

    invoke-virtual {p1}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/i68;->OooO0o0(Ljava/lang/Class;Ljava/lang/String;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Local and anonymous classes can not be ViewModels"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/gf4;Llyiahf/vczjk/ir5;)Llyiahf/vczjk/dha;
    .locals 1

    const-string v0, "modelClass"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/i68;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ir5;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ir5;)Llyiahf/vczjk/dha;
    .locals 3

    sget-object v0, Llyiahf/vczjk/tg7;->OooOOOO:Llyiahf/vczjk/op3;

    iget-object v1, p2, Llyiahf/vczjk/os1;->OooO00o:Ljava/util/LinkedHashMap;

    invoke-virtual {v1, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    if-eqz v0, :cond_5

    sget-object v2, Llyiahf/vczjk/jp8;->OooOOOO:Llyiahf/vczjk/xj0;

    invoke-virtual {v1, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_3

    sget-object v2, Llyiahf/vczjk/jp8;->OooOOOo:Llyiahf/vczjk/uk2;

    invoke-virtual {v1, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_3

    sget-object v0, Llyiahf/vczjk/gha;->OooO0Oo:Llyiahf/vczjk/xj0;

    invoke-virtual {v1, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/Application;

    const-class v1, Llyiahf/vczjk/ph;

    invoke-virtual {v1, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v1

    if-eqz v1, :cond_0

    if-eqz v0, :cond_0

    sget-object v2, Llyiahf/vczjk/j68;->OooO00o:Ljava/util/List;

    invoke-static {p1, v2}, Llyiahf/vczjk/j68;->OooO00o(Ljava/lang/Class;Ljava/util/List;)Ljava/lang/reflect/Constructor;

    move-result-object v2

    goto :goto_0

    :cond_0
    sget-object v2, Llyiahf/vczjk/j68;->OooO0O0:Ljava/util/List;

    invoke-static {p1, v2}, Llyiahf/vczjk/j68;->OooO00o(Ljava/lang/Class;Ljava/util/List;)Ljava/lang/reflect/Constructor;

    move-result-object v2

    :goto_0
    if-nez v2, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/i68;->OooO0O0:Llyiahf/vczjk/gha;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/gha;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ir5;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1

    :cond_1
    if-eqz v1, :cond_2

    if-eqz v0, :cond_2

    invoke-static {p2}, Llyiahf/vczjk/jp8;->OooOOoo(Llyiahf/vczjk/os1;)Llyiahf/vczjk/x58;

    move-result-object p2

    filled-new-array {v0, p2}, [Ljava/lang/Object;

    move-result-object p2

    invoke-static {p1, v2, p2}, Llyiahf/vczjk/j68;->OooO0O0(Ljava/lang/Class;Ljava/lang/reflect/Constructor;[Ljava/lang/Object;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/jp8;->OooOOoo(Llyiahf/vczjk/os1;)Llyiahf/vczjk/x58;

    move-result-object p2

    filled-new-array {p2}, [Ljava/lang/Object;

    move-result-object p2

    invoke-static {p1, v2, p2}, Llyiahf/vczjk/j68;->OooO0O0(Ljava/lang/Class;Ljava/lang/reflect/Constructor;[Ljava/lang/Object;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1

    :cond_3
    iget-object p2, p0, Llyiahf/vczjk/i68;->OooO0Oo:Llyiahf/vczjk/ky4;

    if-eqz p2, :cond_4

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/i68;->OooO0o0(Ljava/lang/Class;Ljava/lang/String;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1

    :cond_4
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "SAVED_STATE_REGISTRY_OWNER_KEY andVIEW_MODEL_STORE_OWNER_KEY must be provided in the creation extras tosuccessfully create a ViewModel."

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_5
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "VIEW_MODEL_KEY must always be provided by ViewModelProvider"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/dha;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/i68;->OooO0Oo:Llyiahf/vczjk/ky4;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/i68;->OooO0o0:Llyiahf/vczjk/e68;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {p1, v1, v0}, Llyiahf/vczjk/t51;->OooOOOO(Llyiahf/vczjk/dha;Llyiahf/vczjk/e68;Llyiahf/vczjk/ky4;)V

    :cond_0
    return-void
.end method

.method public final OooO0o0(Ljava/lang/Class;Ljava/lang/String;)Llyiahf/vczjk/dha;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/i68;->OooO0Oo:Llyiahf/vczjk/ky4;

    if-eqz v0, :cond_5

    const-class v1, Llyiahf/vczjk/ph;

    invoke-virtual {v1, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/i68;->OooO00o:Landroid/app/Application;

    if-eqz v1, :cond_0

    if-eqz v2, :cond_0

    sget-object v3, Llyiahf/vczjk/j68;->OooO00o:Ljava/util/List;

    invoke-static {p1, v3}, Llyiahf/vczjk/j68;->OooO00o(Ljava/lang/Class;Ljava/util/List;)Ljava/lang/reflect/Constructor;

    move-result-object v3

    goto :goto_0

    :cond_0
    sget-object v3, Llyiahf/vczjk/j68;->OooO0O0:Ljava/util/List;

    invoke-static {p1, v3}, Llyiahf/vczjk/j68;->OooO00o(Ljava/lang/Class;Ljava/util/List;)Ljava/lang/reflect/Constructor;

    move-result-object v3

    :goto_0
    if-nez v3, :cond_3

    if-eqz v2, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/i68;->OooO0O0:Llyiahf/vczjk/gha;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/gha;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1

    :cond_1
    sget-object p2, Llyiahf/vczjk/iha;->OooO00o:Llyiahf/vczjk/iha;

    if-nez p2, :cond_2

    new-instance p2, Llyiahf/vczjk/iha;

    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    sput-object p2, Llyiahf/vczjk/iha;->OooO00o:Llyiahf/vczjk/iha;

    :cond_2
    sget-object p2, Llyiahf/vczjk/iha;->OooO00o:Llyiahf/vczjk/iha;

    invoke-static {p2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooOOOo(Ljava/lang/Class;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1

    :cond_3
    iget-object v4, p0, Llyiahf/vczjk/i68;->OooO0o0:Llyiahf/vczjk/e68;

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v5, p0, Llyiahf/vczjk/i68;->OooO0OO:Landroid/os/Bundle;

    invoke-static {v4, v0, p2, v5}, Llyiahf/vczjk/t51;->OooOo0o(Llyiahf/vczjk/e68;Llyiahf/vczjk/ky4;Ljava/lang/String;Landroid/os/Bundle;)Llyiahf/vczjk/y58;

    move-result-object p2

    iget-object v0, p2, Llyiahf/vczjk/y58;->OooOOO:Llyiahf/vczjk/x58;

    if-eqz v1, :cond_4

    if-eqz v2, :cond_4

    filled-new-array {v2, v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {p1, v3, v0}, Llyiahf/vczjk/j68;->OooO0O0(Ljava/lang/Class;Ljava/lang/reflect/Constructor;[Ljava/lang/Object;)Llyiahf/vczjk/dha;

    move-result-object p1

    goto :goto_1

    :cond_4
    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {p1, v3, v0}, Llyiahf/vczjk/j68;->OooO0O0(Ljava/lang/Class;Ljava/lang/reflect/Constructor;[Ljava/lang/Object;)Llyiahf/vczjk/dha;

    move-result-object p1

    :goto_1
    const-string v0, "androidx.lifecycle.savedstate.vm.tag"

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/dha;->OooO00o(Ljava/lang/String;Ljava/lang/AutoCloseable;)V

    return-object p1

    :cond_5
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "SavedStateViewModelFactory constructed with empty constructor supports only calls to create(modelClass: Class<T>, extras: CreationExtras)."

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
