.class public final Llyiahf/vczjk/r36;
.super Llyiahf/vczjk/jha;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/hha;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/e68;

.field public final OooO0O0:Llyiahf/vczjk/ky4;

.field public final synthetic OooO0OO:Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;


# direct methods
.method public constructor <init>(Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;Llyiahf/vczjk/h68;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/r36;->OooO0OO:Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;

    invoke-interface {p2}, Llyiahf/vczjk/h68;->getSavedStateRegistry()Llyiahf/vczjk/e68;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/r36;->OooO00o:Llyiahf/vczjk/e68;

    invoke-interface {p2}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/r36;->OooO0O0:Llyiahf/vczjk/ky4;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/dha;
    .locals 4

    invoke-virtual {p1}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/r36;->OooO0O0:Llyiahf/vczjk/ky4;

    if-eqz v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/r36;->OooO00o:Llyiahf/vczjk/e68;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v2, p0, Llyiahf/vczjk/r36;->OooO0O0:Llyiahf/vczjk/ky4;

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const/4 v3, 0x0

    invoke-static {v1, v2, v0, v3}, Llyiahf/vczjk/t51;->OooOo0o(Llyiahf/vczjk/e68;Llyiahf/vczjk/ky4;Ljava/lang/String;Landroid/os/Bundle;)Llyiahf/vczjk/y58;

    move-result-object v1

    iget-object v2, v1, Llyiahf/vczjk/y58;->OooOOO:Llyiahf/vczjk/x58;

    invoke-virtual {p0, v0, p1, v2}, Llyiahf/vczjk/r36;->OooO0o0(Ljava/lang/String;Ljava/lang/Class;Llyiahf/vczjk/x58;)Llyiahf/vczjk/l46;

    move-result-object p1

    const-string v0, "androidx.lifecycle.savedstate.vm.tag"

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/dha;->OooO00o(Ljava/lang/String;Ljava/lang/AutoCloseable;)V

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string v0, "AbstractSavedStateViewModelFactory constructed with empty constructor supports only calls to create(modelClass: Class<T>, extras: CreationExtras)."

    invoke-direct {p1, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Local and anonymous classes can not be ViewModels"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ir5;)Llyiahf/vczjk/dha;
    .locals 3

    sget-object v0, Llyiahf/vczjk/tg7;->OooOOOO:Llyiahf/vczjk/op3;

    iget-object v1, p2, Llyiahf/vczjk/os1;->OooO00o:Ljava/util/LinkedHashMap;

    invoke-virtual {v1, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/r36;->OooO00o:Llyiahf/vczjk/e68;

    if-eqz v1, :cond_0

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/r36;->OooO0O0:Llyiahf/vczjk/ky4;

    invoke-static {p2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const/4 v2, 0x0

    invoke-static {v1, p2, v0, v2}, Llyiahf/vczjk/t51;->OooOo0o(Llyiahf/vczjk/e68;Llyiahf/vczjk/ky4;Ljava/lang/String;Landroid/os/Bundle;)Llyiahf/vczjk/y58;

    move-result-object p2

    iget-object v1, p2, Llyiahf/vczjk/y58;->OooOOO:Llyiahf/vczjk/x58;

    invoke-virtual {p0, v0, p1, v1}, Llyiahf/vczjk/r36;->OooO0o0(Ljava/lang/String;Ljava/lang/Class;Llyiahf/vczjk/x58;)Llyiahf/vczjk/l46;

    move-result-object p1

    const-string v0, "androidx.lifecycle.savedstate.vm.tag"

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/dha;->OooO00o(Ljava/lang/String;Ljava/lang/AutoCloseable;)V

    return-object p1

    :cond_0
    invoke-static {p2}, Llyiahf/vczjk/jp8;->OooOOoo(Llyiahf/vczjk/os1;)Llyiahf/vczjk/x58;

    move-result-object p2

    invoke-virtual {p0, v0, p1, p2}, Llyiahf/vczjk/r36;->OooO0o0(Ljava/lang/String;Ljava/lang/Class;Llyiahf/vczjk/x58;)Llyiahf/vczjk/l46;

    move-result-object p1

    return-object p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "VIEW_MODEL_KEY must always be provided by ViewModelProvider"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/dha;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/r36;->OooO00o:Llyiahf/vczjk/e68;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/r36;->OooO0O0:Llyiahf/vczjk/ky4;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/t51;->OooOOOO(Llyiahf/vczjk/dha;Llyiahf/vczjk/e68;Llyiahf/vczjk/ky4;)V

    :cond_0
    return-void
.end method

.method public final OooO0o0(Ljava/lang/String;Ljava/lang/Class;Llyiahf/vczjk/x58;)Llyiahf/vczjk/l46;
    .locals 1

    new-instance p1, Llyiahf/vczjk/g46;

    iget-object p2, p0, Llyiahf/vczjk/r36;->OooO0OO:Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;

    invoke-virtual {p2}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p2

    const-string v0, "getApplicationContext(...)"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p1, p2}, Llyiahf/vczjk/g46;-><init>(Landroid/content/Context;)V

    new-instance p2, Llyiahf/vczjk/l46;

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/l46;-><init>(Llyiahf/vczjk/x58;Llyiahf/vczjk/g46;)V

    return-object p2
.end method
