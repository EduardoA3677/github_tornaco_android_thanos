.class public Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;
.super Llyiahf/vczjk/ph;
.source "SourceFile"


# instance fields
.field public final OooO0OO:Landroidx/databinding/ObservableBoolean;

.field public final OooO0Oo:Ljava/util/ArrayList;

.field public final OooO0o:Landroidx/databinding/ObservableField;

.field public final OooO0o0:Landroidx/databinding/ObservableArrayList;

.field public final OooO0oO:Llyiahf/vczjk/hu;

.field public final OooO0oo:Llyiahf/vczjk/wx9;


# direct methods
.method public constructor <init>(Landroid/app/Application;)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/ph;-><init>(Landroid/app/Application;)V

    new-instance p1, Landroidx/databinding/ObservableBoolean;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Landroidx/databinding/ObservableBoolean;-><init>(Z)V

    iput-object p1, p0, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0OO:Landroidx/databinding/ObservableBoolean;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0Oo:Ljava/util/ArrayList;

    new-instance p1, Landroidx/databinding/ObservableArrayList;

    invoke-direct {p1}, Landroidx/databinding/ObservableArrayList;-><init>()V

    iput-object p1, p0, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    new-instance p1, Landroidx/databinding/ObservableField;

    const-string v0, ""

    invoke-direct {p1, v0}, Landroidx/databinding/ObservableField;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0o:Landroidx/databinding/ObservableField;

    new-instance p1, Llyiahf/vczjk/hu;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0oO:Llyiahf/vczjk/hu;

    new-instance p1, Llyiahf/vczjk/wx9;

    const/4 v0, 0x0

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/wx9;-><init>(Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;I)V

    iput-object p1, p0, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0oo:Llyiahf/vczjk/wx9;

    return-void
.end method

.method public static OooO0oO(Ljava/lang/String;)Ljava/util/List;
    .locals 2

    :try_start_0
    sget-object v0, Lgithub/tornaco/android/thanos/core/util/GsonUtils;->GSON:Llyiahf/vczjk/nk3;

    new-instance v1, Lgithub/tornaco/android/thanox/module/activity/trampoline/TrampolineViewModel$1;

    invoke-direct {v1}, Lcom/google/gson/reflect/TypeToken;-><init>()V

    invoke-virtual {v1}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    move-result-object v1

    invoke-virtual {v0, p0, v1}, Llyiahf/vczjk/nk3;->OooO0Oo(Ljava/lang/String;Ljava/lang/reflect/Type;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/util/List;

    invoke-static {p0}, Lutil/CollectionUtils;->isNullOrEmpty(Ljava/util/Collection;)Z

    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez v0, :cond_0

    return-object p0

    :catchall_0
    move-exception p0

    invoke-static {p0}, Llyiahf/vczjk/zsa;->Oooo0oO(Ljava/lang/Throwable;)V

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method


# virtual methods
.method public final OooO0Oo()V
    .locals 3

    iget-object v0, p0, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0Oo:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/oO00Oo00;

    const/16 v2, 0xa

    invoke-direct {v1, v2}, Llyiahf/vczjk/oO00Oo00;-><init>(I)V

    invoke-static {v0, v1}, Lutil/CollectionUtils;->consumeRemaining(Ljava/util/Collection;Lutil/Consumer;)V

    return-void
.end method

.method public final OooO0o()V
    .locals 6

    iget-object v0, p0, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0OO:Landroidx/databinding/ObservableBoolean;

    invoke-virtual {v0}, Landroidx/databinding/ObservableBoolean;->get()Z

    move-result v1

    if-eqz v1, :cond_0

    return-void

    :cond_0
    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroidx/databinding/ObservableBoolean;->set(Z)V

    iget-object v0, p0, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0Oo:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/wx9;

    const/4 v2, 0x3

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/wx9;-><init>(Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;I)V

    new-instance v2, Llyiahf/vczjk/lp8;

    const/4 v3, 0x0

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/lp8;-><init>(Ljava/lang/Object;I)V

    new-instance v1, Llyiahf/vczjk/oOO0O00O;

    const/16 v3, 0x10

    invoke-direct {v1, v3}, Llyiahf/vczjk/oOO0O00O;-><init>(I)V

    new-instance v3, Llyiahf/vczjk/qp8;

    invoke-direct {v3, v2, v1}, Llyiahf/vczjk/qp8;-><init>(Llyiahf/vczjk/jp8;Llyiahf/vczjk/af3;)V

    new-instance v1, Llyiahf/vczjk/wx9;

    const/4 v2, 0x4

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/wx9;-><init>(Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;I)V

    new-instance v2, Llyiahf/vczjk/u76;

    const/4 v4, 0x1

    invoke-direct {v2, v3, v1, v4}, Llyiahf/vczjk/u76;-><init>(Llyiahf/vczjk/o76;Ljava/lang/Object;I)V

    sget-object v1, Llyiahf/vczjk/s88;->OooO0OO:Llyiahf/vczjk/i88;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/o76;->OooO0o(Llyiahf/vczjk/i88;)Llyiahf/vczjk/u76;

    move-result-object v1

    invoke-static {}, Llyiahf/vczjk/wf;->OooO00o()Llyiahf/vczjk/i88;

    move-result-object v2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/o76;->OooO0O0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/c86;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/wx9;

    const/4 v3, 0x5

    invoke-direct {v2, p0, v3}, Llyiahf/vczjk/wx9;-><init>(Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;I)V

    sget-object v3, Llyiahf/vczjk/v34;->OooO0Oo:Llyiahf/vczjk/up3;

    new-instance v4, Llyiahf/vczjk/v76;

    invoke-direct {v4, v1, v2, v3}, Llyiahf/vczjk/v76;-><init>(Llyiahf/vczjk/o76;Llyiahf/vczjk/nl1;Llyiahf/vczjk/o0oo0000;)V

    iget-object v1, p0, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v2, Llyiahf/vczjk/vv;

    const/4 v3, 0x5

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/vv;-><init>(Landroidx/databinding/ObservableArrayList;I)V

    sget-object v1, Lgithub/tornaco/android/thanos/core/util/Rxs;->ON_ERROR_LOGGING:Llyiahf/vczjk/nl1;

    new-instance v3, Llyiahf/vczjk/wx9;

    const/4 v5, 0x6

    invoke-direct {v3, p0, v5}, Llyiahf/vczjk/wx9;-><init>(Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;I)V

    invoke-virtual {v4, v2, v1, v3}, Llyiahf/vczjk/o76;->OooO0OO(Llyiahf/vczjk/nl1;Llyiahf/vczjk/nl1;Llyiahf/vczjk/o0oo0000;)Llyiahf/vczjk/sm4;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method
