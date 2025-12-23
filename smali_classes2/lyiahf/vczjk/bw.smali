.class public Llyiahf/vczjk/bw;
.super Llyiahf/vczjk/ph;
.source "SourceFile"


# instance fields
.field public final OooO0OO:Landroidx/databinding/ObservableBoolean;

.field public final OooO0Oo:Ljava/util/ArrayList;

.field public final OooO0o:Landroidx/databinding/ObservableInt;

.field public final OooO0o0:Landroidx/databinding/ObservableArrayList;


# direct methods
.method public constructor <init>(Landroid/app/Application;)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/ph;-><init>(Landroid/app/Application;)V

    new-instance p1, Landroidx/databinding/ObservableBoolean;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Landroidx/databinding/ObservableBoolean;-><init>(Z)V

    iput-object p1, p0, Llyiahf/vczjk/bw;->OooO0OO:Landroidx/databinding/ObservableBoolean;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bw;->OooO0Oo:Ljava/util/ArrayList;

    new-instance p1, Landroidx/databinding/ObservableArrayList;

    invoke-direct {p1}, Landroidx/databinding/ObservableArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bw;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    new-instance p1, Landroidx/databinding/ObservableInt;

    invoke-direct {p1, v0}, Landroidx/databinding/ObservableInt;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/bw;->OooO0o:Landroidx/databinding/ObservableInt;

    return-void
.end method


# virtual methods
.method public final OooO0Oo()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/bw;->OooO0Oo:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/oO00Oo00;

    const/16 v2, 0xa

    invoke-direct {v1, v2}, Llyiahf/vczjk/oO00Oo00;-><init>(I)V

    invoke-static {v0, v1}, Lutil/CollectionUtils;->consumeRemaining(Ljava/util/Collection;Lutil/Consumer;)V

    return-void
.end method

.method public final OooO0o(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/bw;->OooO0OO:Landroidx/databinding/ObservableBoolean;

    invoke-virtual {v0}, Landroidx/databinding/ObservableBoolean;->get()Z

    move-result v1

    if-eqz v1, :cond_0

    return-void

    :cond_0
    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroidx/databinding/ObservableBoolean;->set(Z)V

    iget-object v0, p0, Llyiahf/vczjk/bw;->OooO0Oo:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/s0;

    const/4 v2, 0x5

    invoke-direct {v1, v2, p0, p1}, Llyiahf/vczjk/s0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/lp8;

    const/4 v2, 0x0

    invoke-direct {p1, v1, v2}, Llyiahf/vczjk/lp8;-><init>(Ljava/lang/Object;I)V

    new-instance v1, Llyiahf/vczjk/oOO0O00O;

    const/16 v2, 0x10

    invoke-direct {v1, v2}, Llyiahf/vczjk/oOO0O00O;-><init>(I)V

    new-instance v2, Llyiahf/vczjk/qp8;

    invoke-direct {v2, p1, v1}, Llyiahf/vczjk/qp8;-><init>(Llyiahf/vczjk/jp8;Llyiahf/vczjk/af3;)V

    sget-object p1, Llyiahf/vczjk/s88;->OooO0OO:Llyiahf/vczjk/i88;

    invoke-virtual {v2, p1}, Llyiahf/vczjk/o76;->OooO0o(Llyiahf/vczjk/i88;)Llyiahf/vczjk/u76;

    move-result-object p1

    invoke-static {}, Llyiahf/vczjk/wf;->OooO00o()Llyiahf/vczjk/i88;

    move-result-object v1

    invoke-virtual {p1, v1}, Llyiahf/vczjk/o76;->OooO0O0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/c86;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/uv;

    invoke-direct {v1, p0}, Llyiahf/vczjk/uv;-><init>(Llyiahf/vczjk/bw;)V

    sget-object v2, Llyiahf/vczjk/v34;->OooO0Oo:Llyiahf/vczjk/up3;

    new-instance v3, Llyiahf/vczjk/v76;

    invoke-direct {v3, p1, v1, v2}, Llyiahf/vczjk/v76;-><init>(Llyiahf/vczjk/o76;Llyiahf/vczjk/nl1;Llyiahf/vczjk/o0oo0000;)V

    iget-object p1, p0, Llyiahf/vczjk/bw;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v1, Llyiahf/vczjk/vv;

    const/4 v2, 0x0

    invoke-direct {v1, p1, v2}, Llyiahf/vczjk/vv;-><init>(Landroidx/databinding/ObservableArrayList;I)V

    sget-object p1, Lgithub/tornaco/android/thanos/core/util/Rxs;->ON_ERROR_LOGGING:Llyiahf/vczjk/nl1;

    new-instance v2, Llyiahf/vczjk/uv;

    invoke-direct {v2, p0}, Llyiahf/vczjk/uv;-><init>(Llyiahf/vczjk/bw;)V

    invoke-virtual {v3, v1, p1, v2}, Llyiahf/vczjk/o76;->OooO0OO(Llyiahf/vczjk/nl1;Llyiahf/vczjk/nl1;Llyiahf/vczjk/o0oo0000;)Llyiahf/vczjk/sm4;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method
