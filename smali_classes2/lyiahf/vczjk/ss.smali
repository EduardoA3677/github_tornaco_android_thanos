.class public final synthetic Llyiahf/vczjk/ss;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Lnow/fortuitous/thanos/apps/AppDetailsActivity;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Lnow/fortuitous/thanos/apps/AppDetailsActivity;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ss;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ss;->OooOOO:Lnow/fortuitous/thanos/apps/AppDetailsActivity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    const/4 v0, 0x3

    const-string v1, "app"

    const-string v2, "pickedFile"

    const/4 v3, 0x0

    iget v4, p0, Llyiahf/vczjk/ss;->OooOOO0:I

    check-cast p1, Ljava/lang/Integer;

    packed-switch v4, :pswitch_data_0

    check-cast p2, Ljava/util/List;

    sget p1, Lnow/fortuitous/thanos/apps/AppDetailsActivity;->OoooO0O:I

    iget-object v6, p0, Llyiahf/vczjk/ss;->OooOOO:Lnow/fortuitous/thanos/apps/AppDetailsActivity;

    if-eqz p2, :cond_1

    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    invoke-interface {p2, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/jd2;

    iget-object p1, v6, Lnow/fortuitous/thanos/apps/AppDetailsActivity;->OoooO00:Llyiahf/vczjk/dl5;

    invoke-virtual {p1}, Llyiahf/vczjk/dl5;->OooO0OO()V

    invoke-static {v6}, Lnow/fortuitous/thanos/apps/AppDetailsActivity;->OooOoOO(Landroidx/fragment/app/FragmentActivity;)Llyiahf/vczjk/jt;

    move-result-object p1

    new-instance v7, Llyiahf/vczjk/us;

    invoke-direct {v7, v6}, Llyiahf/vczjk/us;-><init>(Lnow/fortuitous/thanos/apps/AppDetailsActivity;)V

    iget-object v8, v6, Lnow/fortuitous/thanos/apps/AppDetailsActivity;->Oooo0oo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v5, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v8, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v4, Llyiahf/vczjk/ht;

    const/4 v9, 0x0

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/ht;-><init>(Llyiahf/vczjk/jd2;Landroid/content/Context;Llyiahf/vczjk/ws;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v3, v3, v4, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_1
    :goto_0
    return-object v3

    :pswitch_0
    move-object v5, p2

    check-cast v5, Llyiahf/vczjk/jd2;

    iget-object v6, p0, Llyiahf/vczjk/ss;->OooOOO:Lnow/fortuitous/thanos/apps/AppDetailsActivity;

    iget-object p1, v6, Lnow/fortuitous/thanos/apps/AppDetailsActivity;->OoooO00:Llyiahf/vczjk/dl5;

    invoke-virtual {p1}, Llyiahf/vczjk/dl5;->OooO0OO()V

    invoke-static {v6}, Lnow/fortuitous/thanos/apps/AppDetailsActivity;->OooOoOO(Landroidx/fragment/app/FragmentActivity;)Llyiahf/vczjk/jt;

    move-result-object p1

    new-instance v7, Llyiahf/vczjk/vz5;

    const/4 p2, 0x5

    invoke-direct {v7, v6, p2}, Llyiahf/vczjk/vz5;-><init>(Ljava/lang/Object;I)V

    iget-object v8, v6, Lnow/fortuitous/thanos/apps/AppDetailsActivity;->Oooo0oo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v5, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v8, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v4, Llyiahf/vczjk/bt;

    const/4 v9, 0x0

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/bt;-><init>(Llyiahf/vczjk/jd2;Landroid/content/Context;Llyiahf/vczjk/vs;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v3, v3, v4, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-object v3

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
