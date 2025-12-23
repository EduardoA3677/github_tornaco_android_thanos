.class public final synthetic Llyiahf/vczjk/b2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/b2;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    const/4 v0, 0x1

    const/4 v1, 0x0

    const-string v2, "<this>"

    const-string v3, "getString(...)"

    const-string v4, "it"

    iget v5, p0, Llyiahf/vczjk/b2;->OooOOO0:I

    packed-switch v5, :pswitch_data_0

    check-cast p1, Landroid/content/Context;

    sget v0, Lgithub/tornaco/practice/honeycomb/locker/ui/setup/AppLockListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->module_locker_app_name:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_0
    check-cast p1, Landroid/content/Context;

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->all:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/uj;

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    const/4 v2, 0x5

    const/high16 v3, 0x43480000    # 200.0f

    invoke-static {v1, v3, v0, v2}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/o6;->Oooo000:Llyiahf/vczjk/o6;

    iget-object v2, p1, Llyiahf/vczjk/uj;->OooO0OO:Llyiahf/vczjk/yn4;

    sget-object v3, Llyiahf/vczjk/yn4;->OooOOO:Llyiahf/vczjk/yn4;

    if-ne v2, v3, :cond_0

    new-instance v2, Llyiahf/vczjk/sj;

    invoke-direct {v2, p1, v1}, Llyiahf/vczjk/sj;-><init>(Llyiahf/vczjk/uj;Llyiahf/vczjk/oe3;)V

    sget-object p1, Llyiahf/vczjk/uo2;->OooO00o:Llyiahf/vczjk/n1a;

    new-instance p1, Llyiahf/vczjk/so2;

    invoke-direct {p1, v2}, Llyiahf/vczjk/so2;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v1, Llyiahf/vczjk/dt2;

    new-instance v2, Llyiahf/vczjk/fz9;

    new-instance v4, Llyiahf/vczjk/hr8;

    invoke-direct {v4, p1, v0}, Llyiahf/vczjk/hr8;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/p13;)V

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/16 v8, 0x3d

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/fz9;-><init>(Llyiahf/vczjk/iv2;Llyiahf/vczjk/hr8;Llyiahf/vczjk/ls0;Llyiahf/vczjk/s78;Ljava/util/LinkedHashMap;I)V

    invoke-direct {v1, v2}, Llyiahf/vczjk/dt2;-><init>(Llyiahf/vczjk/fz9;)V

    goto :goto_0

    :cond_0
    sget-object v3, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    if-ne v2, v3, :cond_1

    new-instance v2, Llyiahf/vczjk/tj;

    invoke-direct {v2, p1, v1}, Llyiahf/vczjk/tj;-><init>(Llyiahf/vczjk/uj;Llyiahf/vczjk/oe3;)V

    sget-object p1, Llyiahf/vczjk/uo2;->OooO00o:Llyiahf/vczjk/n1a;

    new-instance p1, Llyiahf/vczjk/so2;

    invoke-direct {p1, v2}, Llyiahf/vczjk/so2;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v1, Llyiahf/vczjk/dt2;

    new-instance v2, Llyiahf/vczjk/fz9;

    new-instance v4, Llyiahf/vczjk/hr8;

    invoke-direct {v4, p1, v0}, Llyiahf/vczjk/hr8;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/p13;)V

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/16 v8, 0x3d

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/fz9;-><init>(Llyiahf/vczjk/iv2;Llyiahf/vczjk/hr8;Llyiahf/vczjk/ls0;Llyiahf/vczjk/s78;Ljava/util/LinkedHashMap;I)V

    invoke-direct {v1, v2}, Llyiahf/vczjk/dt2;-><init>(Llyiahf/vczjk/fz9;)V

    goto :goto_0

    :cond_1
    sget-object v1, Llyiahf/vczjk/ct2;->OooO00o:Llyiahf/vczjk/dt2;

    :goto_0
    return-object v1

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/uj;

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    int-to-long v2, v0

    const/16 v0, 0x20

    shl-long v4, v2, v0

    const-wide v6, 0xffffffffL

    and-long/2addr v2, v6

    or-long/2addr v2, v4

    new-instance v0, Llyiahf/vczjk/u14;

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/u14;-><init>(J)V

    const/4 v2, 0x3

    invoke-static {v1, v1, v0, v2}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/o6;->OooOooo:Llyiahf/vczjk/o6;

    iget-object v2, p1, Llyiahf/vczjk/uj;->OooO0OO:Llyiahf/vczjk/yn4;

    sget-object v3, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    if-eq v2, v3, :cond_3

    sget-object v3, Llyiahf/vczjk/yn4;->OooOOO:Llyiahf/vczjk/yn4;

    if-eq v2, v3, :cond_2

    sget-object p1, Llyiahf/vczjk/ep2;->OooO00o:Llyiahf/vczjk/fp2;

    goto :goto_2

    :cond_2
    new-instance v2, Llyiahf/vczjk/rj;

    invoke-direct {v2, p1, v1}, Llyiahf/vczjk/rj;-><init>(Llyiahf/vczjk/uj;Llyiahf/vczjk/oe3;)V

    sget-object p1, Llyiahf/vczjk/uo2;->OooO00o:Llyiahf/vczjk/n1a;

    new-instance p1, Llyiahf/vczjk/qo2;

    invoke-direct {p1, v2}, Llyiahf/vczjk/qo2;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v1, Llyiahf/vczjk/fp2;

    new-instance v2, Llyiahf/vczjk/fz9;

    new-instance v4, Llyiahf/vczjk/hr8;

    invoke-direct {v4, p1, v0}, Llyiahf/vczjk/hr8;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/p13;)V

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/16 v8, 0x3d

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/fz9;-><init>(Llyiahf/vczjk/iv2;Llyiahf/vczjk/hr8;Llyiahf/vczjk/ls0;Llyiahf/vczjk/s78;Ljava/util/LinkedHashMap;I)V

    invoke-direct {v1, v2}, Llyiahf/vczjk/fp2;-><init>(Llyiahf/vczjk/fz9;)V

    :goto_1
    move-object p1, v1

    goto :goto_2

    :cond_3
    new-instance v2, Llyiahf/vczjk/qj;

    invoke-direct {v2, p1, v1}, Llyiahf/vczjk/qj;-><init>(Llyiahf/vczjk/uj;Llyiahf/vczjk/oe3;)V

    sget-object p1, Llyiahf/vczjk/uo2;->OooO00o:Llyiahf/vczjk/n1a;

    new-instance p1, Llyiahf/vczjk/qo2;

    invoke-direct {p1, v2}, Llyiahf/vczjk/qo2;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v1, Llyiahf/vczjk/fp2;

    new-instance v2, Llyiahf/vczjk/fz9;

    new-instance v4, Llyiahf/vczjk/hr8;

    invoke-direct {v4, p1, v0}, Llyiahf/vczjk/hr8;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/p13;)V

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/16 v8, 0x3d

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/fz9;-><init>(Llyiahf/vczjk/iv2;Llyiahf/vczjk/hr8;Llyiahf/vczjk/ls0;Llyiahf/vczjk/s78;Ljava/util/LinkedHashMap;I)V

    invoke-direct {v1, v2}, Llyiahf/vczjk/fp2;-><init>(Llyiahf/vczjk/fz9;)V

    goto :goto_1

    :goto_2
    return-object p1

    :pswitch_3
    check-cast p1, Ljava/util/List;

    new-instance v1, Llyiahf/vczjk/eq;

    invoke-direct {v1}, Llyiahf/vczjk/eq;-><init>()V

    const/4 v2, 0x0

    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    iget-object v3, v1, Llyiahf/vczjk/eq;->OooO00o:Llyiahf/vczjk/qr5;

    check-cast v3, Llyiahf/vczjk/bw8;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    iget-object v0, v1, Llyiahf/vczjk/eq;->OooO0O0:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    return-object v1

    :pswitch_4
    check-cast p1, Llyiahf/vczjk/af8;

    sget-object p1, Llyiahf/vczjk/up;->OooO00o:Llyiahf/vczjk/jh1;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_5
    check-cast p1, Landroid/content/Context;

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1

    :pswitch_6
    check-cast p1, Landroid/content/Context;

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->off:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_7
    check-cast p1, Landroid/content/Context;

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->on:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_8
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->activity_title_start_restrict:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_9
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->feature_title_smart_app_standby:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_a
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->pre_title_resident:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_b
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->title_suggested_apps_view_all:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_c
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->title_package_sets:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_d
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->feature_summary_shortcut_cleaner:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_e
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->titile_suggested_apps_recent_used:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_f
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->feature_summary_update_blocker:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_10
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->feature_title_update_blocker:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_11
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->title_package_sets:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_12
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->title_suggested_apps_view_all:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_13
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->feature_desc_data_cheat:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_14
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->common_text_value_not_set:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_15
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->common_text_value_not_set:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_16
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->activity_title_data_cheat:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_17
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->feature_summary_uninstall_blocker:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_18
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->feature_title_uninstall_blocker:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_19
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->sensor_off_always:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_1a
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->sensor_off_on_start:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_1b
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->sensor_off_default:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_1c
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->sensor_off_always:I

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
