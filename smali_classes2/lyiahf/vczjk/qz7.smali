.class public final synthetic Llyiahf/vczjk/qz7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/i48;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/i48;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/qz7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/qz7;->OooOOO:Llyiahf/vczjk/i48;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/qz7;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/ah5;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/qz7;->OooOOO:Llyiahf/vczjk/i48;

    iget-object p1, p1, Llyiahf/vczjk/ah5;->OooO00o:Ljava/lang/String;

    invoke-static {v0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/s28;

    const/4 v3, 0x0

    invoke-direct {v2, v0, p1, v3}, Llyiahf/vczjk/s28;-><init>(Llyiahf/vczjk/i48;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v1, v3, v3, v2, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Ljava/util/List;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/qz7;->OooOOO:Llyiahf/vczjk/i48;

    invoke-static {v0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/w28;

    const/4 v3, 0x0

    invoke-direct {v2, v0, p1, v3}, Llyiahf/vczjk/w28;-><init>(Llyiahf/vczjk/i48;Ljava/util/List;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v1, v3, v3, v2, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    check-cast p1, Landroidx/activity/result/ActivityResult;

    const-string v0, "result"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, -0x1

    iget v1, p1, Landroidx/activity/result/ActivityResult;->OooOOO0:I

    if-ne v1, v0, :cond_2

    const/4 v0, 0x0

    iget-object p1, p1, Landroidx/activity/result/ActivityResult;->OooOOO:Landroid/content/Intent;

    if-eqz p1, :cond_0

    const-string v1, "apps"

    invoke-virtual {p1, v1}, Landroid/content/Intent;->getParcelableArrayListExtra(Ljava/lang/String;)Ljava/util/ArrayList;

    move-result-object p1

    goto :goto_0

    :cond_0
    move-object p1, v0

    :goto_0
    if-eqz p1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/qz7;->OooOOO:Llyiahf/vczjk/i48;

    new-instance v2, Ljava/util/ArrayList;

    const/16 v3, 0xa

    invoke-static {p1, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v3}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_1
    invoke-static {v1}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v3, Llyiahf/vczjk/q28;

    invoke-direct {v3, v1, v2, v0}, Llyiahf/vczjk/q28;-><init>(Llyiahf/vczjk/i48;Ljava/util/List;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    invoke-static {p1, v0, v0, v3, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    check-cast p1, Ljava/lang/String;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/qz7;->OooOOO:Llyiahf/vczjk/i48;

    invoke-static {v0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/m28;

    const/4 v3, 0x0

    invoke-direct {v2, v0, p1, v3}, Llyiahf/vczjk/m28;-><init>(Llyiahf/vczjk/i48;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v1, v3, v3, v2, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
