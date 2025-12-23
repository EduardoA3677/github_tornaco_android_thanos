.class public final synthetic Llyiahf/vczjk/tka;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/bla;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/bla;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/tka;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/tka;->OooOOO:Llyiahf/vczjk/bla;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    iget v0, p0, Llyiahf/vczjk/tka;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/uh6;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/tka;->OooOOO:Llyiahf/vczjk/bla;

    iget-object p1, p1, Llyiahf/vczjk/uh6;->OooO0O0:Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    :cond_0
    move v1, v3

    goto :goto_0

    :cond_1
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_0

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/dla;

    iget-boolean v4, v4, Llyiahf/vczjk/dla;->OooO0o:Z

    if-nez v4, :cond_2

    move v1, v2

    :goto_0
    xor-int/2addr v1, v3

    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/dla;

    invoke-virtual {v0, v3, v1, v2}, Llyiahf/vczjk/bla;->OooOOO0(Llyiahf/vczjk/dla;ZZ)V

    goto :goto_1

    :cond_3
    invoke-virtual {v0}, Llyiahf/vczjk/bla;->OooOO0o()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/nw;

    const-string p1, "it"

    invoke-static {v5, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/tka;->OooOOO:Llyiahf/vczjk/bla;

    iget-object v8, p1, Llyiahf/vczjk/bla;->OooO0o:Llyiahf/vczjk/s29;

    invoke-virtual {v8}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/td0;

    const/4 v3, 0x0

    const/16 v7, 0x2f

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v4, 0x0

    const/4 v6, 0x0

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/td0;->OooO00o(Llyiahf/vczjk/td0;ZZLjava/util/List;Ljava/util/List;Llyiahf/vczjk/nw;ZI)Llyiahf/vczjk/td0;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {v8, v1, v0}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    invoke-static {p1}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v2, Llyiahf/vczjk/zka;

    invoke-direct {v2, p1, v1}, Llyiahf/vczjk/zka;-><init>(Llyiahf/vczjk/bla;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v0, v1, v1, v2, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/tka;->OooOOO:Llyiahf/vczjk/bla;

    invoke-virtual {v0}, Llyiahf/vczjk/bla;->OooOO0()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPowerManager()Lgithub/tornaco/android/thanos/core/power/PowerManager;

    move-result-object v1

    invoke-virtual {v1, p1}, Lgithub/tornaco/android/thanos/core/power/PowerManager;->setWakeLockBlockerEnabled(Z)V

    invoke-virtual {v0}, Llyiahf/vczjk/bla;->OooOO0O()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
