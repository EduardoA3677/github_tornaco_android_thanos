.class public final Llyiahf/vczjk/zy7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Ltornaco/apps/thanox/running/RunningAppState;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ltornaco/apps/thanox/running/RunningProcessState;

.field public final synthetic OooOOOo:Llyiahf/vczjk/ks1;

.field public final synthetic OooOOo0:Llyiahf/vczjk/ny7;


# direct methods
.method public synthetic constructor <init>(Ltornaco/apps/thanox/running/RunningAppState;Ltornaco/apps/thanox/running/RunningProcessState;Llyiahf/vczjk/ks1;Llyiahf/vczjk/ny7;I)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/zy7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/zy7;->OooOOO:Ltornaco/apps/thanox/running/RunningAppState;

    iput-object p2, p0, Llyiahf/vczjk/zy7;->OooOOOO:Ltornaco/apps/thanox/running/RunningProcessState;

    iput-object p3, p0, Llyiahf/vczjk/zy7;->OooOOOo:Llyiahf/vczjk/ks1;

    iput-object p4, p0, Llyiahf/vczjk/zy7;->OooOOo0:Llyiahf/vczjk/ny7;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    iget v0, p0, Llyiahf/vczjk/zy7;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/vk;

    move-object v5, p2

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    const-string p2, "$this$AnimatedVisibility"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/16 p2, 0x10

    int-to-float p2, p2

    invoke-static {p1, p2}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    const/4 p1, 0x0

    const/4 p2, 0x1

    invoke-static {p1, v5, p2}, Llyiahf/vczjk/u34;->OooO0o(FLlyiahf/vczjk/rf1;I)J

    move-result-wide p1

    const/4 p3, 0x0

    invoke-static {p1, p2, v5, p3}, Llyiahf/vczjk/l4a;->OooOO0O(JLlyiahf/vczjk/rf1;I)Llyiahf/vczjk/sq0;

    move-result-object v2

    new-instance v6, Llyiahf/vczjk/zy7;

    iget-object v8, p0, Llyiahf/vczjk/zy7;->OooOOOO:Ltornaco/apps/thanox/running/RunningProcessState;

    iget-object v9, p0, Llyiahf/vczjk/zy7;->OooOOOo:Llyiahf/vczjk/ks1;

    iget-object v10, p0, Llyiahf/vczjk/zy7;->OooOOo0:Llyiahf/vczjk/ny7;

    iget-object v7, p0, Llyiahf/vczjk/zy7;->OooOOO:Ltornaco/apps/thanox/running/RunningAppState;

    const/4 v11, 0x0

    invoke-direct/range {v6 .. v11}, Llyiahf/vczjk/zy7;-><init>(Ltornaco/apps/thanox/running/RunningAppState;Ltornaco/apps/thanox/running/RunningProcessState;Llyiahf/vczjk/ks1;Llyiahf/vczjk/ny7;I)V

    const p1, 0x116b8bc9

    invoke-static {p1, v6, v5}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v4

    const v6, 0x30006

    const/16 v7, 0x1a

    const/4 v1, 0x0

    const/4 v3, 0x0

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/c6a;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;Llyiahf/vczjk/sq0;Llyiahf/vczjk/vq0;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/q31;

    move-object v4, p2

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    move-result p2

    const-string p3, "$this$Card"

    invoke-static {p1, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 p1, p2, 0x11

    const/16 p2, 0x10

    if-ne p1, p2, :cond_1

    move-object p1, v4

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p2

    if-nez p2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_2

    :cond_1
    :goto_0
    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object p2, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object p3, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v6, 0x0

    invoke-static {p2, p3, v4, v6}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object p2

    move-object p3, v4

    check-cast p3, Llyiahf/vczjk/zf1;

    iget v0, p3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v1

    invoke-static {v4, p1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    sget-object v2, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v3, p3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v3, :cond_2

    invoke-virtual {p3, v2}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_2
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {p2, v4, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v1, v4, p2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v1, p3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v1, :cond_3

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4

    :cond_3
    invoke-static {v0, p3, v0, p2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_4
    sget-object p2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p1, v4, p2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v6, v4}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    iget-object p1, p0, Llyiahf/vczjk/zy7;->OooOOO:Ltornaco/apps/thanox/running/RunningAppState;

    iget-object v0, p1, Ltornaco/apps/thanox/running/RunningAppState;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v1, p0, Llyiahf/vczjk/zy7;->OooOOOO:Ltornaco/apps/thanox/running/RunningProcessState;

    iget-object v2, p0, Llyiahf/vczjk/zy7;->OooOOOo:Llyiahf/vczjk/ks1;

    iget-object v3, p0, Llyiahf/vczjk/zy7;->OooOOo0:Llyiahf/vczjk/ny7;

    const/4 v5, 0x0

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/ht6;->OooO0O0(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ltornaco/apps/thanox/running/RunningProcessState;Llyiahf/vczjk/ks1;Llyiahf/vczjk/ny7;Llyiahf/vczjk/rf1;I)V

    invoke-static {v6, v4}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    invoke-static {p1, v1, v3, v4, v6}, Llyiahf/vczjk/ht6;->OooO0oO(Ltornaco/apps/thanox/running/RunningAppState;Ltornaco/apps/thanox/running/RunningProcessState;Llyiahf/vczjk/ny7;Llyiahf/vczjk/rf1;I)V

    invoke-static {v6, v4}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    const/4 p1, 0x1

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
