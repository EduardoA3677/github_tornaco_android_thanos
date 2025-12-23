.class public final synthetic Llyiahf/vczjk/l60;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/g70;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/g70;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/l60;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/l60;->OooOOO:Llyiahf/vczjk/g70;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 17

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/l60;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    iget-object v1, v0, Llyiahf/vczjk/l60;->OooOOO:Llyiahf/vczjk/g70;

    iget-object v1, v1, Llyiahf/vczjk/g70;->OooO0o:Landroid/content/Context;

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    return-object v1

    :pswitch_0
    const/4 v1, 0x0

    iget-object v2, v0, Llyiahf/vczjk/l60;->OooOOO:Llyiahf/vczjk/g70;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/g70;->OooOO0(Z)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_1
    const/4 v1, 0x0

    iget-object v2, v0, Llyiahf/vczjk/l60;->OooOOO:Llyiahf/vczjk/g70;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/g70;->OooOO0(Z)V

    const-string v1, "batchOperationConfig.opApplied"

    invoke-virtual {v2, v1}, Llyiahf/vczjk/g70;->OooOO0O(Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_2
    iget-object v1, v0, Llyiahf/vczjk/l60;->OooOOO:Llyiahf/vczjk/g70;

    iget-object v1, v1, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    iget-object v1, v1, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/rs5;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rs5;

    check-cast v1, Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/yu;

    const-string v1, "$this$updateState"

    invoke-static {v3, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v15, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    const/4 v12, 0x0

    const/16 v16, 0x7ff

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    invoke-static/range {v3 .. v16}, Llyiahf/vczjk/yu;->OooO00o(Llyiahf/vczjk/yu;Ljava/util/ArrayList;ZLjava/util/List;Llyiahf/vczjk/nw;Ljava/util/List;Llyiahf/vczjk/nw;Llyiahf/vczjk/vw;ZLjava/util/ArrayList;Ljava/lang/String;ZLjava/util/List;I)Llyiahf/vczjk/yu;

    move-result-object v1

    check-cast v2, Llyiahf/vczjk/s29;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/s29;->OooOOOO(Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_3
    iget-object v1, v0, Llyiahf/vczjk/l60;->OooOOO:Llyiahf/vczjk/g70;

    iget-object v1, v1, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    iget-object v1, v1, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/rs5;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rs5;

    check-cast v1, Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/yu;

    const-string v1, "$this$updateState"

    invoke-static {v3, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, v3, Llyiahf/vczjk/yu;->OooO00o:Ljava/util/List;

    invoke-static {v1}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v15

    const/4 v12, 0x0

    const/16 v16, 0x7ff

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    invoke-static/range {v3 .. v16}, Llyiahf/vczjk/yu;->OooO00o(Llyiahf/vczjk/yu;Ljava/util/ArrayList;ZLjava/util/List;Llyiahf/vczjk/nw;Ljava/util/List;Llyiahf/vczjk/nw;Llyiahf/vczjk/vw;ZLjava/util/ArrayList;Ljava/lang/String;ZLjava/util/List;I)Llyiahf/vczjk/yu;

    move-result-object v1

    check-cast v2, Llyiahf/vczjk/s29;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/s29;->OooOOOO(Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_4
    const-string v1, "pullRefreshState"

    iget-object v2, v0, Llyiahf/vczjk/l60;->OooOOO:Llyiahf/vczjk/g70;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/g70;->OooOO0O(Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
