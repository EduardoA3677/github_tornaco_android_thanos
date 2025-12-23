.class public final Llyiahf/vczjk/jc6;
.super Lgithub/tornaco/android/thanos/core/profile/RuleAddCallback;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/xr1;

.field public final synthetic OooO0OO:Llyiahf/vczjk/dha;

.field public final synthetic OooO0Oo:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/dha;Ljava/lang/Object;I)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/jc6;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/jc6;->OooO0O0:Llyiahf/vczjk/xr1;

    iput-object p2, p0, Llyiahf/vczjk/jc6;->OooO0OO:Llyiahf/vczjk/dha;

    iput-object p3, p0, Llyiahf/vczjk/jc6;->OooO0Oo:Ljava/lang/Object;

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/profile/RuleAddCallback;-><init>()V

    return-void
.end method


# virtual methods
.method public final onRuleAddFail(ILjava/lang/String;)V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/jc6;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0, p1, p2}, Lgithub/tornaco/android/thanos/core/profile/RuleAddCallback;->onRuleAddFail(ILjava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/b87;

    iget-object v1, p0, Llyiahf/vczjk/jc6;->OooO0OO:Llyiahf/vczjk/dha;

    check-cast v1, Llyiahf/vczjk/g87;

    const/4 v2, 0x0

    invoke-direct {v0, v1, p2, p1, v2}, Llyiahf/vczjk/b87;-><init>(Llyiahf/vczjk/g87;Ljava/lang/String;ILlyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    iget-object p2, p0, Llyiahf/vczjk/jc6;->OooO0O0:Llyiahf/vczjk/xr1;

    invoke-static {p2, v2, v2, v0, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void

    :pswitch_0
    invoke-super {p0, p1, p2}, Lgithub/tornaco/android/thanos/core/profile/RuleAddCallback;->onRuleAddFail(ILjava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/hc6;

    iget-object v1, p0, Llyiahf/vczjk/jc6;->OooO0OO:Llyiahf/vczjk/dha;

    check-cast v1, Llyiahf/vczjk/nc6;

    const/4 v2, 0x0

    invoke-direct {v0, v1, p2, p1, v2}, Llyiahf/vczjk/hc6;-><init>(Llyiahf/vczjk/nc6;Ljava/lang/String;ILlyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    iget-object p2, p0, Llyiahf/vczjk/jc6;->OooO0O0:Llyiahf/vczjk/xr1;

    invoke-static {p2, v2, v2, v0, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onRuleAddSuccess()V
    .locals 4

    iget v0, p0, Llyiahf/vczjk/jc6;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0}, Lgithub/tornaco/android/thanos/core/profile/RuleAddCallback;->onRuleAddSuccess()V

    new-instance v0, Llyiahf/vczjk/c87;

    iget-object v1, p0, Llyiahf/vczjk/jc6;->OooO0OO:Llyiahf/vczjk/dha;

    check-cast v1, Llyiahf/vczjk/g87;

    iget-object v2, p0, Llyiahf/vczjk/jc6;->OooO0Oo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/rr2;

    const/4 v3, 0x0

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/c87;-><init>(Llyiahf/vczjk/g87;Llyiahf/vczjk/rr2;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    iget-object v2, p0, Llyiahf/vczjk/jc6;->OooO0O0:Llyiahf/vczjk/xr1;

    invoke-static {v2, v3, v3, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void

    :pswitch_0
    invoke-super {p0}, Lgithub/tornaco/android/thanos/core/profile/RuleAddCallback;->onRuleAddSuccess()V

    new-instance v0, Llyiahf/vczjk/ic6;

    iget-object v1, p0, Llyiahf/vczjk/jc6;->OooO0OO:Llyiahf/vczjk/dha;

    check-cast v1, Llyiahf/vczjk/nc6;

    iget-object v2, p0, Llyiahf/vczjk/jc6;->OooO0Oo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/cc6;

    const/4 v3, 0x0

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/ic6;-><init>(Llyiahf/vczjk/nc6;Llyiahf/vczjk/cc6;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    iget-object v2, p0, Llyiahf/vczjk/jc6;->OooO0O0:Llyiahf/vczjk/xr1;

    invoke-static {v2, v3, v3, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
