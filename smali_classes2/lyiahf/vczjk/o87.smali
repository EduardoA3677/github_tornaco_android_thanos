.class public final synthetic Llyiahf/vczjk/o87;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/o87;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/o87;->OooOOO:Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/o87;->OooOOO0:I

    check-cast p1, Ljava/lang/String;

    packed-switch v0, :pswitch_data_0

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/o87;->OooOOO:Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;

    if-eqz v0, :cond_0

    const/4 v1, 0x0

    invoke-interface {v0, v1, p1}, Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;->onRuleAddFail(ILjava/lang/String;)V

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/o87;->OooOOO:Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;

    if-eqz v0, :cond_1

    const/4 v1, 0x0

    invoke-interface {v0, v1, p1}, Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;->onRuleAddFail(ILjava/lang/String;)V

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onRuleAddFail: "

    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/l87;->OooO0O0(Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/o87;->OooOOO:Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;

    if-eqz v0, :cond_2

    const/4 v1, 0x0

    invoke-interface {v0, v1, p1}, Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;->onRuleAddFail(ILjava/lang/String;)V

    :cond_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
