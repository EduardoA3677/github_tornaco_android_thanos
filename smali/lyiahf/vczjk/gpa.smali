.class public final Llyiahf/vczjk/gpa;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $recomposer:Llyiahf/vczjk/oj7;

.field final synthetic $self:Llyiahf/vczjk/hpa;

.field final synthetic $source:Llyiahf/vczjk/uy4;

.field final synthetic $systemDurationScaleSettingConsumer:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field final synthetic $this_createLifecycleAwareWindowRecomposer:Landroid/view/View;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/oj7;Llyiahf/vczjk/uy4;Llyiahf/vczjk/hpa;Landroid/view/View;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gpa;->$systemDurationScaleSettingConsumer:Llyiahf/vczjk/hl7;

    iput-object p2, p0, Llyiahf/vczjk/gpa;->$recomposer:Llyiahf/vczjk/oj7;

    iput-object p3, p0, Llyiahf/vczjk/gpa;->$source:Llyiahf/vczjk/uy4;

    iput-object p4, p0, Llyiahf/vczjk/gpa;->$self:Llyiahf/vczjk/hpa;

    iput-object p5, p0, Llyiahf/vczjk/gpa;->$this_createLifecycleAwareWindowRecomposer:Landroid/view/View;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/gpa;

    iget-object v1, p0, Llyiahf/vczjk/gpa;->$systemDurationScaleSettingConsumer:Llyiahf/vczjk/hl7;

    iget-object v2, p0, Llyiahf/vczjk/gpa;->$recomposer:Llyiahf/vczjk/oj7;

    iget-object v3, p0, Llyiahf/vczjk/gpa;->$source:Llyiahf/vczjk/uy4;

    iget-object v4, p0, Llyiahf/vczjk/gpa;->$self:Llyiahf/vczjk/hpa;

    iget-object v5, p0, Llyiahf/vczjk/gpa;->$this_createLifecycleAwareWindowRecomposer:Landroid/view/View;

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/gpa;-><init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/oj7;Llyiahf/vczjk/uy4;Llyiahf/vczjk/hpa;Landroid/view/View;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/gpa;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/gpa;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gpa;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/gpa;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/gpa;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x0

    const/4 v4, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v4, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/gpa;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v74;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_3

    :catchall_0
    move-exception p1

    goto/16 :goto_5

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/gpa;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    :try_start_1
    iget-object v1, p0, Llyiahf/vczjk/gpa;->$systemDurationScaleSettingConsumer:Llyiahf/vczjk/hl7;

    iget-object v1, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/go5;

    if-eqz v1, :cond_2

    iget-object v5, p0, Llyiahf/vczjk/gpa;->$this_createLifecycleAwareWindowRecomposer:Landroid/view/View;

    invoke-virtual {v5}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v5

    invoke-virtual {v5}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/kpa;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/q29;

    move-result-object v5

    invoke-interface {v5}, Llyiahf/vczjk/q29;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->floatValue()F

    move-result v6

    iget-object v7, v1, Llyiahf/vczjk/go5;->OooOOO0:Llyiahf/vczjk/lr5;

    check-cast v7, Llyiahf/vczjk/zv8;

    invoke-virtual {v7, v6}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    new-instance v6, Llyiahf/vczjk/fpa;

    invoke-direct {v6, v5, v1, v3}, Llyiahf/vczjk/fpa;-><init>(Llyiahf/vczjk/q29;Llyiahf/vczjk/go5;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    invoke-static {p1, v3, v3, v6, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_0

    :catchall_1
    move-exception p1

    move-object v0, v3

    goto :goto_5

    :cond_2
    move-object p1, v3

    :goto_0
    :try_start_2
    iget-object v1, p0, Llyiahf/vczjk/gpa;->$recomposer:Llyiahf/vczjk/oj7;

    iput-object p1, p0, Llyiahf/vczjk/gpa;->L$0:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/gpa;->label:I

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v4, Llyiahf/vczjk/mj7;

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/mj7;-><init>(Llyiahf/vczjk/oj7;Llyiahf/vczjk/yo1;)V

    invoke-interface {p0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/vc6;->OooOoo0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/xn5;

    move-result-object v5

    new-instance v6, Llyiahf/vczjk/kj7;

    invoke-direct {v6, v1, v4, v5, v3}, Llyiahf/vczjk/kj7;-><init>(Llyiahf/vczjk/oj7;Llyiahf/vczjk/bf3;Llyiahf/vczjk/xn5;Llyiahf/vczjk/yo1;)V

    iget-object v1, v1, Llyiahf/vczjk/oj7;->OooO00o:Llyiahf/vczjk/li0;

    invoke-static {v1, v6, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    if-ne v1, v0, :cond_3

    goto :goto_1

    :cond_3
    move-object v1, v2

    :goto_1
    if-ne v1, v0, :cond_4

    goto :goto_2

    :cond_4
    move-object v1, v2

    :goto_2
    if-ne v1, v0, :cond_5

    return-object v0

    :cond_5
    move-object v0, p1

    :goto_3
    if-eqz v0, :cond_6

    invoke-interface {v0, v3}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_6
    iget-object p1, p0, Llyiahf/vczjk/gpa;->$source:Llyiahf/vczjk/uy4;

    invoke-interface {p1}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/gpa;->$self:Llyiahf/vczjk/hpa;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    return-object v2

    :goto_4
    move-object v8, v0

    move-object v0, p1

    move-object p1, v8

    goto :goto_5

    :catchall_2
    move-exception v0

    goto :goto_4

    :goto_5
    if-eqz v0, :cond_7

    invoke-interface {v0, v3}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_7
    iget-object v0, p0, Llyiahf/vczjk/gpa;->$source:Llyiahf/vczjk/uy4;

    invoke-interface {v0}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/gpa;->$self:Llyiahf/vczjk/hpa;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    throw p1
.end method
