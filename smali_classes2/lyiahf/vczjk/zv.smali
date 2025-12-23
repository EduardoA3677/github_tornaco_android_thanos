.class public final Llyiahf/vczjk/zv;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/aw;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/aw;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zv;->this$0:Llyiahf/vczjk/aw;

    iput-object p2, p0, Llyiahf/vczjk/zv;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/zv;

    iget-object v0, p0, Llyiahf/vczjk/zv;->this$0:Llyiahf/vczjk/aw;

    iget-object v1, p0, Llyiahf/vczjk/zv;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/zv;-><init>(Llyiahf/vczjk/aw;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/zv;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/zv;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zv;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/zv;->label:I

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/zv;->L$0:Ljava/lang/Object;

    check-cast v0, Landroid/content/res/TypedArray;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/zv;->this$0:Llyiahf/vczjk/aw;

    iget-object p1, p1, Llyiahf/vczjk/aw;->OooO0O0:Landroid/content/Context;

    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p1

    sget v1, Lgithub/tornaco/android/thanos/R$array;->module_ops2_op_icon:I

    invoke-virtual {p1, v1}, Landroid/content/res/Resources;->obtainTypedArray(I)Landroid/content/res/TypedArray;

    move-result-object p1

    const-string v1, "obtainTypedArray(...)"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v1, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v4, Llyiahf/vczjk/yv;

    iget-object v5, p0, Llyiahf/vczjk/zv;->this$0:Llyiahf/vczjk/aw;

    iget-object v6, p0, Llyiahf/vczjk/zv;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-direct {v4, v5, v6, p1, v2}, Llyiahf/vczjk/yv;-><init>(Llyiahf/vczjk/aw;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Landroid/content/res/TypedArray;Llyiahf/vczjk/yo1;)V

    iput-object p1, p0, Llyiahf/vczjk/zv;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/zv;->label:I

    invoke-static {v1, v4, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_2

    return-object v0

    :cond_2
    move-object v0, p1

    move-object p1, v1

    :goto_0
    check-cast p1, Ljava/util/List;

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->recycle()V

    iget-object v0, p0, Llyiahf/vczjk/zv;->this$0:Llyiahf/vczjk/aw;

    iget-object v0, v0, Llyiahf/vczjk/aw;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ye6;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v1, "opsItems"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/ye6;

    const/4 v3, 0x0

    invoke-direct {v1, p1, v3}, Llyiahf/vczjk/ye6;-><init>(Ljava/util/List;Z)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
