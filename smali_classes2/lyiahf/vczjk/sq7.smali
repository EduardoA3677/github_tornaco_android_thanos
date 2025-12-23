.class public final Llyiahf/vczjk/sq7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $code:Ljava/lang/String;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/tq7;


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/tq7;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sq7;->$code:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/sq7;->this$0:Llyiahf/vczjk/tq7;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/sq7;

    iget-object v0, p0, Llyiahf/vczjk/sq7;->$code:Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/sq7;->this$0:Llyiahf/vczjk/tq7;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/sq7;-><init>(Ljava/lang/String;Llyiahf/vczjk/tq7;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/sq7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/sq7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/sq7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/sq7;->label:I

    sget-object v2, Llyiahf/vczjk/rea;->OooO00o:Llyiahf/vczjk/rea;

    const/4 v3, 0x1

    const/4 v4, 0x2

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v4, :cond_0

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_0

    :catchall_0
    move-exception v0

    move-object p1, v0

    goto/16 :goto_4

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :try_start_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto/16 :goto_5

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v6, p0, Llyiahf/vczjk/sq7;->$code:Ljava/lang/String;

    iget-object p1, p0, Llyiahf/vczjk/sq7;->this$0:Llyiahf/vczjk/tq7;

    :try_start_2
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    move-result v1

    const/4 v5, 0x6

    if-lt v1, v5, :cond_7

    invoke-static {v6}, Landroid/text/TextUtils;->isDigitsOnly(Ljava/lang/CharSequence;)Z

    move-result v1

    if-eqz v1, :cond_3

    goto/16 :goto_2

    :cond_3
    sget-object v1, Lgithub/tornaco/android/thanos/support/subscribe/code/DeviceCodeBinding;->Companion:Llyiahf/vczjk/l92;

    invoke-static {}, Lcom/tencent/mmkv/MMKV;->OooO0Oo()Lcom/tencent/mmkv/MMKV;

    move-result-object v5

    const-string v7, "39M5DC32-B17D-4370-AB98-A9L809256685"

    invoke-virtual {v5, v7}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    if-eqz v7, :cond_6

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v5, Lgithub/tornaco/android/thanos/support/subscribe/code/DeviceCodeBinding;

    const/4 v12, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/16 v11, 0x1c

    invoke-direct/range {v5 .. v12}, Lgithub/tornaco/android/thanos/support/subscribe/code/DeviceCodeBinding;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IILlyiahf/vczjk/n12;)V

    invoke-static {v5}, Llyiahf/vczjk/m92;->OooO00o(Lgithub/tornaco/android/thanos/support/subscribe/code/DeviceCodeBinding;)Llyiahf/vczjk/br7;

    move-result-object v1

    iget-object p1, p1, Llyiahf/vczjk/tq7;->OooO00o:Landroid/content/Context;

    const-string v5, "context"

    invoke-static {p1, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/pb7;

    const/4 v5, 0x1

    invoke-direct {p1, v5}, Llyiahf/vczjk/pb7;-><init>(I)V

    const-string v5, "http://thanox.emui.tech/api/"

    invoke-virtual {p1, v5}, Llyiahf/vczjk/pb7;->OooO(Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/pk3;->OooO0OO()Llyiahf/vczjk/pk3;

    move-result-object v5

    invoke-virtual {p1, v5}, Llyiahf/vczjk/pb7;->OooO0O0(Llyiahf/vczjk/pk3;)V

    new-instance v5, Llyiahf/vczjk/d96;

    invoke-direct {v5}, Llyiahf/vczjk/d96;-><init>()V

    new-instance v6, Llyiahf/vczjk/e96;

    invoke-direct {v6, v5}, Llyiahf/vczjk/e96;-><init>(Llyiahf/vczjk/d96;)V

    iput-object v6, p1, Llyiahf/vczjk/pb7;->OooOOO:Ljava/lang/Object;

    invoke-virtual {p1}, Llyiahf/vczjk/pb7;->OooOO0()Llyiahf/vczjk/mi;

    move-result-object p1

    const-class v5, Llyiahf/vczjk/v01;

    invoke-virtual {p1, v5}, Llyiahf/vczjk/mi;->OooO0oO(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p1

    const-string v5, "create(...)"

    invoke-static {p1, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/v01;

    iput v4, p0, Llyiahf/vczjk/sq7;->label:I

    invoke-interface {p1, v1, p0}, Llyiahf/vczjk/v01;->OooO0OO(Llyiahf/vczjk/cr7;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    goto :goto_3

    :cond_4
    :goto_0
    check-cast p1, Lgithub/tornaco/android/thanos/support/subscribe/CommonApiResWrapper;

    const-string v0, "<this>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/support/subscribe/CommonApiResWrapper;->getResult()I

    move-result v0

    if-nez v0, :cond_5

    goto :goto_1

    :cond_5
    const/4 v3, 0x0

    :goto_1
    if-eqz v3, :cond_8

    new-instance v2, Llyiahf/vczjk/tea;

    invoke-direct {v2, p1}, Llyiahf/vczjk/tea;-><init>(Lgithub/tornaco/android/thanos/support/subscribe/CommonApiResWrapper;)V

    goto :goto_5

    :cond_6
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Required value was null."

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_7
    :goto_2
    iput v3, p0, Llyiahf/vczjk/sq7;->label:I

    const-wide/16 v3, 0x11d7

    invoke-static {v3, v4, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    if-ne p1, v0, :cond_8

    :goto_3
    return-object v0

    :goto_4
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v2

    :cond_8
    :goto_5
    invoke-static {v2}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object p1

    if-nez p1, :cond_9

    goto :goto_6

    :cond_9
    instance-of v0, p1, Ljava/io/IOException;

    if-eqz v0, :cond_a

    sget-object p1, Llyiahf/vczjk/sea;->OooO00o:Llyiahf/vczjk/sea;

    move-object v2, p1

    goto :goto_6

    :cond_a
    new-instance v0, Llyiahf/vczjk/qea;

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v1

    if-nez v1, :cond_b

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    :cond_b
    invoke-direct {v0, v1}, Llyiahf/vczjk/qea;-><init>(Ljava/lang/String;)V

    move-object v2, v0

    :goto_6
    return-object v2
.end method
