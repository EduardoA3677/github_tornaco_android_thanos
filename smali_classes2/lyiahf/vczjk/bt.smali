.class public final Llyiahf/vczjk/bt;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field final synthetic $context:Landroid/content/Context;

.field final synthetic $listener:Llyiahf/vczjk/vs;

.field final synthetic $pickedFile:Llyiahf/vczjk/jd2;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jd2;Landroid/content/Context;Llyiahf/vczjk/vs;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bt;->$pickedFile:Llyiahf/vczjk/jd2;

    iput-object p2, p0, Llyiahf/vczjk/bt;->$context:Landroid/content/Context;

    iput-object p3, p0, Llyiahf/vczjk/bt;->$listener:Llyiahf/vczjk/vs;

    iput-object p4, p0, Llyiahf/vczjk/bt;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/bt;

    iget-object v1, p0, Llyiahf/vczjk/bt;->$pickedFile:Llyiahf/vczjk/jd2;

    iget-object v2, p0, Llyiahf/vczjk/bt;->$context:Landroid/content/Context;

    iget-object v3, p0, Llyiahf/vczjk/bt;->$listener:Llyiahf/vczjk/vs;

    iget-object v4, p0, Llyiahf/vczjk/bt;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/bt;-><init>(Llyiahf/vczjk/jd2;Landroid/content/Context;Llyiahf/vczjk/vs;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/bt;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/bt;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bt;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/bt;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    const/4 v4, 0x2

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v4, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/bt;->$pickedFile:Llyiahf/vczjk/jd2;

    iget-object v1, p0, Llyiahf/vczjk/bt;->$context:Landroid/content/Context;

    invoke-static {p1, v1}, Llyiahf/vczjk/t51;->OoooO0O(Llyiahf/vczjk/jd2;Landroid/content/Context;)Ljava/io/OutputStream;

    move-result-object v8

    if-nez v8, :cond_3

    sget-object p1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object p1, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    new-instance v1, Llyiahf/vczjk/xs;

    iget-object v4, p0, Llyiahf/vczjk/bt;->$listener:Llyiahf/vczjk/vs;

    const/4 v5, 0x0

    invoke-direct {v1, v4, v5}, Llyiahf/vczjk/xs;-><init>(Llyiahf/vczjk/vs;Llyiahf/vczjk/yo1;)V

    iput v3, p0, Llyiahf/vczjk/bt;->label:I

    invoke-static {p1, v1, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    goto :goto_0

    :cond_3
    sget-object p1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object p1, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v5, Llyiahf/vczjk/at;

    iget-object v6, p0, Llyiahf/vczjk/bt;->$context:Landroid/content/Context;

    iget-object v7, p0, Llyiahf/vczjk/bt;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v9, p0, Llyiahf/vczjk/bt;->$listener:Llyiahf/vczjk/vs;

    const/4 v10, 0x0

    invoke-direct/range {v5 .. v10}, Llyiahf/vczjk/at;-><init>(Landroid/content/Context;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/io/OutputStream;Llyiahf/vczjk/vs;Llyiahf/vczjk/yo1;)V

    iput v4, p0, Llyiahf/vczjk/bt;->label:I

    invoke-static {p1, v5, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_0
    return-object v0

    :cond_4
    return-object v2
.end method
