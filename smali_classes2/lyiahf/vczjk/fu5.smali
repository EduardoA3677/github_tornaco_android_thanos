.class public final Llyiahf/vczjk/fu5;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $propLogger:Lgithub/tornaco/android/thanos/core/Logger;

.field final synthetic $props:Ljava/util/List;

.field label:I


# direct methods
.method public constructor <init>(Lgithub/tornaco/android/thanos/core/Logger;Ljava/util/List;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fu5;->$propLogger:Lgithub/tornaco/android/thanos/core/Logger;

    iput-object p2, p0, Llyiahf/vczjk/fu5;->$props:Ljava/util/List;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/fu5;

    iget-object v0, p0, Llyiahf/vczjk/fu5;->$propLogger:Lgithub/tornaco/android/thanos/core/Logger;

    iget-object v1, p0, Llyiahf/vczjk/fu5;->$props:Ljava/util/List;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/fu5;-><init>(Lgithub/tornaco/android/thanos/core/Logger;Ljava/util/List;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/fu5;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/fu5;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fu5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/fu5;->label:I

    if-nez v0, :cond_2

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/fu5;->$props:Ljava/util/List;

    invoke-static {}, Llyiahf/vczjk/m6a;->o0000oo()Ljava/lang/String;

    move-result-object v0

    sget v1, Llyiahf/vczjk/xl4;->OooO00o:I

    invoke-static {}, Lcom/tencent/mmkv/MMKV;->OooO0Oo()Lcom/tencent/mmkv/MMKV;

    move-result-object v1

    const-string v2, "39M5DC32-B17D-4370-AB98-A9L809256685"

    invoke-virtual {v1, v2}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_1

    invoke-static {v1}, Lcom/tencent/mmkv/MMKV;->OooO(Ljava/lang/String;)Lcom/tencent/mmkv/MMKV;

    move-result-object v1

    invoke-virtual {v1, v0}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-interface {p1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Required value was null."

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
