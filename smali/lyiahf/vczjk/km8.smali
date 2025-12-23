.class public final Llyiahf/vczjk/km8;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/km8;

.field public static final OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

.field public static final OooO0OO:Llyiahf/vczjk/sc9;

.field public static final OooO0Oo:Llyiahf/vczjk/mt5;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/km8;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    new-instance v0, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v1, "ShizukuService"

    invoke-direct {v0, v1}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/km8;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    new-instance v0, Llyiahf/vczjk/p35;

    const/16 v1, 0x1a

    invoke-direct {v0, v1}, Llyiahf/vczjk/p35;-><init>(I)V

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/km8;->OooO0OO:Llyiahf/vczjk/sc9;

    new-instance v0, Llyiahf/vczjk/mt5;

    invoke-direct {v0}, Llyiahf/vczjk/mt5;-><init>()V

    sput-object v0, Llyiahf/vczjk/km8;->OooO0Oo:Llyiahf/vczjk/mt5;

    return-void
.end method

.method public static OooO00o()Llyiahf/vczjk/nm8;
    .locals 1

    sget-object v0, Llyiahf/vczjk/km8;->OooO0OO:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nm8;

    return-object v0
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 7

    instance-of v0, p1, Llyiahf/vczjk/hm8;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/hm8;

    iget v1, v0, Llyiahf/vczjk/hm8;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/hm8;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/hm8;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/hm8;-><init>(Llyiahf/vczjk/km8;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/hm8;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/hm8;->label:I

    const/4 v3, 0x1

    const/4 v4, 0x2

    const/4 v5, 0x0

    if-eqz v2, :cond_3

    if-eq v2, v3, :cond_2

    if-ne v2, v4, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/hm8;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jt5;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_3

    :catchall_0
    move-exception p1

    goto :goto_4

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object v2, v0, Llyiahf/vczjk/hm8;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jt5;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p1, v2

    goto :goto_1

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/km8;->OooO0Oo:Llyiahf/vczjk/mt5;

    iput-object p1, v0, Llyiahf/vczjk/hm8;->L$0:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/hm8;->label:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_4

    goto :goto_2

    :cond_4
    :goto_1
    :try_start_1
    sget-object v2, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v2, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v3, Llyiahf/vczjk/im8;

    invoke-direct {v3, v4, v5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/hm8;->L$0:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/hm8;->label:I

    invoke-static {v2, v3, v0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-ne v0, v1, :cond_5

    :goto_2
    return-object v1

    :cond_5
    move-object v6, v0

    move-object v0, p1

    move-object p1, v6

    :goto_3
    :try_start_2
    check-cast p1, Lgithub/tornaco/android/thanos/core/IThanosLite;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    invoke-interface {v0, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    return-object p1

    :catchall_1
    move-exception v0

    move-object v6, v0

    move-object v0, p1

    move-object p1, v6

    :goto_4
    invoke-interface {v0, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1
.end method
