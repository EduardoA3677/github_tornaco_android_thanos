.class public final Llyiahf/vczjk/d3;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $pm:Lgithub/tornaco/android/thanos/core/pm/PackageManager;

.field synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/d3;->$pm:Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Landroid/content/Context;

    check-cast p2, Ljava/lang/String;

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/d3;

    iget-object v1, p0, Llyiahf/vczjk/d3;->$pm:Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    invoke-direct {v0, v1, p3}, Llyiahf/vczjk/d3;-><init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/d3;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/d3;->L$1:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/d3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/d3;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/d3;->L$0:Ljava/lang/Object;

    check-cast p1, Landroid/content/Context;

    iget-object v0, p0, Llyiahf/vczjk/d3;->L$1:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/d3;->$pm:Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    new-instance v2, Llyiahf/vczjk/w1;

    const/16 v3, 0xb

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/w1;-><init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;I)V

    invoke-static {p1, v0, v2}, Llyiahf/vczjk/ng0;->OooOOOo(Landroid/content/Context;Ljava/lang/String;Llyiahf/vczjk/ze3;)Ljava/util/List;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
