.class public final Llyiahf/vczjk/m28;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $label:Ljava/lang/String;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/i48;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/i48;Ljava/lang/String;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/m28;->this$0:Llyiahf/vczjk/i48;

    iput-object p2, p0, Llyiahf/vczjk/m28;->$label:Ljava/lang/String;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/m28;

    iget-object v0, p0, Llyiahf/vczjk/m28;->this$0:Llyiahf/vczjk/i48;

    iget-object v1, p0, Llyiahf/vczjk/m28;->$label:Ljava/lang/String;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/m28;-><init>(Llyiahf/vczjk/i48;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m28;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/m28;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/m28;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/m28;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/m28;->this$0:Llyiahf/vczjk/i48;

    iget-object p1, p1, Llyiahf/vczjk/i48;->OooO0oO:Llyiahf/vczjk/f28;

    iget-object v1, p0, Llyiahf/vczjk/m28;->$label:Ljava/lang/String;

    iput v3, p0, Llyiahf/vczjk/m28;->label:I

    iget-object p1, p1, Llyiahf/vczjk/f28;->OooO0OO:Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    invoke-virtual {p1, v1}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->createPackageSet(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/pm/PackageSet;

    if-ne v2, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/m28;->this$0:Llyiahf/vczjk/i48;

    invoke-static {p1}, Llyiahf/vczjk/i48;->OooO0oo(Llyiahf/vczjk/i48;)V

    return-object v2
.end method
