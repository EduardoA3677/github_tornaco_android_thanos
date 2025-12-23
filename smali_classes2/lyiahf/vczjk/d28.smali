.class public final Llyiahf/vczjk/d28;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/f28;

.field public final synthetic OooOOO0:Llyiahf/vczjk/h43;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/f28;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/d28;->OooOOO0:Llyiahf/vczjk/h43;

    iput-object p2, p0, Llyiahf/vczjk/d28;->OooOOO:Llyiahf/vczjk/f28;

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 5

    instance-of v0, p2, Llyiahf/vczjk/c28;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/c28;

    iget v1, v0, Llyiahf/vczjk/c28;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/c28;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/c28;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/c28;-><init>(Llyiahf/vczjk/d28;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/c28;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/c28;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    iget-object p1, p0, Llyiahf/vczjk/d28;->OooOOO:Llyiahf/vczjk/f28;

    iget-object p2, p1, Llyiahf/vczjk/f28;->OooO0OO:Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    invoke-virtual {p2, v3}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getAllPackageSets(Z)Ljava/util/List;

    move-result-object p2

    const-string v2, "getAllPackageSets(...)"

    invoke-static {p2, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/kb;

    const/4 v4, 0x5

    invoke-direct {v2, p1, v4}, Llyiahf/vczjk/kb;-><init>(Ljava/lang/Object;I)V

    invoke-static {p2, v2}, Llyiahf/vczjk/d21;->o0000O00(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    move-result-object p1

    iput v3, v0, Llyiahf/vczjk/c28;->label:I

    iget-object p2, p0, Llyiahf/vczjk/d28;->OooOOO0:Llyiahf/vczjk/h43;

    invoke-interface {p2, p1, v0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_3
    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
