.class public final Llyiahf/vczjk/w28;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $sortItems:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;",
            ">;"
        }
    .end annotation
.end field

.field I$0:I

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/i48;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/i48;Ljava/util/List;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/w28;->this$0:Llyiahf/vczjk/i48;

    iput-object p2, p0, Llyiahf/vczjk/w28;->$sortItems:Ljava/util/List;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/w28;

    iget-object v0, p0, Llyiahf/vczjk/w28;->this$0:Llyiahf/vczjk/i48;

    iget-object v1, p0, Llyiahf/vczjk/w28;->$sortItems:Ljava/util/List;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/w28;-><init>(Llyiahf/vczjk/i48;Ljava/util/List;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/w28;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/w28;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/w28;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/w28;->label:I

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    iget v1, p0, Llyiahf/vczjk/w28;->I$0:I

    iget-object v4, p0, Llyiahf/vczjk/w28;->L$1:Ljava/lang/Object;

    check-cast v4, Ljava/util/Iterator;

    iget-object v5, p0, Llyiahf/vczjk/w28;->L$0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/i48;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move p1, v1

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/w28;->this$0:Llyiahf/vczjk/i48;

    iget-object p1, p1, Llyiahf/vczjk/i48;->OooOOo:Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/q29;

    invoke-interface {p1}, Llyiahf/vczjk/q29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/List;

    iget-object v1, p0, Llyiahf/vczjk/w28;->$sortItems:Ljava/util/List;

    new-instance v4, Ljava/util/ArrayList;

    const/16 v5, 0xa

    invoke-static {v1, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v5

    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_2

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;->OooO00o()I

    move-result v5

    new-instance v6, Ljava/lang/Integer;

    invoke-direct {v6, v5}, Ljava/lang/Integer;-><init>(I)V

    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    invoke-static {v4, p1}, Llyiahf/vczjk/xt6;->Oooo0O0(Ljava/util/ArrayList;Ljava/util/List;)Ljava/util/ArrayList;

    move-result-object p1

    iget-object v1, p0, Llyiahf/vczjk/w28;->this$0:Llyiahf/vczjk/i48;

    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    move-object v4, p1

    move-object v5, v1

    move p1, v2

    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    sget-object v6, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz v1, :cond_5

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    add-int/lit8 v7, p1, 0x1

    if-ltz p1, :cond_4

    check-cast v1, Lgithub/tornaco/android/thanos/core/pm/PackageSet;

    iget-object v8, v5, Llyiahf/vczjk/i48;->OooO0oO:Llyiahf/vczjk/f28;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/PackageSet;->getId()Ljava/lang/String;

    move-result-object v1

    const-string v9, "getId(...)"

    invoke-static {v1, v9}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object v5, p0, Llyiahf/vczjk/w28;->L$0:Ljava/lang/Object;

    iput-object v4, p0, Llyiahf/vczjk/w28;->L$1:Ljava/lang/Object;

    iput v7, p0, Llyiahf/vczjk/w28;->I$0:I

    iput v3, p0, Llyiahf/vczjk/w28;->label:I

    iget-object v8, v8, Llyiahf/vczjk/f28;->OooO00o:Landroid/content/Context;

    invoke-static {v8}, Llyiahf/vczjk/n27;->OooO0O0(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v9

    invoke-virtual {v8, v9, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v8

    invoke-interface {v8}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v8

    const-string v9, "PREF_KEY_PKG_SORT_"

    invoke-virtual {v9, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    mul-int/lit8 p1, p1, 0x64

    invoke-interface {v8, v1, p1}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    invoke-interface {p1}, Landroid/content/SharedPreferences$Editor;->apply()V

    if-ne v6, v0, :cond_3

    return-object v0

    :cond_3
    move p1, v7

    goto :goto_1

    :cond_4
    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    const/4 p1, 0x0

    throw p1

    :cond_5
    iget-object p1, p0, Llyiahf/vczjk/w28;->this$0:Llyiahf/vczjk/i48;

    invoke-static {p1}, Llyiahf/vczjk/i48;->OooO0oo(Llyiahf/vczjk/i48;)V

    return-object v6
.end method
