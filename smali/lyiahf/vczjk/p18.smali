.class public final Llyiahf/vczjk/p18;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $id:Ljava/lang/String;

.field final synthetic $newSort:I

.field synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(ILjava/lang/String;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/p18;->$newSort:I

    iput-object p2, p0, Llyiahf/vczjk/p18;->$id:Ljava/lang/String;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/p18;

    iget v1, p0, Llyiahf/vczjk/p18;->$newSort:I

    iget-object v2, p0, Llyiahf/vczjk/p18;->$id:Ljava/lang/String;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/p18;-><init>(ILjava/lang/String;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/p18;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/p18;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/p18;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/p18;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/p18;->label:I

    if-nez v0, :cond_3

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/p18;->L$0:Ljava/lang/Object;

    check-cast p1, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;

    invoke-virtual {p1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;->getSetList()Ljava/util/List;

    move-result-object v0

    const-string v1, "getSetList(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/p18;->$id:Ljava/lang/String;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    const/4 v2, 0x0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;

    invoke-virtual {v3}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;->getId()Ljava/lang/String;

    move-result-object v3

    invoke-static {v3, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    goto :goto_1

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    const/4 v2, -0x1

    :goto_1
    if-gez v2, :cond_2

    return-object p1

    :cond_2
    invoke-virtual {p1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;->getSetList()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;

    invoke-static {v0}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;->newBuilder(Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;)Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet$Builder;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/p18;->$newSort:I

    invoke-virtual {v0, v1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet$Builder;->setSort(I)Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet$Builder;

    move-result-object v0

    invoke-virtual {v0}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet$Builder;->build()Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;

    move-result-object v0

    invoke-static {p1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;->newBuilder(Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;)Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList$Builder;

    move-result-object p1

    invoke-virtual {p1, v2, v0}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList$Builder;->setSet(ILtornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;)Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList$Builder;

    move-result-object p1

    invoke-virtual {p1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList$Builder;->build()Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;

    move-result-object p1

    const-string v0, "build(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
