.class public final Llyiahf/vczjk/yj;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $newTarget:Llyiahf/vczjk/tv7;

.field final synthetic $state:Llyiahf/vczjk/fk;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fk;Llyiahf/vczjk/tv7;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yj;->$state:Llyiahf/vczjk/fk;

    iput-object p2, p0, Llyiahf/vczjk/yj;->$newTarget:Llyiahf/vczjk/tv7;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/yj;

    iget-object v0, p0, Llyiahf/vczjk/yj;->$state:Llyiahf/vczjk/fk;

    iget-object v1, p0, Llyiahf/vczjk/yj;->$newTarget:Llyiahf/vczjk/tv7;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/yj;-><init>(Llyiahf/vczjk/fk;Llyiahf/vczjk/tv7;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/yj;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/yj;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/yj;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/yj;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/yj;->$state:Llyiahf/vczjk/fk;

    iget-object v1, p0, Llyiahf/vczjk/yj;->$newTarget:Llyiahf/vczjk/tv7;

    iput v2, p0, Llyiahf/vczjk/yj;->label:I

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/ek;

    const/4 v3, 0x0

    invoke-direct {v2, p1, v1, v3}, Llyiahf/vczjk/ek;-><init>(Llyiahf/vczjk/fk;Llyiahf/vczjk/ir1;Llyiahf/vczjk/yo1;)V

    invoke-static {v2, p0}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
