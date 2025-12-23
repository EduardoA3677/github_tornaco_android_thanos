.class public final Llyiahf/vczjk/uc1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $logSuccess:Ljava/lang/String;

.field final synthetic $scope:Llyiahf/vczjk/xr1;

.field final synthetic $snackbarHostState:Llyiahf/vczjk/cu8;

.field synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/cu8;Ljava/lang/String;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/uc1;->$scope:Llyiahf/vczjk/xr1;

    iput-object p2, p0, Llyiahf/vczjk/uc1;->$snackbarHostState:Llyiahf/vczjk/cu8;

    iput-object p3, p0, Llyiahf/vczjk/uc1;->$logSuccess:Ljava/lang/String;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/uc1;

    iget-object v1, p0, Llyiahf/vczjk/uc1;->$scope:Llyiahf/vczjk/xr1;

    iget-object v2, p0, Llyiahf/vczjk/uc1;->$snackbarHostState:Llyiahf/vczjk/cu8;

    iget-object v3, p0, Llyiahf/vczjk/uc1;->$logSuccess:Ljava/lang/String;

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/uc1;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/cu8;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/uc1;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/st2;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/uc1;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uc1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/uc1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/uc1;->label:I

    if-nez v0, :cond_2

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/uc1;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/st2;

    instance-of v0, p1, Llyiahf/vczjk/qt2;

    const/4 v1, 0x3

    const/4 v2, 0x0

    if-eqz v0, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/uc1;->$scope:Llyiahf/vczjk/xr1;

    new-instance v0, Llyiahf/vczjk/sc1;

    iget-object v3, p0, Llyiahf/vczjk/uc1;->$snackbarHostState:Llyiahf/vczjk/cu8;

    iget-object v4, p0, Llyiahf/vczjk/uc1;->$logSuccess:Ljava/lang/String;

    invoke-direct {v0, v3, v4, v2}, Llyiahf/vczjk/sc1;-><init>(Llyiahf/vczjk/cu8;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v2, v2, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_0

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/ot2;

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/uc1;->$scope:Llyiahf/vczjk/xr1;

    new-instance v3, Llyiahf/vczjk/tc1;

    iget-object v4, p0, Llyiahf/vczjk/uc1;->$snackbarHostState:Llyiahf/vczjk/cu8;

    invoke-direct {v3, v4, p1, v2}, Llyiahf/vczjk/tc1;-><init>(Llyiahf/vczjk/cu8;Llyiahf/vczjk/st2;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v2, v2, v3, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_1
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
