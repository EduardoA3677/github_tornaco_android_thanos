.class public final Llyiahf/vczjk/kc1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $actionLabel:Ljava/lang/String;

.field final synthetic $backupSuccessMsg:Ljava/lang/String;

.field final synthetic $it:Llyiahf/vczjk/b50;

.field final synthetic $snackbarHostState:Llyiahf/vczjk/cu8;

.field label:I


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/b50;Llyiahf/vczjk/cu8;Ljava/lang/String;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kc1;->$backupSuccessMsg:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/kc1;->$it:Llyiahf/vczjk/b50;

    iput-object p3, p0, Llyiahf/vczjk/kc1;->$snackbarHostState:Llyiahf/vczjk/cu8;

    iput-object p4, p0, Llyiahf/vczjk/kc1;->$actionLabel:Ljava/lang/String;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/kc1;

    iget-object v1, p0, Llyiahf/vczjk/kc1;->$backupSuccessMsg:Ljava/lang/String;

    iget-object v2, p0, Llyiahf/vczjk/kc1;->$it:Llyiahf/vczjk/b50;

    iget-object v3, p0, Llyiahf/vczjk/kc1;->$snackbarHostState:Llyiahf/vczjk/cu8;

    iget-object v4, p0, Llyiahf/vczjk/kc1;->$actionLabel:Ljava/lang/String;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/kc1;-><init>(Ljava/lang/String;Llyiahf/vczjk/b50;Llyiahf/vczjk/cu8;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/kc1;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/kc1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/kc1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/kc1;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/kc1;->$backupSuccessMsg:Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/kc1;->$it:Llyiahf/vczjk/b50;

    check-cast v1, Llyiahf/vczjk/a50;

    iget-object v1, v1, Llyiahf/vczjk/a50;->OooO00o:Ljava/lang/String;

    const-string v3, " "

    invoke-static {p1, v3, v1}, Llyiahf/vczjk/ix8;->OooO0oO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/it8;->OooOOO0:Llyiahf/vczjk/it8;

    iget-object v1, p0, Llyiahf/vczjk/kc1;->$snackbarHostState:Llyiahf/vczjk/cu8;

    iget-object v3, p0, Llyiahf/vczjk/kc1;->$actionLabel:Ljava/lang/String;

    iput v2, p0, Llyiahf/vczjk/kc1;->label:I

    const/4 v2, 0x4

    invoke-static {v1, p1, v3, p0, v2}, Llyiahf/vczjk/cu8;->OooO0O0(Llyiahf/vczjk/cu8;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/eb9;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
