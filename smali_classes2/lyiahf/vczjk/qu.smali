.class public final Llyiahf/vczjk/qu;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $code:I

.field final synthetic $viewModel:Llyiahf/vczjk/dv;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dv;ILlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qu;->$viewModel:Llyiahf/vczjk/dv;

    iput p2, p0, Llyiahf/vczjk/qu;->$code:I

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/qu;

    iget-object v0, p0, Llyiahf/vczjk/qu;->$viewModel:Llyiahf/vczjk/dv;

    iget v1, p0, Llyiahf/vczjk/qu;->$code:I

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/qu;-><init>(Llyiahf/vczjk/dv;ILlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/qu;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/qu;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/qu;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/qu;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/qu;->$viewModel:Llyiahf/vczjk/dv;

    iget v3, p0, Llyiahf/vczjk/qu;->$code:I

    iget-object v8, p1, Llyiahf/vczjk/dv;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v8}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xu;

    iget-object v1, p1, Llyiahf/vczjk/dv;->OooO0o:Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lgithub/tornaco/android/thanos/core/ops/OpsManager;

    invoke-virtual {v1, v3}, Lgithub/tornaco/android/thanos/core/ops/OpsManager;->opToName(I)Ljava/lang/String;

    move-result-object v1

    iget-object p1, p1, Llyiahf/vczjk/dv;->OooO0O0:Landroid/content/Context;

    invoke-static {p1, v3, v1}, Llyiahf/vczjk/vr3;->OooO0Oo(Landroid/content/Context;ILjava/lang/String;)Ljava/lang/String;

    move-result-object v4

    const/4 v2, 0x0

    const/16 v7, 0x33

    const/4 v1, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/xu;->OooO00o(Llyiahf/vczjk/xu;ZLjava/util/ArrayList;ILjava/lang/String;Llyiahf/vczjk/nw;Ljava/util/List;I)Llyiahf/vczjk/xu;

    move-result-object p1

    const/4 v0, 0x0

    invoke-virtual {v8, v0, p1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    iget-object p1, p0, Llyiahf/vczjk/qu;->$viewModel:Llyiahf/vczjk/dv;

    invoke-virtual {p1}, Llyiahf/vczjk/dv;->OooO0o()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
