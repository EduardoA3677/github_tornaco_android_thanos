.class public final Llyiahf/vczjk/b87;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $errorCode:I

.field final synthetic $errorMessage:Ljava/lang/String;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/g87;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/g87;Ljava/lang/String;ILlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/b87;->this$0:Llyiahf/vczjk/g87;

    iput-object p2, p0, Llyiahf/vczjk/b87;->$errorMessage:Ljava/lang/String;

    iput p3, p0, Llyiahf/vczjk/b87;->$errorCode:I

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/b87;

    iget-object v0, p0, Llyiahf/vczjk/b87;->this$0:Llyiahf/vczjk/g87;

    iget-object v1, p0, Llyiahf/vczjk/b87;->$errorMessage:Ljava/lang/String;

    iget v2, p0, Llyiahf/vczjk/b87;->$errorCode:I

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/b87;-><init>(Llyiahf/vczjk/g87;Ljava/lang/String;ILlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/b87;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/b87;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/b87;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/b87;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/b87;->this$0:Llyiahf/vczjk/g87;

    iget-object p1, p1, Llyiahf/vczjk/g87;->OooO0o0:Llyiahf/vczjk/jl8;

    new-instance v1, Llyiahf/vczjk/yq2;

    iget-object v3, p0, Llyiahf/vczjk/b87;->$errorMessage:Ljava/lang/String;

    if-nez v3, :cond_2

    iget v3, p0, Llyiahf/vczjk/b87;->$errorCode:I

    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v3

    :cond_2
    invoke-direct {v1, v3}, Llyiahf/vczjk/yq2;-><init>(Ljava/lang/String;)V

    iput v2, p0, Llyiahf/vczjk/b87;->label:I

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/jl8;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
