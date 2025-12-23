.class public final Llyiahf/vczjk/b73;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $flows:[Llyiahf/vczjk/f43;

.field final synthetic $transform$inlined:Llyiahf/vczjk/gf3;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>([Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;Llyiahf/vczjk/gf3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/b73;->$flows:[Llyiahf/vczjk/f43;

    iput-object p3, p0, Llyiahf/vczjk/b73;->$transform$inlined:Llyiahf/vczjk/gf3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/b73;

    iget-object v1, p0, Llyiahf/vczjk/b73;->$flows:[Llyiahf/vczjk/f43;

    iget-object v2, p0, Llyiahf/vczjk/b73;->$transform$inlined:Llyiahf/vczjk/gf3;

    invoke-direct {v0, v1, p2, v2}, Llyiahf/vczjk/b73;-><init>([Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;Llyiahf/vczjk/gf3;)V

    iput-object p1, v0, Llyiahf/vczjk/b73;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/b73;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/b73;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/b73;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/b73;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/b73;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/h43;

    iget-object v1, p0, Llyiahf/vczjk/b73;->$flows:[Llyiahf/vczjk/f43;

    sget-object v3, Llyiahf/vczjk/dk0;->OooOo00:Llyiahf/vczjk/dk0;

    new-instance v4, Llyiahf/vczjk/a73;

    const/4 v5, 0x0

    iget-object v6, p0, Llyiahf/vczjk/b73;->$transform$inlined:Llyiahf/vczjk/gf3;

    invoke-direct {v4, v5, v6}, Llyiahf/vczjk/a73;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/gf3;)V

    iput v2, p0, Llyiahf/vczjk/b73;->label:I

    invoke-static {p0, p1, v3, v4, v1}, Llyiahf/vczjk/cp7;->OooOOO(Llyiahf/vczjk/yo1;Llyiahf/vczjk/h43;Llyiahf/vczjk/le3;Llyiahf/vczjk/bf3;[Llyiahf/vczjk/f43;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
